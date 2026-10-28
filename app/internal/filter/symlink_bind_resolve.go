package filter

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
)

// Fork-owned (wyrd-company/sockguard): symlink resolution of bind sources.
//
// The allowlist checks compare a bind source as a string, but the daemon
// mounts it through the host filesystem and follows every symlink on the way.
// A source like "/workspaces/a/link" passes a "/workspaces" prefix check while
// "link" points at "/". resolveBindSource walks the source the way the kernel
// does and the allowlist is checked again on the result.
//
// The walk runs in the proxy's own mount namespace. It is only correct when
// the proxy sees each allowlisted host path at the same path as the host does;
// see docs/content/docs/symlink-bind-sources.mdx. A source the proxy
// cannot see at all resolves to itself (the missing-tail rule below), so the
// check never narrows a deployment that mounts nothing into the proxy.
//
// The daemon resolves the source again at every container start. A check at
// create time sees the filesystem only as it is at create time; the docs page
// above describes that residual.

// maxBindSymlinkHops matches the Linux kernel's MAXSYMLINKS, the number of
// symlinks one path lookup may follow before it fails with ELOOP.
const maxBindSymlinkHops = 40

// Errors resolveBindSource returns. Each is a distinct deny reason.
var (
	// errBindSourceDangling: a symlink on the path points at something that
	// does not exist. dockerd fails such a mount, and a target created later
	// could sit anywhere.
	errBindSourceDangling = errors.New("dangling symlink")
	// errBindSourceLoop: more than maxBindSymlinkHops symlinks were followed.
	errBindSourceLoop = errors.New("symlink loop")
	// errBindSourcePermission: the proxy may not look up a component.
	errBindSourcePermission = errors.New("permission denied")
	// errBindSourceUnresolvable: any other lookup failure, for example a
	// non-directory in the middle of the path.
	errBindSourceUnresolvable = errors.New("lookup failed")
)

type bindPathComponent struct {
	name string
	// fromLink is set for components that came from a symlink target. A
	// missing one makes that symlink dangling.
	fromLink bool
}

func splitBindPathComponents(p string, fromLink bool) []bindPathComponent {
	var out []bindPathComponent
	for name := range strings.SplitSeq(p, "/") {
		if name == "" || name == "." {
			continue
		}
		out = append(out, bindPathComponent{name: name, fromLink: fromLink})
	}
	return out
}

// resolveBindSource walks source component by component the way the kernel
// looks up a path, and returns it with every symlink resolved: intermediate
// components, relative targets, and ".." applied to the real parent of what the
// walk has reached, after the link before it is followed. source is used as
// written, without lexical cleaning, so "/a/link/../b" with "link" -> "/x"
// resolves to "/b", where cleaning first gives "/a/b".
//
// A component of source itself that does not exist is taken as a directory
// that will be created, and the walk goes on. dockerd creates a missing
// HostConfig.Binds source at start, and Podman's compat create runs
// os.MkdirAll on a HostConfig.Binds source as written (5.8.6
// pkg/api/handlers/compat/containers_create.go), which creates the missing
// component and then follows the rest, ".." and links included. A missing component that
// came from a symlink target is a dangling symlink and fails with
// errBindSourceDangling.
func resolveBindSource(source string) (string, error) {
	resolved, _, err := walkBindSource(source)
	return resolved, err
}

// walkBindSource is resolveBindSource that also returns, in walk order, the
// resolved location of every missing component of source: the directories
// os.MkdirAll creates for it. A ".." can take the walk back out of such a
// directory, so a location here need not be a parent of the final path.
func walkBindSource(source string) (resolved string, created []string, err error) {
	pending := splitBindPathComponents(source, false)
	resolved = "/"
	hops := 0
	for len(pending) > 0 {
		component := pending[0]
		pending = pending[1:]
		if component.name == ".." {
			// resolved holds no symlink, so its lexical parent is its real
			// parent.
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, component.name)
		info, err := bindfs.Lstat(next)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && !component.fromLink {
				created = append(created, next)
				resolved = next
				continue
			}
			return "", nil, classifyBindLookupError(next, err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		hops++
		if hops > maxBindSymlinkHops {
			return "", nil, fmt.Errorf("%w at %q", errBindSourceLoop, next)
		}
		target, err := bindfs.Readlink(next)
		if err != nil {
			return "", nil, classifyBindLookupError(next, err)
		}
		if path.IsAbs(target) {
			resolved = "/"
		}
		pending = append(splitBindPathComponents(target, true), pending...)
	}
	return resolved, created, nil
}

func classifyBindLookupError(at string, err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("%w at %q", errBindSourceDangling, at)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%w at %q", errBindSourcePermission, at)
	default:
		return fmt.Errorf("%w at %q", errBindSourceUnresolvable, at)
	}
}

// resolveBindAllowlist resolves each allowlist entry, so a source under an
// entry that is itself a symlink (for example "/workspaces" -> "/mnt/ws")
// still matches after resolution. An entry that fails to resolve is kept as
// written: a source under it then fails resolution itself, or resolves to a
// path the entry's text already covers.
func resolveBindAllowlist(allowed []string) []string {
	out := make([]string, 0, len(allowed))
	for _, entry := range allowed {
		if resolved, err := resolveBindSource(entry); err == nil {
			entry = resolved
		}
		out = append(out, entry)
	}
	return out
}

// denySymlinkedBindSourceReason checks the resolved form of a bind source that
// has already passed the lexical bindPathAllowed check. raw is the value as the
// request spelled it and source is its lexically cleaned form, the one the
// lexical check compared.
//
// The cleaned form is what dockerd and Podman's libpod create mount, so it is
// resolved first. When raw has a ".." component, raw is resolved too: the
// kernel applies ".." after the link before it, and a local volume device or
// overlay directory reaches mount(2) as written, as a Podman compat
// HostConfig.Binds source reaches os.MkdirAll. Both forms must resolve under
// an allowlist entry.
//
// Every directory a form creates must be allowed as well, because os.MkdirAll
// creates it before the walk returns: a ".." can lead back under the allowlist
// from a directory created outside it. A created directory is allowed when it
// is under an allowlist entry or is a parent of one, since creating a missing
// entry creates its parents too.
//
// It returns "" when neither form holds a symlink or creates a directory, when
// every location passes, and when the allowlist holds "/". Otherwise it
// returns a deny reason worded like the caller's own: subject names the
// endpoint and label the field.
func denySymlinkedBindSourceReason(subject, label, raw, source string, allowed []string) string {
	if slices.Contains(allowed, "/") {
		return ""
	}
	spellings := []string{source}
	if hasDotDotComponent(raw) {
		spellings = append(spellings, raw)
	}
	var resolvedAllowed []string
	allowlist := func() []string {
		if resolvedAllowed == nil {
			resolvedAllowed = resolveBindAllowlist(allowed)
		}
		return resolvedAllowed
	}
	for _, spelling := range spellings {
		resolved, created, err := walkBindSource(spelling)
		if err != nil {
			return fmt.Sprintf("%s denied: %s %q cannot be resolved: %v", subject, label, spelling, err)
		}
		if resolved != source && !bindPathAllowed(resolved, allowlist()) {
			return fmt.Sprintf("%s denied: %s %q resolves to %q, which is not allowlisted", subject, label, spelling, resolved)
		}
		for _, dir := range created {
			if !createdBindDirAllowed(dir, allowlist()) {
				return fmt.Sprintf("%s denied: %s %q creates directory %q, which is not allowlisted", subject, label, spelling, dir)
			}
		}
	}
	return ""
}

// createdBindDirAllowed reports whether os.MkdirAll may create dir: dir is
// under an allowlist entry, or is a parent of one.
func createdBindDirAllowed(dir string, allowed []string) bool {
	if bindPathAllowed(dir, allowed) {
		return true
	}
	for _, entry := range allowed {
		if strings.HasPrefix(entry, dir+"/") {
			return true
		}
	}
	return false
}

// hasDotDotComponent reports whether p has a ".." path component.
func hasDotDotComponent(p string) bool {
	for name := range strings.SplitSeq(p, "/") {
		if name == ".." {
			return true
		}
	}
	return false
}

// bindSymlinkMode tells a helper shared with the service inspector whether to
// resolve symlinks in the host paths it checks.
type bindSymlinkMode bool

const (
	resolveBindSymlinks bindSymlinkMode = true
	// lexicalBindSources is for service create and update. A swarm task's
	// bind source resolves on the node that runs the task, which the proxy
	// cannot see, so the lexical check is the only one that applies.
	lexicalBindSources bindSymlinkMode = false
)

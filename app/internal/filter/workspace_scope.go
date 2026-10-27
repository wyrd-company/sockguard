package filter

import (
	"errors"
	"path"
	"slices"
	"strings"
)

// Fork-owned (wyrd-company/sockguard): per-workspace bind scoping.
//
// In a container_create block with apply_workspace_exceptions, every create,
// matched or not, has its binds under a per-workspace root scoped to its own
// workspace: a host path under root R must be inside R/<basename W> or inside
// one of W's extraBindSources. W is the request's workspace identity
// (workspaceIdentity). A request with no identity may not bind anything
// under a per-workspace root.
//
// The check reuses the bind checks the base policy runs: it runs them again
// with the base allowlist narrowed per root (workspaceScopedAllowlist), so
// symlink resolution, the directories a source creates, Config.Volumes keys,
// overlay directories and local volume bind devices are scoped by the same
// code that admits them. It runs after the effective policy has admitted the
// request, so a failure here is a scoping failure and nothing else.

// WorkspaceThrowawayLabel names the workspace of a command container. It
// scopes binds like devcontainer.local_folder and never grants an exception.
const WorkspaceThrowawayLabel = "menagerie.throwaway.workspace"

// WorkspaceIdentityKind says where a request's workspace identity came from.
type WorkspaceIdentityKind string

const (
	// WorkspaceIdentityNone: the request names no workspace.
	WorkspaceIdentityNone WorkspaceIdentityKind = "none"
	// WorkspaceIdentityDevcontainer: devcontainer.local_folder names a
	// workspace. Only this kind can match an exception.
	WorkspaceIdentityDevcontainer WorkspaceIdentityKind = "devcontainer"
	// WorkspaceIdentityThrowaway: menagerie.throwaway.workspace names a
	// workspace. It scopes binds and never matches an exception.
	WorkspaceIdentityThrowaway WorkspaceIdentityKind = "throwaway"
)

// WorkspaceIdentity is a request's workspace: Kind and, unless Kind is none,
// the workspace path W.
type WorkspaceIdentity struct {
	Kind      WorkspaceIdentityKind
	Workspace string
}

// workspaceIdentity is the one place a create's workspace identity is read.
// It returns a deny reason when the identity is ambiguous or malformed:
//
//   - both labels are present;
//   - menagerie.throwaway.workspace is not a workspace key (absolute, clean,
//     a direct child of the workspace root) or not a canonical directory.
//
// A devcontainer.local_folder value that is not a workspace key gives no
// identity: the request is then scoped as one that names no workspace, and
// matches no exception. The reasons do not echo the label values.
func workspaceIdentity(labels map[string]string, snap *WorkspaceExceptionSnapshot) (WorkspaceIdentity, string) {
	folder, hasFolder := labels[WorkspaceLocalFolderLabel]
	throwaway, hasThrowaway := labels[WorkspaceThrowawayLabel]
	switch {
	case hasFolder && hasThrowaway:
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, "container create denied: labels " + WorkspaceLocalFolderLabel + " and " + WorkspaceThrowawayLabel + " cannot both be set"
	case hasThrowaway:
		if checkWorkspaceKey(throwaway, snap.workspaceRoot()) != nil {
			return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, "container create denied: label " + WorkspaceThrowawayLabel + " does not name a workspace under the workspace root"
		}
		if cause, _ := checkWorkspaceFolder(throwaway); cause != "" {
			return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, "container create denied: label " + WorkspaceThrowawayLabel + " names a workspace that is not a canonical directory"
		}
		return WorkspaceIdentity{Kind: WorkspaceIdentityThrowaway, Workspace: throwaway}, ""
	case hasFolder && checkWorkspaceKey(folder, snap.workspaceRoot()) == nil:
		return WorkspaceIdentity{Kind: WorkspaceIdentityDevcontainer, Workspace: folder}, ""
	default:
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, ""
	}
}

func (s *WorkspaceExceptionSnapshot) workspaceRoot() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *WorkspaceExceptionSnapshot) perWorkspaceRoots() []string {
	if s == nil {
		return nil
	}
	return s.roots
}

// extraBindSourcesFor is W's extraBindSources, or nil when the file has no
// entry for W or is not loaded.
func (s *WorkspaceExceptionSnapshot) extraBindSourcesFor(workspace string) []string {
	if s == nil || s.state != WorkspaceExceptionsLoaded || workspace == "" {
		return nil
	}
	if entry, ok := s.entries[workspace]; ok {
		return entry.grants.extraBindSources
	}
	return nil
}

// workspaceScopedAllowlist narrows allowed for workspace folder name folder
// (empty: no workspace). Each entry E is judged by its resolved form r (the
// bind checks resolve allowlist entries too), per root R:
//
//   - r not related to any root: E is kept;
//   - r equal to R: E is replaced by R/<folder> and E/<folder>, or dropped
//     without a folder;
//   - r inside R: E is kept when r is inside R/<folder>, else dropped;
//   - r contains R ("/srv" for "/srv/workspaces", or "/"): E cannot be
//     narrowed by prefix and is dropped. Validation refuses such an entry in
//     a block with apply_workspace_exceptions, so this branch only keeps an
//     unvalidated config from widening.
//
// extras are added, so a granted extra bind source under a root stays
// reachable.
func workspaceScopedAllowlist(allowed, roots []string, folder string, extras []string) []string {
	out := make([]string, 0, len(allowed)+len(roots)+len(extras))
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, entry := range allowed {
		resolved := entry
		if r, err := resolveBindSource(entry); err == nil {
			resolved = r
		}
		switch root, relation := rootRelation(resolved, roots); relation {
		case rootUnrelated:
			add(entry)
		case rootEqual:
			if folder != "" {
				add(path.Join(root, folder))
				add(path.Join(entry, folder))
			}
		case rootInside:
			own := path.Join(root, folder)
			if folder != "" && (resolved == own || strings.HasPrefix(resolved, own+"/")) {
				add(entry)
			}
		}
	}
	for _, extra := range extras {
		add(extra)
	}
	return out
}

type rootRelationKind int

const (
	rootUnrelated rootRelationKind = iota
	rootEqual
	rootInside
	rootContains
)

// rootRelation reports how p relates to the first per-workspace root it
// touches. Roots are not nested, so at most one root is inside or equal to p.
func rootRelation(p string, roots []string) (string, rootRelationKind) {
	for _, root := range roots {
		switch {
		case p == root:
			return root, rootEqual
		case strings.HasPrefix(p, root+"/"):
			return root, rootInside
		case p == "/" || strings.HasPrefix(root, p+"/"):
			return root, rootContains
		}
	}
	return "", rootUnrelated
}

// DenyWorkspaceScopeReason checks req's host paths against the per-workspace
// roots of snap for identity id. allowedBindMounts is the allowlist that
// admitted the request. It returns "" when every host path under a
// per-workspace root is inside that root's folder for id's workspace or
// inside one of the workspace's extraBindSources. Exported for the
// start-time re-check, which scopes an inspected container the same way.
func DenyWorkspaceScopeReason(snap *WorkspaceExceptionSnapshot, id WorkspaceIdentity, req WorkspaceExceptionRequest, allowedBindMounts []string) string {
	roots := snap.perWorkspaceRoots()
	if len(roots) == 0 {
		return ""
	}
	folder := ""
	if id.Kind != WorkspaceIdentityNone {
		folder = path.Base(id.Workspace)
		// The bind checks resolve allowlist entries. A workspace folder that
		// is a symlink, into another workspace's folder say, would carry the
		// sources under it along, so it is refused instead.
		for _, root := range roots {
			own := path.Join(root, folder)
			if resolved, err := resolveBindSource(own); err != nil || resolved != own {
				return "container create denied: this workspace's folder under a per-workspace root is not a canonical directory"
			}
		}
	}
	// Extra bind sources are an exception: only a devcontainer identity
	// gets them.
	var extras []string
	if id.Kind == WorkspaceIdentityDevcontainer {
		extras = snap.extraBindSourcesFor(id.Workspace)
	}
	normalized := make([]string, 0, len(allowedBindMounts))
	for _, entry := range allowedBindMounts {
		if n, ok := normalizeBindMount(entry); ok {
			normalized = append(normalized, n)
		}
	}
	scoped := containerCreatePolicy{
		allowedBindMounts: workspaceScopedAllowlist(normalized, roots, folder, extras),
	}
	hostConfig, volumes := req.containerCreateShape()
	reason := scoped.denyBindMountReason(hostConfig)
	if reason == "" {
		reason = scoped.denyVolumeSpecReason(volumes)
	}
	if reason == "" {
		return ""
	}
	detail := strings.TrimPrefix(reason, "container create denied: ")
	if id.Kind == WorkspaceIdentityNone {
		return "container create denied: a host path under a per-workspace root needs a workspace label (" + detail + ")"
	}
	return "container create denied: a host path under a per-workspace root is outside this workspace's folder (" + detail + ")"
}

// ForkStartRecheckWorkspace validates w against the current snapshot and
// returns its scope for the start re-check: the per-workspace roots, W's
// folder under each, and W's extra bind sources (none for a throwaway
// workspace). W must be a workspace key and a canonical directory.
func (s *WorkspaceExceptionStore) ForkStartRecheckWorkspace(w ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error) {
	snap := s.Load()
	if err := checkWorkspaceKey(w.Path, snap.workspaceRoot()); err != nil {
		return ForkStartRecheckWorkspaceScope{}, err
	}
	if cause, detail := checkWorkspaceFolder(w.Path); cause != "" {
		return ForkStartRecheckWorkspaceScope{}, errors.New(detail)
	}
	roots := slices.Clone(snap.perWorkspaceRoots())
	scope := ForkStartRecheckWorkspaceScope{Roots: roots}
	for _, root := range roots {
		scope.Folders = append(scope.Folders, path.Join(root, path.Base(w.Path)))
	}
	if !w.Throwaway {
		scope.ExtraBindSources = slices.Clone(snap.extraBindSourcesFor(w.Path))
	}
	return scope, nil
}

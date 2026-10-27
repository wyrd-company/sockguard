package filter

import (
	"errors"
	"net/http"
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
// (WorkspaceFromHeaders). A request with no identity may not bind anything
// under a per-workspace root.
//
// The check reuses the bind checks the base policy runs: it runs them again
// with the base allowlist narrowed per root (workspaceScopedAllowlist), so
// symlink resolution, the directories a source creates, Config.Volumes keys,
// overlay directories and local volume bind devices are scoped by the same
// code that admits them. It runs after the effective policy has admitted the
// request, so a failure here is a scoping failure and nothing else.

// WorkspaceThrowawayLabel is the label a command container may carry under
// the throwaway header. When present it must equal the request's workspace.
const WorkspaceThrowawayLabel = "menagerie.throwaway.workspace"

// The request headers that name the workspace W. The workspace manager sets
// them on its own Docker client; a container label can be written by
// whoever writes the container's configuration, so it is never identity.
const (
	// WorkspaceHeader names W for a devcontainer job. Exceptions apply only
	// under this header.
	WorkspaceHeader = "X-Sockguard-Workspace"
	// WorkspaceThrowawayHeader names W for a command container. It scopes
	// binds and never grants an exception.
	WorkspaceThrowawayHeader = "X-Sockguard-Throwaway-Workspace"
)

// WorkspaceIdentityKind says which header named the workspace.
type WorkspaceIdentityKind string

const (
	// WorkspaceIdentityNone: no workspace.
	WorkspaceIdentityNone WorkspaceIdentityKind = "none"
	// WorkspaceIdentityDevcontainer: X-Sockguard-Workspace. Only this kind
	// can match an exception.
	WorkspaceIdentityDevcontainer WorkspaceIdentityKind = "devcontainer"
	// WorkspaceIdentityThrowaway: X-Sockguard-Throwaway-Workspace. It
	// scopes binds and never matches an exception.
	WorkspaceIdentityThrowaway WorkspaceIdentityKind = "throwaway"
)

// WorkspaceIdentity is a request's workspace: Kind and, unless Kind is none,
// the workspace path W as the header gives it.
type WorkspaceIdentity struct {
	Kind      WorkspaceIdentityKind
	Workspace string
}

// WorkspaceHeaderProblem is why WorkspaceFromHeaders found no workspace.
type WorkspaceHeaderProblem string

const (
	WorkspaceHeaderOK        WorkspaceHeaderProblem = ""
	WorkspaceHeaderMissing   WorkspaceHeaderProblem = "missing"
	WorkspaceHeaderAmbiguous WorkspaceHeaderProblem = "ambiguous"
	WorkspaceHeaderEmpty     WorkspaceHeaderProblem = "empty"
)

// WorkspaceFromHeaders is the one reader of the workspace headers, for create,
// exec and the start re-check. Exactly one of the two headers, with exactly
// one non-empty value, names W. It checks no path rule; see
// checkWorkspaceIdentity.
func WorkspaceFromHeaders(header http.Header) (WorkspaceIdentity, WorkspaceHeaderProblem) {
	devcontainer := header.Values(WorkspaceHeader)
	throwaway := header.Values(WorkspaceThrowawayHeader)
	switch {
	case len(devcontainer) == 0 && len(throwaway) == 0:
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, WorkspaceHeaderMissing
	case len(devcontainer)+len(throwaway) > 1:
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, WorkspaceHeaderAmbiguous
	}
	id := WorkspaceIdentity{Kind: WorkspaceIdentityDevcontainer}
	if len(throwaway) == 1 {
		id = WorkspaceIdentity{Kind: WorkspaceIdentityThrowaway, Workspace: throwaway[0]}
	} else {
		id.Workspace = devcontainer[0]
	}
	if id.Workspace == "" {
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, WorkspaceHeaderEmpty
	}
	return id, WorkspaceHeaderOK
}

// workspaceHeaderDenyReason reads and checks W for subject ("container
// create", "exec create", ...). The reasons name the cause and never quote a
// header value.
func workspaceHeaderDenyReason(header http.Header, snap *WorkspaceExceptionSnapshot, subject string) (WorkspaceIdentity, string) {
	id, problem := WorkspaceFromHeaders(header)
	switch problem {
	case WorkspaceHeaderMissing:
		return id, subject + " denied: the request names no workspace (set " + WorkspaceHeader + " or " + WorkspaceThrowawayHeader + ")"
	case WorkspaceHeaderAmbiguous:
		return id, subject + " denied: the request names more than one workspace"
	case WorkspaceHeaderEmpty:
		return id, subject + " denied: the workspace header does not name a valid workspace"
	}
	if !checkWorkspaceIdentity(id.Workspace, snap) {
		return WorkspaceIdentity{Kind: WorkspaceIdentityNone}, subject + " denied: the workspace header does not name a valid workspace"
	}
	return id, ""
}

// checkWorkspaceIdentity applies the exception-key rules to W: absolute,
// clean, a direct child of the workspace root, and a canonical directory.
func checkWorkspaceIdentity(workspace string, snap *WorkspaceExceptionSnapshot) bool {
	if checkWorkspaceKey(workspace, snap.workspaceRoot()) != nil {
		return false
	}
	cause, _ := checkWorkspaceFolder(workspace)
	return cause == ""
}

// workspaceLabelDenyReason requires the same-kind label to be absent or equal
// W, and the opposite-kind label to be absent. The reason names the label,
// not its value.
func workspaceLabelDenyReason(labels map[string]string, id WorkspaceIdentity, subject string) string {
	label, opposite := workspaceIdentityLabels(id)
	if _, present := labels[opposite]; present {
		return subject + " denied: workspace label " + opposite + " disagrees with the request's workspace kind"
	}
	if value, present := labels[label]; present && value != id.Workspace {
		return subject + " denied: workspace label " + label + " disagrees with the request's workspace"
	}
	return ""
}

func workspaceIdentityLabels(id WorkspaceIdentity) (same, opposite string) {
	if id.Kind == WorkspaceIdentityThrowaway {
		return WorkspaceThrowawayLabel, WorkspaceLocalFolderLabel
	}
	return WorkspaceLocalFolderLabel, WorkspaceThrowawayLabel
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
// admitted the request. granted is the matched exception's extraBindSources:
// extra bind sources are a grant, so they are passed only when the exception
// applies (MatchWorkspaceException's ExtraBindSources, nil otherwise). It
// returns "" when every host path under a per-workspace root is inside that
// root's folder for id's workspace or inside one of granted. The roots come
// from the configuration, so a missing or invalid file removes only the
// grants, never the scoping.
func DenyWorkspaceScopeReason(snap *WorkspaceExceptionSnapshot, id WorkspaceIdentity, req WorkspaceExceptionRequest, allowedBindMounts, granted []string) string {
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
	// A throwaway identity never holds a grant, whatever the caller passes.
	extras := granted
	if id.Kind != WorkspaceIdentityDevcontainer {
		extras = nil
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
		return "container create denied: a host path under a per-workspace root needs a workspace (" + detail + ")"
	}
	return "container create denied: a host path under a per-workspace root is outside this workspace's folder (" + detail + ")"
}

// ForkStartRecheckWorkspace validates w against the current snapshot and
// returns its scope for the start re-check: the per-workspace roots, W's
// folder under each, and extra bind sources only if w.Request passes the
// current create-equivalent match. Throwaway requests receive no grants. W
// must be a workspace key and a canonical directory.
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
		scope.ExtraBindSources = MatchWorkspaceException(snap, w.Path, w.Request).ExtraBindSources()
	}
	return scope, nil
}

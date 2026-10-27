package filter

import (
	"fmt"
	"net/http"
	"slices"
)

// Fork-owned (wyrd-company/sockguard): workspace scope of the start re-check.
//
// A policy that applies workspace exceptions takes a request's workspace W
// only from a header the workspace manager sets, never from a container
// label, since a client can write any label. A start or restart under such a
// policy must name W; the container's identity labels must be absent or equal
// W; and each bind source, as written and after resolution, must stay inside
// W's folders under the per-workspace roots, inside the base allowlist
// elsewhere, or inside one of W's extra bind sources. Extra bind sources are
// exceptions and apply only to a devcontainer: a throwaway workspace header,
// or a throwaway label on the container, gets no extra bind source.

// Workspace headers and identity labels.
const (
	forkStartRecheckWorkspaceHeader          = "X-Sockguard-Workspace"
	forkStartRecheckThrowawayWorkspaceHeader = "X-Sockguard-Throwaway-Workspace"
	forkStartRecheckWorkspaceLabel           = "devcontainer.local_folder"
	forkStartRecheckThrowawayWorkspaceLabel  = "menagerie.throwaway.workspace"
)

// Reason codes of the workspace scope. A deny reason never quotes a header
// value.
const (
	forkStartRecheckReasonCodeWorkspaceMissing       = "container_start_workspace_missing"
	forkStartRecheckReasonCodeWorkspaceAmbiguous     = "container_start_workspace_ambiguous"
	forkStartRecheckReasonCodeWorkspaceInvalid       = "container_start_workspace_invalid"
	forkStartRecheckReasonCodeWorkspaceLabelMismatch = "container_start_workspace_label_mismatch"
	forkStartRecheckReasonCodeOutsideWorkspace       = "container_start_bind_source_outside_workspace"
)

// ForkStartRecheckWorkspace is the workspace a request names.
type ForkStartRecheckWorkspace struct {
	// Path is the workspace path W, as the header gives it.
	Path string
	// Throwaway is set for a throwaway workspace, which gets no exceptions.
	Throwaway bool
}

// ForkStartRecheckWorkspaceScope is what a workspace's bind sources may use.
type ForkStartRecheckWorkspaceScope struct {
	// Roots are the per-workspace roots. A path under one of them belongs to
	// one workspace.
	Roots []string
	// Folders are W's folders, one under each root.
	Folders []string
	// ExtraBindSources are W's extra bind sources. They are empty for a
	// throwaway workspace.
	ExtraBindSources []string
}

// ForkStartRecheckWorkspaceFunc validates W and returns its scope. An error
// means W is not a valid workspace.
type ForkStartRecheckWorkspaceFunc func(ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error)

func forkStartRecheckWorkspaceDenied(code, reason string) error {
	return newRequestRejectionErrorWithCode(http.StatusForbidden, code, reason)
}

// forkStartRecheckWorkspaceFromHeaders reads W from the request. Exactly one
// header with exactly one non-empty value is accepted.
func forkStartRecheckWorkspaceFromHeaders(header http.Header, subject string) (ForkStartRecheckWorkspace, error) {
	devcontainer := header.Values(forkStartRecheckWorkspaceHeader)
	throwaway := header.Values(forkStartRecheckThrowawayWorkspaceHeader)
	switch {
	case len(devcontainer) == 0 && len(throwaway) == 0:
		return ForkStartRecheckWorkspace{}, forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeWorkspaceMissing,
			fmt.Sprintf("%s denied: the request names no workspace (set %s or %s)", subject, forkStartRecheckWorkspaceHeader, forkStartRecheckThrowawayWorkspaceHeader))
	case len(devcontainer)+len(throwaway) > 1:
		return ForkStartRecheckWorkspace{}, forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeWorkspaceAmbiguous,
			fmt.Sprintf("%s denied: the request names more than one workspace", subject))
	}
	workspace := ForkStartRecheckWorkspace{Throwaway: len(throwaway) == 1}
	if workspace.Throwaway {
		workspace.Path = throwaway[0]
	} else {
		workspace.Path = devcontainer[0]
	}
	if workspace.Path == "" {
		return ForkStartRecheckWorkspace{}, forkStartRecheckWorkspaceInvalid(subject)
	}
	return workspace, nil
}

func forkStartRecheckWorkspaceInvalid(subject string) error {
	return forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeWorkspaceInvalid,
		fmt.Sprintf("%s denied: the workspace header does not name a valid workspace", subject))
}

// denyWorkspace applies the workspace scope to an inspected container.
func (p forkStartRecheckPolicy) denyWorkspace(subject string, workspace ForkStartRecheckWorkspace, container ForkStartRecheckContainer) error {
	for _, label := range []string{forkStartRecheckWorkspaceLabel, forkStartRecheckThrowawayWorkspaceLabel} {
		if value, ok := container.Config.Labels[label]; ok && value != workspace.Path {
			return forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeWorkspaceLabelMismatch,
				fmt.Sprintf("%s denied: container label %q does not match the request's workspace", subject, label))
		}
	}
	// A command container never gets exceptions, whichever header starts it.
	if _, ok := container.Config.Labels[forkStartRecheckThrowawayWorkspaceLabel]; ok {
		workspace.Throwaway = true
	}
	scope, err := p.workspace(workspace)
	if err != nil {
		return forkStartRecheckWorkspaceInvalid(subject)
	}
	if workspace.Throwaway {
		scope.ExtraBindSources = nil
	}
	allowed := newForkStartRecheckWorkspaceAllowed(scope, p.workspaceBase)
	for _, source := range forkStartRecheckSources(container) {
		if reason := allowed.denyReason(subject, source); reason != "" {
			return forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeOutsideWorkspace, reason)
		}
	}
	return nil
}

// forkStartRecheckWorkspaceAllowed holds the paths a location may use. A
// location written by the request is compared with the entries as configured,
// a resolved one with the entries resolved the way the create check resolves
// its allowlist. W's folders are never resolved: a folder replaced with a
// symlink into another workspace must not carry the sources under it along.
type forkStartRecheckWorkspaceAllowed struct {
	roots []string
	// underRoot is used under a root: W's folders and extra bind sources.
	underRoot []string
	// elsewhere is used outside the roots: the base allowlist and W's extra
	// bind sources, as configured and resolved.
	elsewhere, elsewhereResolved []string
}

func newForkStartRecheckWorkspaceAllowed(scope ForkStartRecheckWorkspaceScope, base []string) forkStartRecheckWorkspaceAllowed {
	elsewhere := append(slices.Clone(base), scope.ExtraBindSources...)
	return forkStartRecheckWorkspaceAllowed{
		roots:             scope.Roots,
		underRoot:         append(slices.Clone(scope.Folders), scope.ExtraBindSources...),
		elsewhere:         elsewhere,
		elsewhereResolved: resolveBindAllowlist(elsewhere),
	}
}

// location reports whether a path may be bound, or, when created is set,
// created on the way to a bind source.
func (a forkStartRecheckWorkspaceAllowed) location(location string, resolved, created bool) bool {
	allowed := a.elsewhere
	if resolved {
		allowed = a.elsewhereResolved
	}
	if bindPathAllowed(location, a.roots) {
		allowed = a.underRoot
	}
	if created {
		return createdBindDirAllowed(location, allowed)
	}
	return bindPathAllowed(location, allowed)
}

// denyReason checks one source: as written, and in each spelling the create
// check resolves, the resolved path and every directory the walk would
// create. A source that cannot be resolved is denied, since where it leads is
// unknown.
func (a forkStartRecheckWorkspaceAllowed) denyReason(subject string, source forkStartRecheckSource) string {
	if !a.location(source.clean, false, false) {
		return fmt.Sprintf("%s denied: bind mount source %q is outside the request's workspace", subject, source.clean)
	}
	spellings := []string{source.clean}
	if hasDotDotComponent(source.raw) {
		spellings = append(spellings, source.raw)
	}
	for _, spelling := range spellings {
		resolved, created, err := walkBindSource(spelling)
		if err != nil {
			return fmt.Sprintf("%s denied: bind mount source %q cannot be resolved: %v", subject, spelling, err)
		}
		if !a.location(resolved, true, false) {
			return fmt.Sprintf("%s denied: bind mount source %q resolves to %q, which is outside the request's workspace", subject, spelling, resolved)
		}
		for _, dir := range created {
			if !a.location(dir, true, true) {
				return fmt.Sprintf("%s denied: bind mount source %q creates directory %q, which is outside the request's workspace", subject, spelling, dir)
			}
		}
	}
	return ""
}

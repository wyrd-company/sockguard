package filter

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// Fork-owned (wyrd-company/sockguard): the workspace header on exec.
//
// In a policy whose container_create block applies workspace exceptions,
// exec create and exec start must name a valid workspace in a header, the
// way container create must. The target container must carry the same-kind
// workspace label equal to W. The check reads no body and runs ahead of the
// exec body inspector. Missing headers are denied before any daemon lookup.

type forkExecWorkspacePolicy struct {
	apply             bool
	store             *WorkspaceExceptionStore
	inspectContainer  ForkStartRecheckInspectFunc
	inspectExec       ExecInspectFunc
	inspectExecLibpod ExecInspectFunc
}

func newForkExecWorkspacePolicy(cfg PolicyConfig) forkExecWorkspacePolicy {
	// These inspectors already use the serve chain's shared upstream
	// resolver. Reusing the container reader does not attach start/restart
	// workspace scope (ForkStartRecheck.Workspace remains independent).
	return forkExecWorkspacePolicy{
		apply:             cfg.ContainerCreate.ApplyWorkspaceExceptions,
		store:             cfg.ContainerCreate.WorkspaceExceptions,
		inspectContainer:  cfg.ForkStartRecheck.InspectContainer,
		inspectExec:       cfg.Exec.InspectStart,
		inspectExecLibpod: cfg.Exec.InspectStartLibpod,
	}
}

func (p forkExecWorkspacePolicy) inspect(_ *slog.Logger, r *http.Request, normalizedPath string) (string, error) {
	if !p.apply || r == nil || r.Method != http.MethodPost || !matchesExecInspection(normalizedPath) {
		return "", nil
	}
	subject := "exec start"
	if isExecCreatePath(normalizedPath) || isLibpodExecCreatePath(normalizedPath) {
		subject = "exec create"
	}
	id, reason := workspaceHeaderDenyReason(r.Header, p.store.Load(), subject)
	if reason != "" {
		return reason, nil
	}
	if p.inspectContainer == nil {
		return subject + " denied: no workspace container inspection configured", nil
	}
	var containerID string
	if subject == "exec create" {
		containerID = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(normalizedPath, "/libpod"), "/containers/"), "/exec")
	} else {
		execID, libpod, _ := execStartIdentifier(normalizedPath)
		inspect := p.inspectExec
		if libpod {
			inspect = p.inspectExecLibpod
		}
		if inspect == nil {
			return subject + " denied: no workspace exec inspection configured", nil
		}
		result, found, err := inspect(r.Context(), execID)
		if err != nil {
			return "", fmt.Errorf("inspect workspace exec target: %w", err)
		}
		if !found || result.ContainerID == "" {
			return subject + " denied: workspace exec target is missing", nil
		}
		containerID = result.ContainerID
	}
	container, err := p.inspectContainer(r.Context(), containerID)
	if err != nil {
		return "", fmt.Errorf("inspect workspace exec container: %w", err)
	}
	if reason := workspaceLabelDenyReason(container.Config.Labels, id, subject); reason != "" {
		return reason, nil
	}
	label, _ := workspaceIdentityLabels(id)
	if container.Config.Labels[label] != id.Workspace {
		return subject + " denied: target container has no matching workspace label", nil
	}
	return "", nil
}

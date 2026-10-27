package filter

import (
	"log/slog"
	"net/http"
)

// Fork-owned (wyrd-company/sockguard): the workspace header on exec.
//
// In a policy whose container_create block applies workspace exceptions,
// exec create and exec start must name a valid workspace in a header, the
// way container create must. The check reads no body and runs in the exec
// inspector's bucket ahead of it, so a request without one is denied before
// the exec inspector reads the daemon.

type forkExecWorkspacePolicy struct {
	apply bool
	store *WorkspaceExceptionStore
}

func newForkExecWorkspacePolicy(cfg PolicyConfig) forkExecWorkspacePolicy {
	return forkExecWorkspacePolicy{
		apply: cfg.ContainerCreate.ApplyWorkspaceExceptions,
		store: cfg.ContainerCreate.WorkspaceExceptions,
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
	_, reason := workspaceHeaderDenyReason(r.Header, p.store.Load(), subject)
	return reason, nil
}

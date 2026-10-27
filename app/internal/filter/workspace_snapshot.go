// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"context"
	"net/http"
)

// A value records admission even when snapshot is nil, missing or invalid.
// Its store identifies the policy that admitted the request.
type workspaceAdmittedSnapshot struct {
	store    *WorkspaceExceptionStore
	snapshot *WorkspaceExceptionSnapshot
}

type workspaceSnapshotContextKey struct{}

// captureWorkspaceSnapshot runs before the selected policy's body inspectors,
// including admission mutation. Each invocation replaces any inherited value;
// a reused context cannot carry another request or profile's admission.
func (p containerCreatePolicy) captureWorkspaceSnapshot(r *http.Request, normalizedPath string) {
	if !p.applyWorkspaceExceptions || r == nil || r.Method != http.MethodPost || normalizedPath != "/containers/create" {
		return
	}
	admitted := workspaceAdmittedSnapshot{store: p.workspaceExceptions, snapshot: p.workspaceExceptions.Load()}
	*r = *r.WithContext(context.WithValue(r.Context(), workspaceSnapshotContextKey{}, admitted))
}

func (p containerCreatePolicy) requestWorkspaceSnapshot(r *http.Request) *WorkspaceExceptionSnapshot {
	if admitted, ok := r.Context().Value(workspaceSnapshotContextKey{}).(workspaceAdmittedSnapshot); ok && admitted.store == p.workspaceExceptions {
		return admitted.snapshot
	}
	// Direct inspector calls have no earlier body reader. Capture at their
	// own entry, retaining the same contract as the composed middleware.
	return p.workspaceExceptions.Load()
}

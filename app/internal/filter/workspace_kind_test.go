// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"net/http"
	"testing"
)

func TestWorkspaceCreateLabelKind(t *testing.T) {
	h, sockets := newScopeHarness(t, privilegedGrant)
	opts := h.scopeOptions(sockets, nil)
	for _, header := range []string{WorkspaceHeader, WorkspaceThrowawayHeader} {
		same, opposite := WorkspaceLocalFolderLabel, WorkspaceThrowawayLabel
		if header == WorkspaceThrowawayHeader {
			same, opposite = opposite, same
		}
		for _, tc := range []struct {
			name   string
			labels map[string]string
			deny   string
		}{
			{"absent", nil, ""},
			{"same", map[string]string{same: h.f.alpha}, ""},
			{"mismatch", map[string]string{same: h.f.beta}, "disagrees with the request's workspace"},
			{"empty same", map[string]string{same: ""}, "disagrees with the request's workspace"},
			{"opposite", map[string]string{opposite: h.f.alpha}, "workspace kind"},
			{"empty opposite", map[string]string{opposite: ""}, "workspace kind"},
			{"both equal", map[string]string{same: h.f.alpha, opposite: h.f.alpha}, "workspace kind"},
		} {
			t.Run(header+"/"+tc.name, func(t *testing.T) {
				req := scopedRequest(tc.labels, h.f.alpha+":/workspace")
				req.headers = http.Header{header: {h.f.alpha}}
				if tc.deny == "" {
					h.with(t).admit(opts, req)
				} else {
					h.with(t).deny(opts, req, tc.deny)
				}
			})
		}
	}
}

// Grok P1's exact input: alpha grants beta, but the only mount is beta.
func TestWorkspaceScopeExtraBetaWithoutAlphaMount(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{h.f.beta}}))))
	h.store.Reload()
	opts := h.scopeOptions(sockets, nil)
	control := scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/workspace", h.f.beta+":/shared")
	control.headers = http.Header{WorkspaceHeader: {h.f.alpha}}
	h.admit(opts, control)
	onlyBeta := scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.beta+":/shared")
	onlyBeta.headers = http.Header{WorkspaceHeader: {h.f.alpha}}
	match := MatchWorkspaceException(h.store.Load(), h.f.alpha, WorkspaceExceptionRequest{Binds: []string{h.f.beta + ":/shared"}})
	if match.Applied() || match.Outcome != WorkspaceExceptionNotApplied {
		t.Fatalf("beta-only match = %+v, want not_applied", match)
	}
	h.deny(opts, onlyBeta, "outside this workspace's folder")
}

// Grok P2: a devcontainer header cannot use extras with a throwaway label.
func TestWorkspaceCreateMixedKindWithExtras(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{h.f.beta}}))))
	h.store.Reload()
	opts := h.scopeOptions(sockets, nil)
	req := scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/workspace", h.f.beta+":/shared")
	req.headers = http.Header{WorkspaceHeader: {h.f.alpha}}
	h.admit(opts, req)
	req.labels[WorkspaceThrowawayLabel] = h.f.alpha
	h.deny(opts, req, "workspace kind")
	delete(req.labels, WorkspaceLocalFolderLabel)
	h.deny(opts, req, "workspace kind")
}

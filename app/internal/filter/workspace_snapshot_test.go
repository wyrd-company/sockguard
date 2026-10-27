// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

func workspaceSnapshotRule(t *testing.T) *CompiledRule {
	t.Helper()
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func workspaceSnapshotMutation(mode string) MutationOptions {
	if mode == "none" {
		return MutationOptions{}
	}
	return MutationOptions{Rules: []MutationRuleOptions{{ID: "sample-label", Mode: mode, Surfaces: []string{mutationSurfaceContainerCreate}, InjectLabels: &InjectLabelsMutationOptions{Labels: map[string]string{"com.example.admission": "yes"}}}}}
}

// Hold the composed handler at the first body read, replace the policy, and
// complete a fresh request while that read is held. Both requests then prove
// their own admission snapshot and whether an upstream write occurred.
func TestWorkspaceSnapshotBeforeMutation(t *testing.T) {
	for _, profile := range []bool{false, true} {
		surface := "default"
		if profile {
			surface = "profile"
		}
		for _, tc := range []struct {
			name, mode, initial string
			replace             bool
			next                bool
		}{
			{"no mutation revoke control", "none", "grant", true, false},
			{"mutation no reload control", "enforce", "grant", false, true},
			{"mutation no grant control", "enforce", "denied", false, false},
			{"mutation revoke", "enforce", "grant", true, false},
			{"mutation add", "enforce", "denied", true, true},
			{"missing then add", "enforce", "missing", true, true},
			{"invalid then add", "enforce", "invalid", true, true},
			{"warn revoke", "warn", "grant", true, false},
			{"warn add", "warn", "denied", true, true},
			{"audit revoke", "audit", "grant", true, false},
			{"audit add", "audit", "denied", true, true},
		} {
			t.Run(surface+"/"+tc.name, func(t *testing.T) {
				entry := func(grant bool) func(workspaceExceptionsFixture) []map[string]any {
					return func(f workspaceExceptionsFixture) []map[string]any {
						return []map[string]any{workspaceEntryDoc(f.alpha, map[string]any{"privileged": grant})}
					}
				}
				h := newWSHarness(t, entry(tc.initial == "grant"))
				if tc.initial == "missing" {
					if err := os.Remove(h.f.file); err != nil {
						t.Fatal(err)
					}
					if h.store.Reload().State() != WorkspaceExceptionsMissing {
						t.Fatal("missing control did not load")
					}
				}
				if tc.initial == "invalid" {
					writeAtomic(t, h.f.file, []byte(`{"bad":true}`))
					if h.store.Reload().State() != WorkspaceExceptionsInvalid {
						t.Fatal("invalid control did not load")
					}
				}
				cfg := PolicyConfig{ContainerCreate: h.options(nil), DenyResponseVerbosity: DenyResponseVerbosityVerbose}
				if tc.mode == "enforce" {
					cfg.ContainerCreate.RequiredLabels = []string{"com.example.admission"}
				}
				opts := Options{PolicyConfig: cfg, Mutation: workspaceSnapshotMutation(tc.mode)}
				rule := workspaceSnapshotRule(t)
				if profile {
					opts.Profiles = map[string]Policy{"sample": {Rules: []*CompiledRule{rule}, PolicyConfig: cfg}}
					opts.ResolveProfile = func(*http.Request) (string, bool) { return "sample", true }
					opts.PolicyConfig = PolicyConfig{}
				}
				var mu sync.Mutex
				forwarded := map[string][]byte{}
				handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, err.Error(), 500)
						return
					}
					mu.Lock()
					forwarded[r.Header.Get("X-Test-Request")] = data
					mu.Unlock()
					w.WriteHeader(http.StatusNoContent)
				}))
				bodyText := wsRequest(h.f.alpha, map[string]any{"Privileged": true}).body(t)
				body := &holdingBody{reached: make(chan struct{}), release: make(chan struct{}), r: strings.NewReader(bodyText)}
				req := httptest.NewRequest(http.MethodPost, "/v1.51/containers/create", body)
				req.Header.Set(WorkspaceHeader, h.f.alpha)
				req.Header.Set("X-Test-Request", "held")
				rec := httptest.NewRecorder()
				done := make(chan struct{})
				var release sync.Once
				go func() { defer close(done); handler.ServeHTTP(rec, req) }()
				defer func() { release.Do(func() { close(body.release) }); <-done }()
				select {
				case <-body.reached:
				case <-done:
					t.Fatalf("held boundary not reached: status %d body %s", rec.Code, rec.Body.String())
				}
				if tc.replace {
					writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(entry(tc.next)(h.f)...)))
					if h.store.Reload().State() != WorkspaceExceptionsLoaded {
						t.Fatal("replacement did not load")
					}
				}
				fresh := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(bodyText))
				fresh.Header.Set(WorkspaceHeader, h.f.alpha)
				fresh.Header.Set("X-Test-Request", "fresh")
				freshRec := httptest.NewRecorder()
				handler.ServeHTTP(freshRec, fresh)
				assertResult := func(name string, rec *httptest.ResponseRecorder, grant bool) {
					t.Helper()
					want := http.StatusForbidden
					if grant {
						want = http.StatusNoContent
					}
					mu.Lock()
					data, passed := forwarded[name]
					mu.Unlock()
					if rec.Code != want || passed != grant {
						t.Fatalf("%s admission snapshot: status=%d forwarded=%t want=%d body=%s", name, rec.Code, passed, want, rec.Body.String())
					}
					if grant && tc.mode == "enforce" {
						var doc struct{ Labels map[string]string }
						if err := json.Unmarshal(data, &doc); err != nil {
							t.Fatal(err)
						}
						if doc.Labels["com.example.admission"] != "yes" {
							t.Fatalf("%s mutation must precede validation and forwarding: %s", name, data)
						}
					}
				}
				assertResult("fresh", freshRec, tc.next)
				release.Do(func() { close(body.release) })
				<-done
				assertResult("held", rec, tc.initial == "grant")
			})
		}
	}
}

func TestWorkspaceSnapshotRequestAndProfileIsolation(t *testing.T) {
	first := newWSHarness(t, privilegedGrant)
	second := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{workspaceEntryDoc(f.alpha, nil)}
	})
	rule := workspaceSnapshotRule(t)
	cfg := func(h *wsHarness) PolicyConfig {
		return PolicyConfig{ContainerCreate: h.options(nil), DenyResponseVerbosity: DenyResponseVerbosityVerbose}
	}
	opts := Options{PolicyConfig: cfg(first), Mutation: workspaceSnapshotMutation("enforce"), Profiles: map[string]Policy{"second": {Rules: []*CompiledRule{rule}, PolicyConfig: cfg(second)}}, ResolveProfile: func(r *http.Request) (string, bool) { name := r.Header.Get("X-Test-Profile"); return name, name != "" }}
	var inherited context.Context
	handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inherited = r.Context()
		w.WriteHeader(http.StatusNoContent)
	}))
	send := func(h *wsHarness, profile string, ctx context.Context, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(wsRequest(h.f.alpha, map[string]any{"Privileged": true}).body(t)))
		req.Header.Set(WorkspaceHeader, h.f.alpha)
		req.Header.Set("X-Test-Profile", profile)
		if ctx != nil {
			req = req.WithContext(ctx)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("request/profile snapshot isolation: profile=%q status=%d want=%d body=%s", profile, rec.Code, want, rec.Body.String())
		}
	}
	send(first, "", nil, http.StatusNoContent)
	old := inherited
	writeAtomic(t, first.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(first.f.alpha, nil))))
	first.store.Reload()
	writeAtomic(t, second.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(second.f.alpha, map[string]any{"privileged": true}))))
	second.store.Reload()
	send(first, "", old, http.StatusForbidden)
	send(second, "second", old, http.StatusNoContent)
	send(first, "", inherited, http.StatusForbidden)
}

func TestWorkspaceSnapshotExplicitAdmissionAndScope(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	p := newContainerCreatePolicy(h.options(nil))
	req := httptest.NewRequest(http.MethodPost, "/containers/create", nil)
	// Explicit nil is an admitted absence, not permission to read the live store.
	req = req.WithContext(context.WithValue(req.Context(), workspaceSnapshotContextKey{}, workspaceAdmittedSnapshot{store: h.store, snapshot: nil}))
	if got := p.requestWorkspaceSnapshot(req); got != nil {
		t.Fatal("explicit nil admission must not fall back to live policy")
	}
	// A direct inspector of another policy cannot borrow this store's snapshot.
	other := newWSHarness(t, nil)
	otherPolicy := newContainerCreatePolicy(other.options(nil))
	req = req.WithContext(context.WithValue(req.Context(), workspaceSnapshotContextKey{}, workspaceAdmittedSnapshot{store: other.store, snapshot: other.store.Load()}))
	if got := p.requestWorkspaceSnapshot(req); got != h.store.Load() {
		t.Fatal("foreign profile admission must not leak into direct inspection")
	}
	for _, tc := range []struct {
		name, method, path string
		apply              bool
	}{
		{"disabled", http.MethodPost, "/containers/create", false},
		{"read", http.MethodGet, "/containers/create", true},
		{"libpod", http.MethodPost, "/libpod/containers/create", true},
		{"exec", http.MethodPost, "/containers/sample/exec", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := newContainerCreatePolicy(h.options(func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = tc.apply }))
			r := httptest.NewRequest(tc.method, tc.path, nil)
			q.captureWorkspaceSnapshot(r, tc.path)
			if r.Context().Value(workspaceSnapshotContextKey{}) != nil {
				t.Fatal("snapshot capture must stay on opted-in Docker create")
			}
		})
	}
	p.captureWorkspaceSnapshot(nil, "/containers/create")
	// A different profile always captures its own store, even on a reused context.
	otherPolicy.captureWorkspaceSnapshot(req, "/containers/create")
	if got := otherPolicy.requestWorkspaceSnapshot(req); got != other.store.Load() {
		t.Fatal("selected policy must capture its own store")
	}
}

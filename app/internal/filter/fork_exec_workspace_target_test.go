// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForkExecWorkspaceTarget(t *testing.T) {
	h := newWSHarness(t, nil)
	for _, route := range []string{"/containers/sample/exec", "/exec/instance/start", "/libpod/containers/sample/exec", "/libpod/exec/instance/start"} {
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
				{"same", map[string]string{same: h.f.alpha}, ""},
				{"missing", nil, "target container has no matching workspace label"},
				{"mismatch", map[string]string{same: h.f.beta}, "disagrees with the request's workspace"},
				{"opposite", map[string]string{opposite: h.f.alpha}, "workspace kind"},
				{"both", map[string]string{same: h.f.alpha, opposite: h.f.alpha}, "workspace kind"},
			} {
				t.Run(route+"/"+header+"/"+tc.name, func(t *testing.T) {
					calls := 0
					cfg := PolicyConfig{ContainerCreate: h.options(nil)}
					cfg.Exec.AllowAnyCommand = true
					cfg.Exec.InspectStart = func(_ context.Context, id string) (ExecInspectResult, bool, error) {
						if strings.HasPrefix(route, "/libpod/") {
							t.Fatal("Docker exec inspector used for libpod")
						}
						if id != "instance" {
							t.Fatalf("exec id = %q", id)
						}
						return ExecInspectResult{ContainerID: "sample", Command: []string{"true"}, User: "1000"}, true, nil
					}
					cfg.Exec.InspectStartLibpod = func(_ context.Context, id string) (ExecInspectResult, bool, error) {
						if !strings.HasPrefix(route, "/libpod/") {
							t.Fatal("libpod exec inspector used for Docker")
						}
						if id != "instance" {
							t.Fatalf("exec id = %q", id)
						}
						return ExecInspectResult{ContainerID: "sample", Command: []string{"true"}, User: "1000"}, true, nil
					}
					cfg.ForkStartRecheck.InspectContainer = func(_ context.Context, id string) (ForkStartRecheckContainer, error) {
						calls++
						if id != "sample" {
							t.Fatalf("target id = %q, want sample", id)
						}
						return ForkStartRecheckContainer{Config: ForkStartRecheckConfig{Labels: tc.labels}}, nil
					}
					rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/**", Action: ActionAllow})
					if err != nil {
						t.Fatal(err)
					}
					cfg.DenyResponseVerbosity = DenyResponseVerbosityVerbose
					forwarded := false
					handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{PolicyConfig: cfg})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { forwarded = true; w.WriteHeader(http.StatusNoContent) }))
					req := httptest.NewRequest(http.MethodPost, "/v1.51"+route, strings.NewReader(`{"Cmd":["true"],"User":"1000"}`))
					req.Header.Set(header, h.f.alpha)
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					if calls != 1 {
						t.Fatalf("container inspections = %d, want 1", calls)
					}
					if tc.deny == "" {
						if rec.Code != http.StatusNoContent || !forwarded {
							t.Fatalf("matching target: status %d body %s forwarded %t", rec.Code, rec.Body.String(), forwarded)
						}
					} else if rec.Code != http.StatusForbidden || forwarded || !strings.Contains(rec.Body.String(), tc.deny) {
						t.Fatalf("target guard: status %d body %s forwarded %t, want 403 with %q", rec.Code, rec.Body.String(), forwarded, tc.deny)
					}
				})
			}
		}
	}
}

func TestForkExecWorkspaceTargetLookupFailures(t *testing.T) {
	h := newWSHarness(t, nil)
	for _, tc := range []struct {
		name    string
		edit    func(*PolicyConfig)
		want    string
		wantErr bool
	}{
		{"container inspector missing", func(c *PolicyConfig) { c.ForkStartRecheck.InspectContainer = nil }, "no workspace container inspection", false},
		{"container inspect failure", func(c *PolicyConfig) {
			c.ForkStartRecheck.InspectContainer = func(context.Context, string) (ForkStartRecheckContainer, error) {
				return ForkStartRecheckContainer{}, errors.New("lookup failed")
			}
		}, "inspect workspace exec container", true},
		{"exec inspector missing", func(c *PolicyConfig) { c.Exec.InspectStart = nil }, "no workspace exec inspection", false},
		{"exec missing", func(c *PolicyConfig) {
			c.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) { return ExecInspectResult{}, false, nil }
		}, "workspace exec target is missing", false},
		{"exec missing with stale metadata", func(c *PolicyConfig) {
			c.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) {
				return ExecInspectResult{ContainerID: "sample"}, false, nil
			}
		}, "workspace exec target is missing", false},
		{"exec target empty", func(c *PolicyConfig) {
			c.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) { return ExecInspectResult{}, true, nil }
		}, "workspace exec target is missing", false},
		{"exec inspect failure", func(c *PolicyConfig) {
			c.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) {
				return ExecInspectResult{}, false, errors.New("lookup failed")
			}
		}, "inspect workspace exec target", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := PolicyConfig{ContainerCreate: h.options(nil)}
			cfg.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) {
				return ExecInspectResult{ContainerID: "sample"}, true, nil
			}
			cfg.ForkStartRecheck.InspectContainer = func(context.Context, string) (ForkStartRecheckContainer, error) {
				return ForkStartRecheckContainer{Config: ForkStartRecheckConfig{Labels: map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}}}, nil
			}
			req := httptest.NewRequest(http.MethodPost, "/exec/instance/start", nil)
			req.Header.Set(WorkspaceHeader, h.f.alpha)
			if reason, err := newForkExecWorkspacePolicy(cfg).inspect(testLogger(), req, req.URL.Path); reason != "" || err != nil {
				t.Fatalf("positive control: %q %v", reason, err)
			}
			tc.edit(&cfg)
			reason, err := newForkExecWorkspacePolicy(cfg).inspect(testLogger(), req, req.URL.Path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("lookup error = %v, want %q", err, tc.want)
				}
			} else if err != nil || !strings.Contains(reason, tc.want) {
				t.Fatalf("lookup denial = %q %v, want %q", reason, err, tc.want)
			}
		})
	}
}

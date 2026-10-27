// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestServeChainExecWorkspaceTarget(t *testing.T) {
	for _, profile := range []bool{false, true} {
		name := "default"
		if profile {
			name = "profile"
		}
		t.Run(name, func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			f.write(t, false)
			socket := shortSocketPath(t, "ws-exec")
			var mu sync.Mutex
			var seen []string
			startUnixHTTPUpstream(t, socket, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seen = append(seen, r.Method+" "+r.URL.Path)
				mu.Unlock()
				switch {
				case r.Method == http.MethodGet && (r.URL.Path == "/exec/instance/json" || r.URL.Path == "/libpod/exec/instance/json"):
					_ = json.NewEncoder(w).Encode(map[string]any{"ContainerID": "sample", "ProcessConfig": map[string]any{"entrypoint": "true", "user": "1000"}})
				case r.Method == http.MethodGet && r.URL.Path == "/containers/sample/json":
					_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Labels": map[string]string{filter.WorkspaceLocalFolderLabel: f.alpha}}})
				case r.Method == http.MethodPost:
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected lookup", http.StatusNotFound)
				}
			}))
			cfg := f.config(socket)
			cfg.Rules = nil
			for _, pattern := range []string{"/containers/*/exec", "/exec/*/start", "/libpod/containers/*/exec", "/libpod/exec/*/start"} {
				cfg.Rules = append(cfg.Rules, config.RuleConfig{Match: config.MatchConfig{Method: http.MethodPost, Path: pattern}, Action: "allow"})
			}
			cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
			cfg.RequestBody.Exec.AllowAnyCommand = true
			if profile {
				cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "sample", Rules: cfg.Rules, RequestBody: cfg.RequestBody}}
				cfg.Clients.DefaultProfile = "sample"
				cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = false
			}
			if err := config.Validate(&cfg); err != nil {
				t.Fatal(err)
			}
			if _, err := compileClientProfiles(&cfg); err != nil {
				t.Fatal(err)
			}
			rules, err := compileRuleConfigsForTest(cfg.Rules)
			if err != nil {
				t.Fatal(err)
			}
			deps := newServeTestDeps()
			runtime, err := newServeRuntime(&cfg, newDiscardLogger(), deps)
			if err != nil {
				t.Fatal(err)
			}
			if err := runtime.loadWorkspaceExceptions(&cfg, newDiscardLogger()); err != nil {
				t.Fatal(err)
			}
			handler, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{Cfg: &cfg, Logger: newDiscardLogger(), Rules: rules, Deps: deps, Runtime: runtime})
			defer teardown()
			for _, route := range []string{"/containers/sample/exec", "/exec/instance/start", "/libpod/containers/sample/exec", "/libpod/exec/instance/start"} {
				for _, header := range []string{filter.WorkspaceHeader, filter.WorkspaceThrowawayHeader} {
					mu.Lock()
					seen = nil
					mu.Unlock()
					req := httptest.NewRequest(http.MethodPost, "/v1.51"+route, strings.NewReader(`{"Cmd":["true"],"User":"1000"}`))
					req.Header.Set(header, f.alpha)
					rec := httptest.NewRecorder()
					handler.ServeHTTP(rec, req)
					mu.Lock()
					calls := append([]string(nil), seen...)
					mu.Unlock()
					if header == filter.WorkspaceHeader {
						if rec.Code != http.StatusNoContent {
							t.Fatalf("%s matching target: status %d body %s lookups %v", route, rec.Code, rec.Body.String(), calls)
						}
					} else if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "workspace kind") {
						t.Fatalf("%s opposite target: status %d body %s lookups %v", route, rec.Code, rec.Body.String(), calls)
					}
					containerReads, posts := 0, 0
					for _, call := range calls {
						if call == "GET /containers/sample/json" {
							containerReads++
						}
						if strings.HasPrefix(call, "POST ") {
							posts++
						}
					}
					if containerReads != 1 {
						t.Fatalf("%s container reads = %d, want 1: %v", route, containerReads, calls)
					}
					expectedPosts := 0
					if header == filter.WorkspaceHeader {
						expectedPosts = 1
					}
					if posts != expectedPosts {
						t.Fatalf("%s forwarded writes = %d, want %d: %v", route, posts, expectedPosts, calls)
					}
				}
			}
		})
	}
}

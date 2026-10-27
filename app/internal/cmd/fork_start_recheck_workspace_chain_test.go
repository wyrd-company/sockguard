// relationships:
//
// references: [../../../docs/content/docs/workspace-exceptions]
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

type startWorkspaceDaemon struct {
	mu        sync.Mutex
	container filter.ForkStartRecheckContainer
	volume    filter.ForkStartRecheckVolume
	seen      []string
}

func (d *startWorkspaceDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, r.Method+" "+r.URL.Path)
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/containers/c1/json":
		_ = json.NewEncoder(w).Encode(d.container)
	case r.Method == http.MethodGet && r.URL.Path == "/volumes/data":
		_ = json.NewEncoder(w).Encode(d.volume)
	case r.Method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
func (d *startWorkspaceDaemon) set(sources []string, labels map[string]string, device string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.container = filter.ForkStartRecheckContainer{Config: filter.ForkStartRecheckConfig{Labels: labels}}
	for _, source := range sources {
		d.container.Mounts = append(d.container.Mounts, filter.ForkStartRecheckMount{Type: "bind", Source: source})
	}
	if device != "" {
		d.container.Mounts = append(d.container.Mounts, filter.ForkStartRecheckMount{Type: "volume", Name: "data"})
		d.volume = filter.ForkStartRecheckVolume{Driver: "local", Options: map[string]string{"type": "none", "o": "bind", "device": device, "private": "must-not-appear"}}
	}
	d.seen = nil
}
func (d *startWorkspaceDaemon) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

type startWorkspaceChain struct {
	handler http.Handler
	store   *filter.WorkspaceExceptionStore
}

func newStartWorkspaceChain(t *testing.T, cfg config.Config, d *startWorkspaceDaemon) startWorkspaceChain {
	t.Helper()
	cfg.Upstream.Socket = shortSocketPath(t, "start-ws")
	startUnixHTTPUpstream(t, cfg.Upstream.Socket, d)
	cfg.Upstream.Flavor = "docker"
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Response.DenyVerbosity = "verbose"
	cfg.Rules = nil
	for _, prefix := range []string{"/containers/", "/libpod/containers/"} {
		for _, action := range []string{"start", "restart"} {
			cfg.Rules = append(cfg.Rules, config.RuleConfig{Match: config.MatchConfig{Method: "POST", Path: prefix + "*/" + action}, Action: "allow"})
		}
	}
	for i := range cfg.Clients.Profiles {
		cfg.Clients.Profiles[i].Rules = cfg.Rules
	}
	if _, err := compileClientProfiles(&cfg); err != nil {
		t.Fatal(err)
	}
	if err := config.Validate(&cfg); err != nil {
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
	t.Cleanup(teardown)
	return startWorkspaceChain{handler: handler, store: runtime.workspaceExceptions}
}

func (c startWorkspaceChain) post(t *testing.T, route string, headers http.Header, want int, reason string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, route, nil)
	r.Header = headers.Clone()
	if r.Header == nil {
		r.Header = make(http.Header)
	}
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, r)
	if w.Code != want || !strings.Contains(w.Body.String(), reason) {
		t.Fatalf("%s status=%d body=%s; want %d containing %q", route, w.Code, w.Body.String(), want, reason)
	}
	if strings.Contains(w.Body.String(), "must-not-appear") {
		t.Fatal("driver option leaked")
	}
}

func TestServeChainForkStartWorkspaceIdentityAndScope(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bindfs.RealRootForTest(t, root)
	ws := filepath.Join(root, "ws")
	alpha, beta := filepath.Join(ws, "alpha"), filepath.Join(ws, "beta")
	sockets, stage, extra := filepath.Join(root, "sockets"), filepath.Join(root, "stage"), filepath.Join(root, "extra")
	roots := []string{ws, sockets, stage}
	for _, r := range roots {
		for _, name := range []string{"alpha", "beta"} {
			if err := os.MkdirAll(filepath.Join(r, name, "data"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.MkdirAll(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(beta, "shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "exceptions.json")
	write := func(valid bool) {
		body := []byte(`{"invalid":true}`)
		if valid {
			body, err = json.Marshal(map[string]any{"version": 1, "exceptions": []any{map[string]any{"workspace": alpha, "grants": map[string]any{"extraBindSources": []string{extra, filepath.Join(beta, "shared")}}, "approval": map[string]any{"by": map[string]string{"issuer": "https://id.example.org", "subject": "user-0001"}, "at": "2026-01-02T03:04:05Z"}}}})
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(file, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, profile := range []bool{false, true} {
		name := "default"
		if profile {
			name = "named-profile"
		}
		t.Run(name, func(t *testing.T) {
			write(true)
			cfg := config.Defaults()
			cfg.WorkspaceExceptions = config.WorkspaceExceptionsConfig{File: file, WorkspaceRoot: ws, PerWorkspaceRoots: roots}
			cfg.RequestBody.ContainerCreate.AllowedBindMounts = roots
			cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = !profile
			if profile {
				p := config.ClientProfileConfig{Name: "sample"}
				p.RequestBody.ContainerCreate.AllowedBindMounts = roots
				p.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
				cfg.Clients.Profiles = []config.ClientProfileConfig{p}
				cfg.Clients.DefaultProfile = p.Name
			}
			d := &startWorkspaceDaemon{}
			chain := newStartWorkspaceChain(t, cfg, d)
			plainCfg := cfg
			plainCfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = false
			plainCfg.Clients.Profiles = slices.Clone(cfg.Clients.Profiles)
			for i := range plainCfg.Clients.Profiles {
				plainCfg.Clients.Profiles[i].RequestBody.ContainerCreate.ApplyWorkspaceExceptions = false
			}
			plain := newStartWorkspaceChain(t, plainCfg, d)
			dev := http.Header{filter.WorkspaceHeader: {alpha}}
			throw := http.Header{filter.WorkspaceThrowawayHeader: {alpha}}
			for _, route := range []string{"/containers/c1/start", "/v1.45/containers/c1/restart", "/libpod/containers/c1/start", "/v5.0.0/libpod/containers/c1/restart"} {
				d.set([]string{alpha}, nil, "")
				chain.post(t, route, dev, 204, "") // absent same-kind label remains supported
				chain.post(t, route, throw, 204, "")
				for _, tc := range []struct {
					name    string
					headers http.Header
					reason  string
				}{
					{"missing", nil, "the request names no workspace"},
					{"both", http.Header{filter.WorkspaceHeader: {alpha}, filter.WorkspaceThrowawayHeader: {beta}}, "the request names more than one workspace"},
					{"repeat-dev", http.Header{filter.WorkspaceHeader: {alpha, beta}}, "the request names more than one workspace"},
					{"repeat-throw", http.Header{filter.WorkspaceThrowawayHeader: {alpha, alpha}}, "the request names more than one workspace"},
					{"empty", http.Header{filter.WorkspaceHeader: {""}}, "does not name a valid workspace"},
					{"invalid", http.Header{filter.WorkspaceHeader: {extra}}, "does not name a valid workspace"},
				} {
					t.Run(tc.name+route, func(t *testing.T) {
						r := httptest.NewRequest(http.MethodPost, route, nil)
						r.Header = tc.headers.Clone()
						if r.Header == nil {
							r.Header = make(http.Header)
						}
						w := httptest.NewRecorder()
						chain.handler.ServeHTTP(w, r)
						if w.Code != 403 || !strings.Contains(w.Body.String(), tc.reason) {
							t.Fatalf("header guard: %d %s", w.Code, w.Body.String())
						}
						for _, values := range tc.headers {
							for _, v := range values {
								if v != "" && strings.Contains(w.Body.String(), v) {
									t.Fatal("header value leaked")
								}
							}
						}
					})
				}
			}
			for _, tc := range []struct {
				name    string
				labels  map[string]string
				headers http.Header
				want    int
			}{
				{"equal-dev", map[string]string{filter.WorkspaceLocalFolderLabel: alpha}, dev, 204},
				{"equal-throw", map[string]string{filter.WorkspaceThrowawayLabel: alpha}, throw, 204},
				{"mismatched-dev", map[string]string{filter.WorkspaceLocalFolderLabel: beta}, dev, 403},
				{"mismatched-throw", map[string]string{filter.WorkspaceThrowawayLabel: beta}, throw, 403},
				{"opposite-throw", map[string]string{filter.WorkspaceThrowawayLabel: alpha}, dev, 403},
				{"opposite-dev", map[string]string{filter.WorkspaceLocalFolderLabel: alpha}, throw, 403},
				{"empty-opposite", map[string]string{filter.WorkspaceThrowawayLabel: ""}, dev, 403},
				{"both-equal", map[string]string{filter.WorkspaceLocalFolderLabel: alpha, filter.WorkspaceThrowawayLabel: alpha}, dev, 403},
			} {
				t.Run(tc.name, func(t *testing.T) {
					d.set([]string{alpha}, tc.labels, "")
					reason := ""
					if tc.want == 403 {
						reason = "workspace label"
					}
					chain.post(t, "/containers/c1/start", tc.headers, tc.want, reason)
				})
			}
			for _, r := range roots {
				t.Run("swap-"+filepath.Base(r), func(t *testing.T) {
					own, other := filepath.Join(r, "alpha", "data"), filepath.Join(r, "beta", "data")
					if r != ws {
						own, other = filepath.Join(r, "alpha"), filepath.Join(r, "beta")
					}
					d.set([]string{alpha, own}, nil, "")
					chain.post(t, "/containers/c1/start", dev, 204, "")
					if err := os.Rename(own, own+".orig"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(other, own); err != nil {
						t.Fatal(err)
					}
					chain.post(t, "/containers/c1/restart", dev, 403, "outside the request's workspace")
					plain.post(t, "/containers/c1/restart", nil, 204, "")
					if err := os.Remove(own); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(own+".orig", own); err != nil {
						t.Fatal(err)
					}
				})
			}
			t.Run("extras-current-inspected-match", func(t *testing.T) {
				d.set([]string{alpha, extra}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 204, "")
				chain.post(t, "/containers/c1/start", throw, 403, "outside the request's workspace")
				d.set([]string{extra}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
				// Exact prior Grok regression: beta-only extra, no alpha mount.
				d.set([]string{filepath.Join(beta, "shared")}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
				d.set([]string{alpha, extra}, map[string]string{filter.WorkspaceThrowawayLabel: alpha}, "")
				chain.post(t, "/containers/c1/start", dev, 403, "workspace label")
				d.set([]string{alpha, extra}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 204, "")
				write(false)
				chain.store.Reload()
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
				// Invalid policy removes grants, never scoping.
				d.set([]string{filepath.Join(beta, "data")}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				chain.store.Reload()
				d.set([]string{alpha, extra}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
				write(true)
				chain.store.Reload()
				d.set([]string{alpha, extra}, nil, "")
				chain.post(t, "/containers/c1/start", dev, 204, "")
			})
			t.Run("volume-device", func(t *testing.T) {
				own, other := filepath.Join(alpha, "data"), filepath.Join(beta, "data")
				d.set([]string{alpha}, nil, own)
				chain.post(t, "/containers/c1/start", dev, 204, "")
				if !slices.Contains(d.requests(), "GET /volumes/data") {
					t.Fatal("serve volume inspector not attached")
				}
				if err := os.Rename(own, own+".orig"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, own); err != nil {
					t.Fatal(err)
				}
				// A volume device alone must not satisfy the workspace-mount
				// rule or lend an extra bind grant.
				d.set(nil, nil, own)
				chain.post(t, "/containers/c1/restart", dev, 403, "outside the request's workspace")
				if err := os.Remove(own); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(own+".orig", own); err != nil {
					t.Fatal(err)
				}
				d.set([]string{alpha}, nil, extra)
				chain.post(t, "/containers/c1/start", dev, 204, "")
				chain.post(t, "/containers/c1/start", throw, 403, "outside the request's workspace")
				d.set(nil, nil, extra)
				chain.post(t, "/containers/c1/start", dev, 403, "outside the request's workspace")
			})
		})
	}
}

func TestServeChainForkStartWorkspaceProfileGate(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default-off", true: "profile-off-global-on"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			cfg := f.config("")
			cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = named
			if named {
				p := config.ClientProfileConfig{Name: "plain"}
				p.RequestBody.ContainerCreate.AllowedBindMounts = []string{f.root}
				cfg.Clients.Profiles = []config.ClientProfileConfig{p}
				cfg.Clients.DefaultProfile = p.Name
			}
			d := &startWorkspaceDaemon{}
			d.set([]string{f.alpha}, map[string]string{filter.WorkspaceThrowawayLabel: "arbitrary"}, "")
			chain := newStartWorkspaceChain(t, cfg, d)
			for _, route := range []string{"/containers/c1/start", "/containers/c1/restart"} {
				for _, headers := range []http.Header{nil, {filter.WorkspaceHeader: {"invalid", "repeated"}, filter.WorkspaceThrowawayHeader: {"also-invalid"}}} {
					chain.post(t, route, headers, 204, "")
				}
			}
		})
	}
}

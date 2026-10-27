// relationships:
//
// references: [../../../docs/content/docs/workspace-exceptions]
package cmd

import (
	"encoding/json"
	"io"
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

type primaryGrantDaemon struct {
	mu      sync.Mutex
	inspect filter.ForkStartRecheckContainer
	volume  filter.ForkStartRecheckVolume
	writes  []string
	bodies  []string
	reads   []string
}

func (d *primaryGrantDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Method == http.MethodPost {
		b, _ := io.ReadAll(r.Body)
		d.writes = append(d.writes, r.Method+" "+r.URL.Path)
		d.bodies = append(d.bodies, string(b))
		if strings.HasSuffix(r.URL.Path, "/create") {
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"Id":"sample-id"}`))
		} else {
			w.WriteHeader(204)
		}
		return
	}
	d.reads = append(d.reads, r.Method+" "+r.URL.Path)
	if strings.HasSuffix(r.URL.Path, "/json") {
		_ = json.NewEncoder(w).Encode(d.inspect)
		return
	}
	if strings.Contains(r.URL.Path, "/volumes/") {
		_ = json.NewEncoder(w).Encode(d.volume)
		return
	}
	w.WriteHeader(404)
}
func primaryGrantChain(t *testing.T, f serveWorkspaceFixture, named bool, d *primaryGrantDaemon, edit ...func(*config.Config)) (http.Handler, *filter.WorkspaceExceptionStore) {
	t.Helper()
	sock := shortSocketPath(t, "primary-grant")
	startUnixHTTPUpstream(t, sock, d)
	cfg := f.config(sock)
	base := filepath.Join(filepath.Dir(f.root), "base")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = append(cfg.RequestBody.ContainerCreate.AllowedBindMounts, base)
	cfg.RequestBody.ContainerCreate.DenyUnconfinedSeccomp = true
	cfg.RequestBody.ContainerCreate.DenyUnconfinedAppArmor = true
	cfg.RequestBody.ContainerCreate.DenySelinuxDisable = true
	cfg.RequestBody.ContainerCreate.DenyUnconfinedSystemPaths = true
	cfg.RequestBody.ContainerCreate.AllowedSeccompProfiles = []string{"default"}
	cfg.RequestBody.ContainerCreate.AllowedAppArmorProfiles = []string{"default"}
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "POST", Path: "/containers/create"}, Action: "allow"}}
	for _, prefix := range []string{"/containers/", "/libpod/containers/"} {
		for _, action := range []string{"start", "restart"} {
			cfg.Rules = append(cfg.Rules, config.RuleConfig{Match: config.MatchConfig{Method: "POST", Path: prefix + "*/" + action}, Action: "allow"})
		}
	}
	cfg.RequestBody.ContainerCreate.RequireNoRestartPolicy = true
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = !named
	if named {
		p := config.ClientProfileConfig{Name: "sample", Rules: cfg.Rules}
		p.RequestBody.ContainerCreate = cfg.RequestBody.ContainerCreate
		p.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
		cfg.Clients.Profiles = []config.ClientProfileConfig{p}
		cfg.Clients.DefaultProfile = p.Name
	}
	for _, fn := range edit {
		fn(&cfg)
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
	h, teardown, _ := buildServeHandlerChainWithRuntime(serveHandlerBuild{Cfg: &cfg, Logger: newDiscardLogger(), Rules: rules, Deps: deps, Runtime: runtime})
	t.Cleanup(teardown)
	return h, runtime.workspaceExceptions
}
func primaryGrantPolicy(t *testing.T, f serveWorkspaceFixture, extra string, grants bool) {
	t.Helper()
	g := map[string]any{}
	if grants {
		g = map[string]any{"privileged": true, "restartPolicy": []string{"always"}, "extraBindSources": []string{extra}}
	}
	primaryGrantWritePolicy(t, f, g)
}
func primaryGrantWritePolicy(t *testing.T, f serveWorkspaceFixture, g map[string]any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": 1, "exceptions": []any{map[string]any{"workspace": f.alpha, "grants": g, "approval": map[string]any{"by": map[string]string{"issuer": "https://id.example.org", "subject": "user-0001"}, "at": "2026-01-02T03:04:05Z"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.file, b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPrimaryGrantCreate(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			extra := filepath.Join(filepath.Dir(f.root), "extra")
			if err := os.Mkdir(extra, 0755); err != nil {
				t.Fatal(err)
			}
			primaryGrantPolicy(t, f, extra, true)
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d)
			for _, route := range []string{"/containers/create", "/v1.45/containers/create"} {
				t.Run(route, func(t *testing.T) {
					for _, tc := range []struct {
						name, label, grant, header string
						want                       int
						noPolicy, base             bool
					}{
						{name: "labeled-primary-privileged", label: "same", grant: "privileged", want: 201},
						{name: "labeled-primary-restart", label: "same", grant: "restart", want: 201},
						{name: "labeled-primary-extra", label: "same", grant: "extra", want: 201},
						{name: "labeled-base-source-breaks-agreement", label: "same", grant: "privileged", base: true, want: 403},
						{name: "absent-label-base", want: 201},
						{name: "absent-label-own-bind-privileged-denied", grant: "privileged", want: 403},
						{name: "absent-label-own-bind-restart-denied", grant: "restart", want: 403},
						{name: "absent-label-own-bind-extra-denied", grant: "extra", want: 403},
						{name: "opposite-label", label: "opposite", grant: "privileged", want: 403},
						{name: "both-labels", label: "both", grant: "privileged", want: 403},
						{name: "mismatch-label", label: "mismatch", grant: "privileged", want: 403},
						{name: "label-alone-no-header", label: "same", grant: "privileged", header: "missing", want: 403},
						{name: "throwaway-base", header: "throwaway", want: 201},
						{name: "throwaway-privileged", header: "throwaway", grant: "privileged", want: 403},
						{name: "throwaway-restart", header: "throwaway", grant: "restart", want: 403},
						{name: "throwaway-extra", header: "throwaway", grant: "extra", want: 403},
						{name: "both-headers", header: "both", want: 403},
						{name: "empty-label", label: "empty", want: 403},
						{name: "repeated-header", header: "repeated", want: 403},
						{name: "empty-header", header: "empty", want: 403},
						{name: "invalid-header", header: "invalid", want: 403},
						{name: "absent-label-grant-removed-privileged", grant: "privileged", want: 403, noPolicy: true},
						{name: "absent-label-grant-removed-restart", grant: "restart", want: 403, noPolicy: true},
						{name: "absent-label-grant-removed-extra", grant: "extra", want: 403, noPolicy: true},
						{name: "grant-removed-privileged", label: "same", grant: "privileged", want: 403, noPolicy: true},
						{name: "grant-removed-restart", label: "same", grant: "restart", want: 403, noPolicy: true},
						{name: "grant-removed-extra", label: "same", grant: "extra", want: 403, noPolicy: true},
					} {
						t.Run(tc.name, func(t *testing.T) {
							primaryGrantPolicy(t, f, extra, !tc.noPolicy)
							store.Reload()
							labels := map[string]string{}
							switch tc.label {
							case "same":
								labels[filter.WorkspaceLocalFolderLabel] = f.alpha
							case "opposite":
								labels[filter.WorkspaceThrowawayLabel] = f.alpha
							case "both":
								labels[filter.WorkspaceThrowawayLabel] = f.alpha
								labels[filter.WorkspaceLocalFolderLabel] = f.alpha
							case "empty":
								labels[filter.WorkspaceLocalFolderLabel] = ""
							case "mismatch":
								labels[filter.WorkspaceLocalFolderLabel] = filepath.Join(f.root, "beta")
							}
							hc := map[string]any{"Binds": []string{f.alpha + ":/workspace"}}
							if tc.base {
								hc["Binds"] = []string{f.alpha + ":/workspace", filepath.Join(filepath.Dir(f.root), "base") + ":/base"}
							}
							switch tc.grant {
							case "privileged":
								hc["Privileged"] = true
							case "restart":
								hc["RestartPolicy"] = map[string]string{"Name": "always"}
							case "extra":
								hc["Binds"] = []string{f.alpha + ":/workspace", extra + ":/extra"}
							}
							b, err := json.Marshal(map[string]any{"Image": "busybox", "Labels": labels, "HostConfig": hc})
							if err != nil {
								t.Fatal(err)
							}
							r := httptest.NewRequest("POST", route, strings.NewReader(string(b)))
							if tc.header != "missing" {
								key := filter.WorkspaceHeader
								if tc.header == "throwaway" {
									key = filter.WorkspaceThrowawayHeader
								}
								r.Header.Set(key, f.alpha)
								switch tc.header {
								case "repeated":
									r.Header.Add(key, f.alpha)
								case "empty":
									r.Header.Set(key, "")
								case "invalid":
									r.Header.Set(key, f.alpha+"/../alpha")
								}
								if tc.header == "both" {
									r.Header.Set(filter.WorkspaceThrowawayHeader, f.alpha)
								}
							}
							d.mu.Lock()
							d.writes = nil
							d.bodies = nil
							d.reads = nil
							d.mu.Unlock()
							w := httptest.NewRecorder()
							h.ServeHTTP(w, r)
							d.mu.Lock()
							defer d.mu.Unlock()
							t.Logf("RESULT expected=%d actual=%d writes=%v input=%s forwarded=%v response=%s", tc.want, w.Code, d.writes, b, d.bodies, w.Body.String())
							if w.Code != tc.want {
								t.Errorf("GRANT_ELIGIBILITY_STATUS: got %d want %d", w.Code, tc.want)
							}
							if tc.want == 403 && len(d.writes) != 0 {
								t.Errorf("DENIED_WRITE_REACHED_DAEMON: %v bodies=%v", d.writes, d.bodies)
							}
							if w.Code == 201 {
								if len(d.writes) != 1 || len(d.bodies) != 1 {
									t.Fatalf("admission must forward exactly one write: %v", d.writes)
								}
								var forwarded map[string]any
								if err := json.Unmarshal([]byte(d.bodies[0]), &forwarded); err != nil {
									t.Fatal(err)
								}
								var original map[string]any
								_ = json.Unmarshal(b, &original)
								fb, _ := json.Marshal(forwarded)
								ob, _ := json.Marshal(original)
								if string(fb) != string(ob) {
									t.Errorf("FORWARDED_EFFECT_CHANGED: got %s want %s", fb, ob)
								}
							}
						})
					}
				})
			}
		})
	}
}
func TestPrimaryGrantStartRestart(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			extra := filepath.Join(filepath.Dir(f.root), "extra")
			if err := os.Mkdir(extra, 0755); err != nil {
				t.Fatal(err)
			}
			primaryGrantPolicy(t, f, extra, true)
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d)
			for _, route := range []string{"/containers/c1/start", "/containers/c1/restart", "/v1.45/containers/c1/start", "/v1.45/containers/c1/restart", "/libpod/containers/c1/start", "/libpod/containers/c1/restart", "/v5.0.0/libpod/containers/c1/start", "/v5.0.0/libpod/containers/c1/restart"} {
				t.Run(route, func(t *testing.T) {
					for _, tc := range []struct {
						name, label, header, policyState     string
						extra, volume, noPolicy, noOwn, base bool
						want                                 int
					}{
						{name: "labeled-primary-extra", label: "same", extra: true, want: 204},
						{name: "absent-label-base", want: 204},
						{name: "absent-label-inspected-extra-denied", extra: true, want: 403},
						{name: "labeled-primary-volume-device", label: "same", volume: true, want: 204},
						{name: "absent-label-volume-device-denied", volume: true, want: 403},
						{name: "opposite-label", label: "opposite", extra: true, want: 403},
						{name: "both-labels", label: "both", extra: true, want: 403},
						{name: "mismatch-label", label: "mismatch", extra: true, want: 403},
						{name: "label-alone-no-header", label: "same", header: "missing", extra: true, want: 403},
						{name: "throwaway-base", header: "throwaway", want: 204},
						{name: "throwaway-extra", header: "throwaway", extra: true, want: 403},
						{name: "throwaway-volume", header: "throwaway", volume: true, want: 403},
						{name: "no-own-bind-extra", label: "same", extra: true, noOwn: true, want: 403},
						{name: "no-own-bind-volume", label: "same", volume: true, noOwn: true, want: 403},
						{name: "empty-label-volume", label: "empty", volume: true, want: 403},
						{name: "opposite-label-volume", label: "opposite", volume: true, want: 403},
						{name: "both-labels-volume", label: "both", volume: true, want: 403},
						{name: "mismatch-label-volume", label: "mismatch", volume: true, want: 403},
						{name: "invalid-policy-extra", label: "same", extra: true, policyState: "invalid", want: 403},
						{name: "missing-policy-extra", label: "same", extra: true, policyState: "missing", want: 403},
						{name: "invalid-policy-volume", label: "same", volume: true, policyState: "invalid", want: 403},
						{name: "missing-policy-volume", label: "same", volume: true, policyState: "missing", want: 403},
						{name: "base-source-breaks-extra-agreement", label: "same", base: true, extra: true, want: 403},
						{name: "base-source-breaks-volume-agreement", label: "same", base: true, volume: true, want: 403},
						{name: "unlabeled-base-allowed-source", base: true, want: 204},
						{name: "labeled-base-allowed-source", label: "same", base: true, want: 204},
						{name: "base-no-own-bind", base: true, noOwn: true, want: 204},
						{name: "throwaway-base-allowed-source", header: "throwaway", base: true, want: 204},
						{name: "grant-removed-extra", label: "same", extra: true, noPolicy: true, want: 403},
						{name: "both-headers", header: "both", want: 403},
						{name: "empty-label", label: "empty", want: 403},
						{name: "repeated-header", header: "repeated", want: 403},
						{name: "empty-header", header: "empty", want: 403},
						{name: "invalid-header", header: "invalid", want: 403},
						{name: "absent-label-grant-removed-extra", extra: true, noPolicy: true, want: 403},
						{name: "absent-label-grant-removed-volume", volume: true, noPolicy: true, want: 403},
						{name: "grant-removed-volume", label: "same", volume: true, noPolicy: true, want: 403},
					} {
						t.Run(tc.name, func(t *testing.T) {
							primaryGrantPolicy(t, f, extra, !tc.noPolicy)
							switch tc.policyState {
							case "missing":
								if err := os.Remove(f.file); err != nil {
									t.Fatal(err)
								}
							case "invalid":
								if err := os.WriteFile(f.file, []byte(`{"invalid":true}`), 0600); err != nil {
									t.Fatal(err)
								}
							}
							store.Reload()
							labels := map[string]string{}
							switch tc.label {
							case "same":
								labels[filter.WorkspaceLocalFolderLabel] = f.alpha
							case "opposite":
								labels[filter.WorkspaceThrowawayLabel] = f.alpha
							case "both":
								labels[filter.WorkspaceLocalFolderLabel] = f.alpha
								labels[filter.WorkspaceThrowawayLabel] = f.alpha
							case "empty":
								labels[filter.WorkspaceLocalFolderLabel] = ""
							case "mismatch":
								labels[filter.WorkspaceLocalFolderLabel] = filepath.Join(f.root, "beta")
							}
							mounts := []filter.ForkStartRecheckMount{}
							if !tc.noOwn {
								mounts = append(mounts, filter.ForkStartRecheckMount{Type: "bind", Source: f.alpha})
							}
							if tc.base {
								mounts = append(mounts, filter.ForkStartRecheckMount{Type: "bind", Source: filepath.Join(filepath.Dir(f.root), "base")})
							}
							if tc.extra {
								mounts = append(mounts, filter.ForkStartRecheckMount{Type: "bind", Source: extra})
							}
							if tc.volume {
								mounts = append(mounts, filter.ForkStartRecheckMount{Type: "volume", Name: "data"})
							}
							d.mu.Lock()
							d.inspect = filter.ForkStartRecheckContainer{Config: filter.ForkStartRecheckConfig{Labels: labels}, Mounts: mounts}
							d.volume = filter.ForkStartRecheckVolume{Driver: "local", Options: map[string]string{"type": "none", "o": "bind", "device": extra}}
							d.writes = nil
							d.bodies = nil
							d.reads = nil
							inspectJSON, _ := json.Marshal(d.inspect)
							d.mu.Unlock()
							r := httptest.NewRequest("POST", route, nil)
							if tc.header != "missing" {
								key := filter.WorkspaceHeader
								if tc.header == "throwaway" {
									key = filter.WorkspaceThrowawayHeader
								}
								r.Header.Set(key, f.alpha)
								switch tc.header {
								case "repeated":
									r.Header.Add(key, f.alpha)
								case "empty":
									r.Header.Set(key, "")
								case "invalid":
									r.Header.Set(key, f.alpha+"/../alpha")
								}
								if tc.header == "both" {
									r.Header.Set(filter.WorkspaceThrowawayHeader, f.alpha)
								}
							}
							w := httptest.NewRecorder()
							h.ServeHTTP(w, r)
							d.mu.Lock()
							defer d.mu.Unlock()
							t.Logf("RESULT expected=%d actual=%d writes=%v reads=%v inspected=%s volume-device=%s response=%s", tc.want, w.Code, d.writes, d.reads, inspectJSON, extra, w.Body.String())
							if w.Code != tc.want {
								t.Errorf("GRANT_ELIGIBILITY_STATUS: got %d want %d", w.Code, tc.want)
							}
							if tc.want == 403 && len(d.writes) != 0 {
								t.Errorf("DENIED_WRITE_REACHED_DAEMON: %v", d.writes)
							}
							if w.Code == 204 {
								if len(d.writes) != 1 {
									t.Errorf("expected exactly one forwarded write: %v", d.writes)
								}
								if !slices.Contains(d.reads, "GET /containers/c1/json") {
									t.Error("INSPECT_NOT_REACHED")
								}
								if tc.volume && !strings.Contains(strings.Join(d.reads, " "), "/volumes/data") {
									t.Error("VOLUME_INSPECT_NOT_REACHED")
								}
							}
						})
					}
				})
			}
		})
	}
}

// Native libpod create has no exception path. These rows prove route denial,
// not grant eligibility, and are excluded from the defect count.
func TestPrimaryGrantLibpodCreateRouteControl(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			extra := filepath.Join(filepath.Dir(f.root), "extra")
			if err := os.Mkdir(extra, 0755); err != nil {
				t.Fatal(err)
			}
			primaryGrantPolicy(t, f, extra, true)
			d := &primaryGrantDaemon{}
			h, _ := primaryGrantChain(t, f, named, d)
			for _, route := range []string{"/libpod/containers/create", "/v5.0.0/libpod/containers/create"} {
				t.Run(route, func(t *testing.T) {
					r := httptest.NewRequest("POST", route, strings.NewReader(f.createBody(f.alpha)))
					r.Header.Set(filter.WorkspaceHeader, f.alpha)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					d.mu.Lock()
					defer d.mu.Unlock()
					t.Logf("ROUTE_CONTROL expected=403 actual=%d writes=%v response=%s", w.Code, d.writes, w.Body.String())
					if w.Code != 403 || len(d.writes) != 0 {
						t.Errorf("NATIVE_LIBPOD_ROUTE_DENIAL: status=%d writes=%v", w.Code, d.writes)
					}
				})
			}
		})
	}
}

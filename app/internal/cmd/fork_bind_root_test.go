// ---
// relationships:
//   references: fork_bind_root.go
// ---

package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/testhelp"
)

// Every filesystem input belongs to this fixture; no host bind root is assumed.
func bindRootConfig(t *testing.T, feature bool) *config.Config {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testServeConfig()
	cfg.Upstream.Socket = filepath.Join(base, "daemon.sock")
	cfg.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"}}
	cfg.Reload.Enabled = false
	cfg.Response.DenyVerbosity = "verbose"
	if feature {
		root := filepath.Join(base, "workspace")
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
		cfg.WorkspaceExceptions = config.WorkspaceExceptionsConfig{File: filepath.Join(base, "exceptions.json"), WorkspaceRoot: root}
	}
	return cfg
}

// Run the actual startup path through validation, store, chain and a bound
// HTTP server. Success means that /probe was served by the composed policy.
func runBindRootStartup(t *testing.T, cfg *config.Config) (*testhelp.CollectingHandler, bool, error) {
	t.Helper()
	deps := newServeTestDeps()
	logs := &testhelp.CollectingHandler{}
	deps.loadConfig = func(string) (*config.Config, error) { return cfg, nil }
	deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) { return logs.Logger(), nil, nil }
	deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
	var address string
	deps.createServeListener = func(*config.Config) (net.Listener, error) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			address = ln.Addr().String()
		}
		return ln, err
	}
	served := false
	deps.notifySignals = func(ch chan<- os.Signal, _ ...os.Signal) {
		// This reuses the suite's 5s client bound. It is not a product timeout.
		response, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + address + "/probe")
		if err != nil {
			t.Errorf("startup request: %v", err)
		} else {
			served = response.StatusCode == http.StatusForbidden
			_ = response.Body.Close()
		}
		ch <- syscall.SIGTERM
	}
	cmd := newServeCommand()
	cmd.SetErr(io.Discard)
	err := runServeWithDeps(cmd, nil, deps)
	return logs, served, err
}

func requireBindRootWarning(t *testing.T, logs *testhelp.CollectingHandler, path, block string) {
	t.Helper()
	count := 0
	for _, record := range logs.FindMessage("bind root visibility check failed") {
		if record.Attrs["path"] != path || record.Attrs["block"] != block {
			continue
		}
		count++
		text := fmt.Sprint(record.Attrs["error"])
		if record.Level != slog.LevelWarn || !strings.Contains(text, "does not exist") || !strings.Contains(text, path) || !strings.Contains(text, "mount it read-only at the same path") {
			t.Errorf("warning severity/path/remedy: %+v", record)
		}
	}
	if count != 1 {
		t.Fatalf("want one warning per entry/block, got %d for %s %s: %+v", count, block, path, logs.Records())
	}
}

func TestBindRootsStartupMissingWarningPerBlock(t *testing.T) {
	cfg := bindRootConfig(t, false)
	missing := filepath.Join(t.TempDir(), "missing")
	second := filepath.Join(t.TempDir(), "second")
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{missing, second}
	cfg.RequestBody.LibpodContainerCreate.AllowedBindMounts = []string{missing, second}
	profile := config.ClientProfileConfig{Name: "sample", Rules: cfg.Rules}
	profile.RequestBody = cfg.RequestBody
	cfg.Clients.Profiles = []config.ClientProfileConfig{profile}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served {
		t.Fatalf("warning prevented startup: %v served=%v", err, served)
	}
	for _, block := range []string{"base.request_body.container_create", "base.request_body.libpod_container_create", `profile "sample".request_body.container_create`, `profile "sample".request_body.libpod_container_create`} {
		requireBindRootWarning(t, logs, missing, block)
		requireBindRootWarning(t, logs, second, block)
	}
	if got := len(logs.FindMessage("bind root visibility check failed")); got != 8 {
		t.Fatalf("warning count=%d want 8", got)
	}
}

func TestBindRootsStartupExistingDirectoryAndFile(t *testing.T) {
	cfg := bindRootConfig(t, true)
	dir := t.TempDir()
	file := filepath.Join(dir, "socket-entry")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{dir, file}
	cfg.RequestBody.LibpodContainerCreate.AllowedBindMounts = []string{dir, file}
	profile := config.ClientProfileConfig{Name: "sample", Rules: cfg.Rules, RequestBody: cfg.RequestBody}
	cfg.Clients.Profiles = []config.ClientProfileConfig{profile}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served {
		t.Fatalf("existing roots rejected: %v served=%v", err, served)
	}
	if records := logs.FindMessage("bind root visibility check failed"); len(records) != 0 {
		t.Fatalf("existing entries logged: %+v", records)
	}
}

func strictBindStartup(t *testing.T, profile bool) {
	t.Helper()
	cfg := bindRootConfig(t, true)
	missing := filepath.Join(t.TempDir(), "missing")
	body := cfg.RequestBody
	body.ContainerCreate.ApplyWorkspaceExceptions = true
	body.ContainerCreate.AllowedBindMounts = []string{missing}
	block := "base.request_body.container_create"
	if profile {
		cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "sample", Rules: cfg.Rules, RequestBody: body}}
		block = `profile "sample".request_body.container_create`
	} else {
		cfg.RequestBody = body
	}
	logs, served, err := runBindRootStartup(t, cfg)
	if err == nil || served {
		t.Fatalf("missing strict root admitted: err=%v served=%v", err, served)
	}
	for _, part := range []string{missing, block, "does not exist", "mount it read-only at the same path"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("missing diagnostic %q: %v", part, err)
		}
	}
	records := logs.FindMessage("bind root visibility check failed")
	if len(records) != 1 || records[0].Level != slog.LevelError {
		t.Fatalf("strict severity/count: %+v", records)
	}
}
func TestBindRootsStartupStrictBase(t *testing.T)    { strictBindStartup(t, false) }
func TestBindRootsStartupStrictProfile(t *testing.T) { strictBindStartup(t, true) }

func TestBindRootsStartupWarningOnlyProfile(t *testing.T) {
	cfg := bindRootConfig(t, true)
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{cfg.WorkspaceExceptions.WorkspaceRoot}
	missing := filepath.Join(t.TempDir(), "missing")
	profile := config.ClientProfileConfig{Name: "sample", Rules: cfg.Rules}
	profile.RequestBody.ContainerCreate.AllowedBindMounts = []string{missing}
	cfg.Clients.Profiles = []config.ClientProfileConfig{profile}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served {
		t.Fatalf("non-opt-in profile narrowed: %v served=%v", err, served)
	}
	requireBindRootWarning(t, logs, missing, `profile "sample".request_body.container_create`)
}

func TestBindRootsStartupLibpodStaysWarningWithStrictDocker(t *testing.T) {
	cfg := bindRootConfig(t, true)
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	missing := filepath.Join(t.TempDir(), "missing")
	cfg.RequestBody.LibpodContainerCreate.AllowedBindMounts = []string{missing}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served {
		t.Fatalf("libpod warning promoted: %v served=%v", err, served)
	}
	requireBindRootWarning(t, logs, missing, "base.request_body.libpod_container_create")
}

func TestBindRootsStartupMissingWorkspaceRoot(t *testing.T) {
	workspaceRootStartupFailure(t, false, false)
}
func TestBindRootsStartupNonDirectoryWorkspaceRoot(t *testing.T) {
	workspaceRootStartupFailure(t, true, false)
}
func TestBindRootsStartupMissingPerWorkspaceRoot(t *testing.T) {
	workspaceRootStartupFailure(t, false, true)
}
func TestBindRootsStartupNonDirectoryPerWorkspaceRoot(t *testing.T) {
	workspaceRootStartupFailure(t, true, true)
}
func workspaceRootStartupFailure(t *testing.T, file, perRoot bool) {
	t.Helper()
	cfg := bindRootConfig(t, true)
	bad := filepath.Join(t.TempDir(), "bad")
	text := "does not exist"
	if file {
		if err := os.WriteFile(bad, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		text = "not a directory"
	}
	if perRoot {
		cfg.WorkspaceExceptions.PerWorkspaceRoots = []string{cfg.WorkspaceExceptions.WorkspaceRoot, bad}
	} else {
		cfg.WorkspaceExceptions.WorkspaceRoot = bad
	}
	logs, served, err := runBindRootStartup(t, cfg)
	if err == nil || served {
		t.Fatalf("invalid directory admitted: err=%v served=%v", err, served)
	}
	for _, part := range []string{bad, text, "mount it read-only at the same path"} {
		if !strings.Contains(err.Error(), part) {
			t.Errorf("missing diagnostic %q: %v", part, err)
		}
	}
	records := logs.FindMessage("workspace root validation failed")
	if len(records) != 1 || records[0].Level != slog.LevelError {
		t.Fatalf("root severity/count: %+v", records)
	}
}

func TestBindRootsStartupFeatureOff(t *testing.T) {
	logs, served, err := runBindRootStartup(t, bindRootConfig(t, false))
	if err != nil || !served || logs.HasMessage("workspace root validation failed") {
		t.Fatalf("feature off: %v served=%v logs=%+v", err, served, logs.Records())
	}
}

func TestBindRootsStartupPermissionSeverity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses search permissions")
	}
	cfg := bindRootConfig(t, true)
	parent := t.TempDir()
	inaccessible := filepath.Join(parent, "hidden")
	if err := os.WriteFile(inaccessible, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	for _, strict := range []bool{false, true} {
		cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = strict
		cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{inaccessible}
		logs, served, err := runBindRootStartup(t, cfg)
		if strict != (err != nil) || strict == served {
			t.Fatalf("permission severity strict=%v err=%v served=%v", strict, err, served)
		}
		records := logs.FindMessage("bind root visibility check failed")
		want := slog.LevelWarn
		if strict {
			want = slog.LevelError
		}
		if len(records) != 1 || records[0].Level != want {
			t.Fatalf("permission severity: %+v", records)
		}
		text := fmt.Sprint(records[0].Attrs["error"])
		if !strings.Contains(text, "permission denied in the proxy mount namespace") || strings.Contains(text, "does not exist") || !strings.Contains(text, inaccessible) || !strings.Contains(text, "mount it read-only at the same path") {
			t.Fatalf("permission diagnostic: %s", text)
		}
	}
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = nil
	cfg.WorkspaceExceptions.WorkspaceRoot = inaccessible
	_, served, err := runBindRootStartup(t, cfg)
	if err == nil || served || !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "permission denied in the proxy mount namespace") || !strings.Contains(err.Error(), "mount it read-only at the same path") {
		t.Fatalf("workspace permission diagnostic: %v served=%v", err, served)
	}
}

// Use real validation and chain builds through the production coordinator.
// First establish a running generation. After rejection, inspect both that
// generation and HTTP behavior, then restore the root and prove apply works.
func TestBindRootsReloadPreservesRunningGeneration(t *testing.T) {
	for _, guard := range []string{"base", "profile", "workspace", "per-workspace", "workspace-file", "per-workspace-file", "workspace-symlink", "per-workspace-symlink"} {
		t.Run(guard, func(t *testing.T) {
			initial := bindRootConfig(t, true)
			root := initial.WorkspaceExceptions.WorkspaceRoot
			extra := filepath.Join(t.TempDir(), "extra")
			if err := os.Mkdir(extra, 0o755); err != nil {
				t.Fatal(err)
			}
			initial.WorkspaceExceptions.PerWorkspaceRoots = []string{root, extra}
			bindOnly := filepath.Join(t.TempDir(), "bind-only")
			if err := os.Mkdir(bindOnly, 0o755); err != nil {
				t.Fatal(err)
			}
			body := initial.RequestBody
			body.ContainerCreate.ApplyWorkspaceExceptions = true
			body.ContainerCreate.AllowedBindMounts = []string{root, extra, bindOnly}
			switch guard {
			case "profile":
				initial.Clients.Profiles = []config.ClientProfileConfig{{Name: "sample", Rules: initial.Rules, RequestBody: body}}
			case "base":
				initial.RequestBody = body
			}
			f := newReloadCoordinatorFixture(t, initial)
			t.Cleanup(f.coordinator.stop)
			f.coordinator.deps.validateRules = validateAndCompileRules
			if err := f.coordinator.runtime.loadWorkspaceExceptions(initial, newDiscardLogger()); err != nil {
				t.Fatal(err)
			}
			f.coordinator.reload()
			if count, ok := f.reloadCount("ok"); !ok || count != 1 {
				t.Fatalf("positive control apply: %s", f.logBuf.String())
			}
			active := f.coordinator.activeCfg
			version := f.versioner.Snapshot()
			var originalBody string
			assertHTTP := func() {
				t.Helper()
				rec := httptest.NewRecorder()
				f.swappable.ServeHTTP(rec, httptest.NewRequest("GET", "/probe", nil))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("running handler lost: %d %s", rec.Code, rec.Body.String())
				}
				if originalBody == "" {
					originalBody = rec.Body.String()
				} else if rec.Body.String() != originalBody {
					t.Fatalf("rejected reload changed HTTP policy: %s", rec.Body.String())
				}
			}
			assertHTTP()
			candidate := *initial
			candidate.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "replacement generation"}}
			f.loadCfg = &candidate
			missing := extra
			if guard == "base" || guard == "profile" {
				missing = bindOnly
			}
			if strings.HasPrefix(guard, "workspace") {
				missing = root
			}
			if err := os.Remove(missing); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(guard, "-file") {
				if err := os.WriteFile(missing, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			} else if strings.HasSuffix(guard, "symlink") {
				if err := os.Symlink(t.TempDir(), missing); err != nil {
					t.Fatal(err)
				}
			}
			f.coordinator.reload()
			if count, ok := f.reloadCount("reject_validation"); !ok || count != 1 {
				t.Fatalf("reload guard not reached: %s", f.logBuf.String())
			}
			if f.coordinator.activeCfg != active || f.versioner.Snapshot() != version {
				t.Fatal("rejected reload replaced running generation")
			}
			assertHTTP()
			if !strings.Contains(f.logBuf.String(), missing) || (!strings.HasSuffix(guard, "symlink") && !strings.Contains(f.logBuf.String(), "mount it read-only at the same path")) || !strings.Contains(f.logBuf.String(), "level=ERROR") {
				t.Fatalf("reload diagnostic missing: %s", f.logBuf.String())
			}
			if strings.HasSuffix(guard, "-file") || strings.HasSuffix(guard, "symlink") {
				if err := os.Remove(missing); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(missing, 0o755); err != nil {
				t.Fatal(err)
			}
			f.coordinator.reload()
			if f.coordinator.activeCfg != &candidate || f.versioner.Snapshot().Version != version.Version+1 {
				t.Fatalf("restored root did not apply: %s", f.logBuf.String())
			}
			rec := httptest.NewRecorder()
			f.swappable.ServeHTTP(rec, httptest.NewRequest("GET", "/probe", nil))
			if !strings.Contains(rec.Body.String(), "replacement generation") {
				t.Fatalf("replacement handler not served: %s", rec.Body.String())
			}
		})
	}
}

func TestBindRootsReloadWarningOnlyAndFeatureOff(t *testing.T) {
	initial := bindRootConfig(t, false)
	f := newReloadCoordinatorFixture(t, initial)
	t.Cleanup(f.coordinator.stop)
	f.coordinator.deps.validateRules = validateAndCompileRules
	candidate := *initial
	missing := filepath.Join(t.TempDir(), "missing")
	profile := config.ClientProfileConfig{Name: "sample", Rules: initial.Rules}
	profile.RequestBody.ContainerCreate.AllowedBindMounts = []string{missing}
	profile.RequestBody.LibpodContainerCreate.AllowedBindMounts = []string{missing}
	candidate.Clients.Profiles = []config.ClientProfileConfig{profile}
	f.loadCfg = &candidate
	f.coordinator.reload()
	if f.coordinator.activeCfg != &candidate || f.versioner.Snapshot() == nil {
		t.Fatalf("warning reload rejected: %s", f.logBuf.String())
	}
	if strings.Count(f.logBuf.String(), "bind root visibility check failed") != 2 || strings.Contains(f.logBuf.String(), "level=ERROR") {
		t.Fatalf("warning reload diagnostic: %s", f.logBuf.String())
	}
	rec := httptest.NewRecorder()
	f.swappable.ServeHTTP(rec, httptest.NewRequest("GET", "/probe", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("warning-only handler not served: %d", rec.Code)
	}
	t.Cleanup(f.coordinator.stop)
}

func TestBindRootsStartupReusesWorkspaceSocketAndComposeRoots(t *testing.T) {
	cfg := bindRootConfig(t, true)
	roots := []string{cfg.WorkspaceExceptions.WorkspaceRoot, filepath.Join(t.TempDir(), "workspace-sockets"), filepath.Join(t.TempDir(), "compose-staging")}
	for _, root := range roots[1:] {
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg.WorkspaceExceptions.PerWorkspaceRoots = roots
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = roots
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served || logs.HasMessage("bind root visibility check failed") {
		t.Fatalf("valid shared roots rejected: %v served=%v", err, served)
	}
	for _, root := range roots {
		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
		_, served, err = runBindRootStartup(t, cfg)
		if err == nil || served || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), "mount it read-only at the same path") {
			t.Fatalf("missing shared root admitted: %v served=%v", err, served)
		}
		if err := os.Mkdir(root, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBindRootsStartupOtherLookupErrorIsNotMissing(t *testing.T) {
	cfg := bindRootConfig(t, false)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{filepath.Join(file, "child")}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served {
		t.Fatalf("non-opt-in lookup error restricted: %v served=%v", err, served)
	}
	records := logs.FindMessage("bind root visibility check failed")
	if len(records) != 1 {
		t.Fatalf("lookup error diagnostics: %+v", records)
	}
	text := fmt.Sprint(records[0].Attrs["error"])
	if !strings.Contains(text, "cannot be inspected") || strings.Contains(text, "does not exist") || strings.Contains(text, "permission denied") {
		t.Fatalf("misclassified lookup error: %s", text)
	}
}

func TestBindRootsStartupServiceAndPluginExcluded(t *testing.T) {
	cfg := bindRootConfig(t, false)
	missing := filepath.Join(t.TempDir(), "missing")
	cfg.RequestBody.Service.AllowedBindMounts = []string{missing}
	cfg.RequestBody.Plugin.AllowedBindMounts = []string{missing}
	profile := config.ClientProfileConfig{Name: "sample", Rules: cfg.Rules, RequestBody: cfg.RequestBody}
	cfg.Clients.Profiles = []config.ClientProfileConfig{profile}
	logs, served, err := runBindRootStartup(t, cfg)
	if err != nil || !served || logs.HasMessage("bind root visibility check failed") {
		t.Fatalf("out-of-scope roots checked: %v served=%v records=%+v", err, served, logs.Records())
	}
}

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

type serveWorkspaceFixture struct {
	root  string
	alpha string
	file  string
}

func newServeWorkspaceFixture(t *testing.T) serveWorkspaceFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := serveWorkspaceFixture{root: filepath.Join(base, "root"), file: filepath.Join(base, "policy", "workspace-exceptions.json")}
	f.alpha = filepath.Join(f.root, "alpha")
	for _, dir := range []string{f.alpha, filepath.Dir(f.file)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f serveWorkspaceFixture) write(t *testing.T, privileged bool) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"version": 1, "exceptions": []any{map[string]any{
		"workspace": f.alpha,
		"grants":    map[string]any{"privileged": privileged},
		"approval":  map[string]any{"by": map[string]any{"issuer": "https://id.example.org", "subject": "user-0001"}, "at": "2026-01-02T03:04:05Z"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tmp := f.file + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, f.file); err != nil {
		t.Fatal(err)
	}
}

func (f serveWorkspaceFixture) config(socketPath string) config.Config {
	cfg := config.Defaults()
	cfg.Health.Enabled = false
	cfg.Log.AccessLog = false
	cfg.Upstream.Socket = socketPath
	cfg.WorkspaceExceptions = config.WorkspaceExceptionsConfig{File: f.file, WorkspaceRoot: f.root}
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{f.root}
	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	return cfg
}

func (f serveWorkspaceFixture) createBody(ws string) string {
	return `{"Image":"busybox","Labels":{"devcontainer.local_folder":"` + ws + `"},"HostConfig":{"Privileged":true,"Binds":["` + ws + `:/workspaces/project"]}}`
}

func TestLoadWorkspaceExceptions(t *testing.T) {
	f := newServeWorkspaceFixture(t)
	cfg := f.config("/nonexistent.sock")
	runtime := &serveRuntime{}
	off := config.Defaults()
	if err := runtime.loadWorkspaceExceptions(&off, newDiscardLogger()); err != nil || runtime.workspaceExceptions != nil {
		t.Fatalf("disabled: err %v store %v", err, runtime.workspaceExceptions)
	}
	if runtimeWorkspaceExceptions(nil) != nil {
		t.Fatal("nil runtime has no store")
	}
	link := filepath.Join(filepath.Dir(f.root), "rootlink")
	if err := os.Symlink(f.root, link); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.WorkspaceExceptions.WorkspaceRoot = link
	if err := runtime.loadWorkspaceExceptions(&bad, newDiscardLogger()); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("symlinked root: err %v, want not canonical", err)
	}
	badRoots := cfg
	badRoots.WorkspaceExceptions.PerWorkspaceRoots = []string{f.root, link}
	if err := runtime.loadWorkspaceExceptions(&badRoots, newDiscardLogger()); err == nil || !strings.Contains(err.Error(), "per-workspace root") {
		t.Fatalf("symlinked per-workspace root: err %v, want refused", err)
	}
	if err := runtime.loadWorkspaceExceptions(&cfg, newDiscardLogger()); err != nil || runtime.workspaceExceptions == nil {
		t.Fatalf("missing file must start with no exceptions: err %v", err)
	}
	if got := runtime.workspaceExceptions.Load().State(); got != filter.WorkspaceExceptionsMissing {
		t.Fatalf("state %q, want missing", got)
	}
}

func TestAttachWorkspaceExceptionsReachesDefaultAndProfiles(t *testing.T) {
	f := newServeWorkspaceFixture(t)
	store, err := filter.NewWorkspaceExceptionStore(filter.WorkspaceExceptionStoreOptions{Path: f.file, WorkspaceRoot: f.root, MaxBytes: 1 << 20, Logger: newDiscardLogger()})
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]filter.Policy{"sample": {}}
	opts := attachWorkspaceExceptions(filter.Options{Profiles: profiles}, store)
	if opts.ContainerCreate.WorkspaceExceptions != store || opts.Profiles["sample"].ContainerCreate.WorkspaceExceptions != store {
		t.Fatal("store not attached to the default policy and every profile")
	}
	if profiles["sample"].ContainerCreate.WorkspaceExceptions != nil {
		t.Fatal("the caller's profile map must not be modified")
	}
	// Only a block that applies exceptions gets the start re-check scope.
	if opts.ForkStartRecheck.Workspace != nil || opts.Profiles["sample"].ForkStartRecheck.Workspace != nil {
		t.Fatal("a block without apply_workspace_exceptions must not get the start re-check scope")
	}
	applied := filter.Options{Profiles: map[string]filter.Policy{"menagerie": {}}}
	applied.ContainerCreate.ApplyWorkspaceExceptions = true
	menagerie := applied.Profiles["menagerie"]
	menagerie.ContainerCreate.ApplyWorkspaceExceptions = true
	applied.Profiles["menagerie"] = menagerie
	applied = attachWorkspaceExceptions(applied, store)
	if applied.ForkStartRecheck.Workspace == nil || applied.Profiles["menagerie"].ForkStartRecheck.Workspace == nil {
		t.Fatal("a block with apply_workspace_exceptions must get the start re-check scope")
	}
	if got := attachWorkspaceExceptions(filter.Options{Profiles: profiles}, nil); got.ContainerCreate.WorkspaceExceptions != nil {
		t.Fatal("a nil store attaches nothing")
	}
}

// The handler chain gives the store to the default block and to a client
// profile, and the file watcher swaps it on replace and removal.
func TestServeChainAppliesWorkspaceExceptions(t *testing.T) {
	f := newServeWorkspaceFixture(t)
	f.write(t, true)
	socketPath := shortSocketPath(t, "ws-exc")
	_ = os.Remove(socketPath)
	startUnixHTTPUpstream(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))
	gamma := filepath.Join(f.root, "gamma")
	if err := os.MkdirAll(gamma, 0o755); err != nil {
		t.Fatal(err)
	}

	for name, edit := range map[string]func(*config.Config){
		"default block": func(c *config.Config) { c.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true },
		"client profile": func(c *config.Config) {
			profile := config.ClientProfileConfig{Name: "sample", Rules: c.Rules}
			profile.RequestBody.ContainerCreate.AllowedBindMounts = []string{f.root}
			profile.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
			c.Clients.Profiles = []config.ClientProfileConfig{profile}
			c.Clients.DefaultProfile = "sample"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f.write(t, true)
			cfg := f.config(socketPath)
			edit(&cfg)
			if err := config.Validate(&cfg); err != nil {
				t.Fatalf("Validate: %v", err)
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
			post := func(ws string) int {
				rec := httptest.NewRecorder()
				r := httptest.NewRequest(http.MethodPost, "/v1.51/containers/create", strings.NewReader(f.createBody(ws)))
				r.Header.Set(filter.WorkspaceHeader, ws)
				handler.ServeHTTP(rec, r)
				return rec.Code
			}
			if code := post(f.alpha); code != http.StatusCreated {
				t.Fatalf("matched create: status %d, want 201", code)
			}
			if code := post(gamma); code != http.StatusForbidden {
				t.Fatalf("unmatched create: status %d, want 403", code)
			}
			// Scoping: alpha's label may not bind gamma's folder.
			rec := httptest.NewRecorder()
			crossBody := `{"Image":"busybox","Labels":{"devcontainer.local_folder":"` + f.alpha + `"},"HostConfig":{"Binds":["` + f.alpha + `:/w","` + gamma + `:/other"]}}`
			cross := httptest.NewRequest(http.MethodPost, "/v1.51/containers/create", strings.NewReader(crossBody))
			cross.Header.Set(filter.WorkspaceHeader, f.alpha)
			handler.ServeHTTP(rec, cross)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("cross-workspace bind: status %d, want 403", rec.Code)
			}
			// A create and a start without the workspace header are denied
			// before the daemon is read.
			for _, path := range []string{"/v1.51/containers/create", "/v1.51/containers/sample/start"} {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(f.createBody(f.alpha))))
				if rec.Code != http.StatusForbidden {
					t.Fatalf("%s without a workspace header: status %d, want 403", path, rec.Code)
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			stop := runtime.watchWorkspaceExceptions(ctx, &cfg, newDiscardLogger())
			defer func() { cancel(); stop() }()
			waitForWorkspaceExceptions := func(what string, ok func(*filter.WorkspaceExceptionSnapshot) bool) {
				t.Helper()
				// The watcher reloads after the 250ms default debounce; 5s
				// covers a loaded shared host.
				deadline := time.Now().Add(5 * time.Second)
				for !ok(runtime.workspaceExceptions.Load()) {
					if time.Now().After(deadline) {
						t.Fatalf("watcher did not reload: %s", what)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			// The watch starts asynchronously. A replace made before it is in
			// place is missed, so the replace is repeated once a second: more
			// often would keep re-arming the debounce.
			deadline := time.Now().Add(5 * time.Second)
			for revoked := false; !revoked; {
				if time.Now().After(deadline) {
					t.Fatal("revocation by atomic replace was not picked up")
				}
				f.write(t, false)
				for wait := time.Now().Add(time.Second); time.Now().Before(wait); time.Sleep(10 * time.Millisecond) {
					if revoked = post(f.alpha) == http.StatusForbidden; revoked {
						break
					}
				}
			}
			if err := os.Remove(f.file); err != nil {
				t.Fatal(err)
			}
			waitForWorkspaceExceptions("removal", func(s *filter.WorkspaceExceptionSnapshot) bool {
				return s.State() == filter.WorkspaceExceptionsMissing
			})
		})
	}
}

// A replace between the startup load and the start of the watch is picked
// up once the watch starts, with no further event.
func TestWatchWorkspaceExceptionsReloadsOnStart(t *testing.T) {
	f := newServeWorkspaceFixture(t)
	cfg := f.config("/nonexistent.sock")
	runtime := &serveRuntime{}
	if err := runtime.loadWorkspaceExceptions(&cfg, newDiscardLogger()); err != nil {
		t.Fatal(err)
	}
	f.write(t, true)
	if got := runtime.workspaceExceptions.Load().State(); got != filter.WorkspaceExceptionsMissing {
		t.Fatalf("store reloaded before the watch started: %q", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := runtime.watchWorkspaceExceptions(ctx, &cfg, newDiscardLogger())
	defer func() { cancel(); stop() }()
	// Debounce is 250ms by default; 5s covers a loaded shared host.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.workspaceExceptions.Load().State() != filter.WorkspaceExceptionsLoaded {
		if time.Now().After(deadline) {
			t.Fatal("the file written before the watch started was not loaded")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stopNil := (*serveRuntime)(nil).watchWorkspaceExceptions(ctx, &cfg, newDiscardLogger()); stopNil == nil {
		t.Fatal("nil runtime must return a stop func")
	}
}

// runServeWithDeps loads the store before serving and fails start-up on a
// root that is not canonical, and it starts the file watcher.
func TestRunServeWorkspaceExceptionsStartup(t *testing.T) {
	f := newServeWorkspaceFixture(t)
	newDeps := func(edit func(*config.Config), logs *syncBuffer) *serveDeps {
		deps := newServeTestDeps()
		deps.loadConfig = func(string) (*config.Config, error) {
			cfg := testServeConfig()
			cfg.Listen.Socket = "/tmp/sockguard-test.sock"
			cfg.Listen.Address = ""
			cfg.WorkspaceExceptions = config.WorkspaceExceptionsConfig{File: f.file, WorkspaceRoot: f.root}
			if edit != nil {
				edit(cfg)
			}
			return cfg, nil
		}
		deps.newLogger = func(string, string, string) (*slog.Logger, io.Closer, error) {
			return slog.New(slog.NewTextHandler(logs, nil)), nil, nil
		}
		deps.validateRules = func(*config.Config) ([]*filter.CompiledRule, error) { return stubCompiledRules(), nil }
		deps.dialUpstream = func(string, string, time.Duration) (net.Conn, error) { return &serveTestConn{}, nil }
		deps.createServeListener = func(*config.Config) (net.Listener, error) { return &serveTestListener{}, nil }
		deps.notifySignals = func(chan<- os.Signal, ...os.Signal) {}
		deps.shutdownServer = func(*http.Server, context.Context) error { return nil }
		deps.removePath = func(string) error { return nil }
		return deps
	}

	t.Run("root not canonical", func(t *testing.T) {
		link := filepath.Join(filepath.Dir(f.root), "startup-rootlink")
		if err := os.Symlink(f.root, link); err != nil {
			t.Fatal(err)
		}
		deps := newDeps(func(c *config.Config) { c.WorkspaceExceptions.WorkspaceRoot = link }, &syncBuffer{})
		// Serving ends the run at once, so a start-up that does not refuse
		// the root fails this test instead of hanging it.
		deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) { errCh <- errors.New("served") }
		err := runServeWithDeps(newServeCommand(), nil, deps)
		if err == nil || !strings.Contains(err.Error(), "workspace exceptions:") || !strings.Contains(err.Error(), "not canonical") {
			t.Fatalf("runServeWithDeps() = %v, want a workspace exceptions start-up error", err)
		}
	})

	t.Run("watcher started", func(t *testing.T) {
		f.write(t, true)
		logs := &syncBuffer{}
		deps := newDeps(nil, logs)
		deps.startServing = func(_ *http.Server, _ net.Listener, errCh chan<- error) {
			go func() {
				// The start-up load logs once; the watcher's first reload
				// logs again. 5s bounds a loaded shared host.
				deadline := time.Now().Add(5 * time.Second)
				for strings.Count(logs.String(), "workspace exceptions loaded") < 2 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				errCh <- errors.New("stop")
			}()
		}
		if err := runServeWithDeps(newServeCommand(), nil, deps); err == nil || !strings.Contains(err.Error(), "stop") {
			t.Fatalf("runServeWithDeps() = %v", err)
		}
		if got := strings.Count(logs.String(), "workspace exceptions loaded"); got < 2 {
			t.Fatalf("watcher did not reload the file after start-up (%d loads logged)", got)
		}
	})
}

// syncBuffer is a bytes.Buffer safe for the logger and the test to share.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

package filter

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/logging"
)

// forkStartRecheckFixture is a temp tree, the container "c1" a mock daemon
// reports, and the filter middleware in front of a recording upstream:
//
//	<root>/ws/                the allowlisted root
//	<root>/ws/proj/           a real directory, the container's bind source
//	<root>/ws/up/             a real directory a ".." spelling walks through
//	<root>/ws/up/inner/       a real directory under a narrower entry
//	<root>/outside/sub/       outside every allowlist entry
type forkStartRecheckFixture struct {
	t       *testing.T
	ws      string
	outside string
	daemon  *forkStartRecheckDaemon
}

func newForkStartRecheckFixture(t *testing.T) *forkStartRecheckFixture {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := &forkStartRecheckFixture{t: t, ws: filepath.Join(root, "ws"), outside: filepath.Join(root, "outside")}
	for _, dir := range []string{filepath.Join(f.ws, "proj"), filepath.Join(f.ws, "up", "inner"), filepath.Join(f.outside, "sub")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.daemon = newForkStartRecheckDaemon(t)
	return f
}

// swap replaces the real directory ws/<name> with a symlink to target, the
// way a writer would after create. name may hold a "/".
func (f *forkStartRecheckFixture) swap(name, target string) {
	f.t.Helper()
	f.swapPath(filepath.Join(f.ws, name), target)
}

// swapPath is swap for any directory.
func (f *forkStartRecheckFixture) swapPath(dir, target string) {
	f.t.Helper()
	if err := os.Rename(dir, dir+".orig"); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		f.t.Fatal(err)
	}
}

// restore undoes swap.
func (f *forkStartRecheckFixture) restore(name string) {
	f.t.Helper()
	dir := filepath.Join(f.ws, name)
	if err := os.Remove(dir); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Rename(dir+".orig", dir); err != nil {
		f.t.Fatal(err)
	}
}

// forkStartRecheckDaemon is a mock daemon. It answers GET /containers/c1/json
// with its current inspect body and records every request it gets.
type forkStartRecheckDaemon struct {
	server *httptest.Server
	mu     sync.Mutex
	status int
	body   string
	seen   []string
}

func newForkStartRecheckDaemon(t *testing.T) *forkStartRecheckDaemon {
	t.Helper()
	d := &forkStartRecheckDaemon{status: http.StatusOK, body: `{}`}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.seen = append(d.seen, r.Method+" "+r.URL.EscapedPath())
		status, body := d.status, d.body
		d.mu.Unlock()
		if r.URL.Path != "/containers/c1/json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(d.server.Close)
	return d
}

func (d *forkStartRecheckDaemon) set(status int, body string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status, d.body = status, body
}

func (d *forkStartRecheckDaemon) inspects() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.seen...)
}

// transport sends every request to the mock daemon whatever its URL host is,
// as the upstream resolver sends it to the daemon socket.
func (d *forkStartRecheckDaemon) transport() http.RoundTripper {
	addr := d.server.Listener.Addr().String()
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
}

// inspectBody is a container inspect body with the given bind sources, set the
// way dockerd reports a create with HostConfig.Binds: the mount point carries
// the cleaned source and HostConfig.Binds the spec as written.
func inspectBody(t *testing.T, mounts []ForkStartRecheckMount, binds []string, hostMounts []ForkStartRecheckMount) string {
	t.Helper()
	return inspectBodyOf(t, ForkStartRecheckContainer{
		HostConfig: ForkStartRecheckHostConfig{Binds: binds, Mounts: hostMounts},
		Mounts:     mounts,
	})
}

func inspectBodyOf(t *testing.T, container ForkStartRecheckContainer) string {
	t.Helper()
	body, err := json.Marshal(container)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func bindMount(source string) ForkStartRecheckMount {
	return ForkStartRecheckMount{Type: "bind", Source: source}
}

type forkStartRecheckResult struct {
	status     int
	reason     string
	reasonCode string
	forwarded  bool
}

// send runs one request through the filter middleware with every path
// allowed by rule, so only the request-body inspectors decide.
func send(t *testing.T, policy PolicyConfig, method, target, body string) forkStartRecheckResult {
	t.Helper()
	return sendLogged(t, slog.New(slog.NewTextHandler(io.Discard, nil)), policy, method, target, body)
}

func sendLogged(t *testing.T, logger *slog.Logger, policy PolicyConfig, method, target, body string) forkStartRecheckResult {
	t.Helper()
	return serveForkStartRecheck(t, logger, policy, httptest.NewRequest(method, target, strings.NewReader(body)))
}

func serveForkStartRecheck(t *testing.T, logger *slog.Logger, policy PolicyConfig, req *http.Request) forkStartRecheckResult {
	t.Helper()
	rule, err := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	policy.DenyResponseVerbosity = DenyResponseVerbosityVerbose
	forwarded := false
	handler := MiddlewareWithOptions([]*CompiledRule{rule}, logger, Options{PolicyConfig: policy})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			forwarded = true
			w.WriteHeader(http.StatusNoContent)
		}))
	meta := &logging.RequestMeta{}
	req = req.WithContext(logging.WithMeta(req.Context(), meta))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var denial struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &denial)
	return forkStartRecheckResult{status: rec.Code, reason: denial.Reason, reasonCode: meta.ReasonCode, forwarded: forwarded}
}

func (f *forkStartRecheckFixture) policy(compat, libpod []string) PolicyConfig {
	return PolicyConfig{
		ContainerCreate:       ContainerCreateOptions{AllowedBindMounts: compat},
		LibpodContainerCreate: LibpodContainerCreateOptions{AllowedBindMounts: libpod},
		ForkStartRecheck:      ForkStartRecheckOptions{InspectContainer: NewForkStartRecheckInspectorWithRoundTripper(f.daemon.transport())},
	}
}

func assertForwarded(t *testing.T, got forkStartRecheckResult) {
	t.Helper()
	if !got.forwarded || got.status != http.StatusNoContent {
		t.Fatalf("got status %d, reason %q, forwarded %v; want forwarded", got.status, got.reason, got.forwarded)
	}
}

func assertDenied(t *testing.T, got forkStartRecheckResult, reasonCode, reason string) {
	t.Helper()
	if got.forwarded || got.status != http.StatusForbidden {
		t.Fatalf("got status %d, reason %q, forwarded %v; want 403 not forwarded", got.status, got.reason, got.forwarded)
	}
	if got.reasonCode != reasonCode {
		t.Errorf("reason code = %q, want %q", got.reasonCode, reasonCode)
	}
	if got.reason != reason {
		t.Errorf("reason = %q, want %q", got.reason, reason)
	}
}

// forkStartRecheckRoutes is every start and restart spelling: Docker with and
// without a version prefix, and the libpod equivalents.
var forkStartRecheckRoutes = []struct{ path, subject string }{
	{"/containers/c1/start", "container start"},
	{"/v1.45/containers/c1/start", "container start"},
	{"/containers/c1/restart", "container restart"},
	{"/v1.45/containers/c1/restart", "container restart"},
	{"/libpod/containers/c1/start", "libpod container start"},
	{"/v5.0.0/libpod/containers/c1/start", "libpod container start"},
	{"/libpod/containers/c1/restart", "libpod container restart"},
	{"/v5.0.0/libpod/containers/c1/restart", "libpod container restart"},
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// forkStartRecheckWorkspaceFixture adds per-workspace folders to the start
// re-check fixture:
//
//	<root>/ws/alpha/proj/   workspace alpha's bind source
//	<root>/ws/beta/proj/    workspace beta's folder
//	<root>/extra/data/sub/  under an extra bind source outside the root
//
// The per-workspace root is <root>/ws, the base allowlist is ws, and
// extra/data is the extra bind source a devcontainer of any workspace gets.
type forkStartRecheckWorkspaceFixture struct {
	*forkStartRecheckFixture
	alpha, beta, extra string
}

func newForkStartRecheckWorkspaceFixture(t *testing.T) *forkStartRecheckWorkspaceFixture {
	t.Helper()
	f := &forkStartRecheckWorkspaceFixture{forkStartRecheckFixture: newForkStartRecheckFixture(t)}
	root := filepath.Dir(f.ws)
	f.alpha, f.beta, f.extra = filepath.Join(f.ws, "alpha"), filepath.Join(f.ws, "beta"), filepath.Join(root, "extra")
	for _, dir := range []string{filepath.Join(f.alpha, "proj"), filepath.Join(f.beta, "proj"), filepath.Join(f.extra, "data", "sub")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// scope stands in for the workspace identity of the exceptions file: a
// workspace is a direct child of the root, and only a devcontainer gets the
// extra bind source.
func (f *forkStartRecheckWorkspaceFixture) scope(w ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error) {
	if path.Dir(w.Path) != f.ws || path.Clean(w.Path) != w.Path {
		return ForkStartRecheckWorkspaceScope{}, errors.New("not a workspace")
	}
	scope := ForkStartRecheckWorkspaceScope{Roots: []string{f.ws}, Folders: []string{w.Path}}
	if !w.Throwaway {
		scope.ExtraBindSources = []string{filepath.Join(f.extra, "data")}
	}
	return scope, nil
}

func (f *forkStartRecheckWorkspaceFixture) policy() PolicyConfig {
	p := f.forkStartRecheckFixture.policy([]string{f.ws}, nil)
	p.ForkStartRecheck.Workspace = f.scope
	return p
}

func sendWorkspace(t *testing.T, policy PolicyConfig, target string, header http.Header) forkStartRecheckResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, target, nil)
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	return serveForkStartRecheck(t, slog.New(slog.NewTextHandler(io.Discard, nil)), policy, req)
}

func devcontainerHeader(w string) http.Header {
	return http.Header{"X-Sockguard-Workspace": {w}}
}

func throwawayHeader(w string) http.Header {
	return http.Header{"X-Sockguard-Throwaway-Workspace": {w}}
}

// containerIn is an inspect body whose bind sources are given and whose
// labels are given as key=value pairs.
func containerIn(t *testing.T, sources []string, labels ...string) string {
	t.Helper()
	mounts := make([]ForkStartRecheckMount, 0, len(sources))
	for _, source := range sources {
		mounts = append(mounts, bindMount(source))
	}
	body := ForkStartRecheckContainer{Mounts: mounts, Config: ForkStartRecheckConfig{Labels: map[string]string{}}}
	for _, label := range labels {
		key, value, _ := strings.Cut(label, "=")
		body.Config.Labels[key] = value
	}
	return inspectBodyOf(t, body)
}

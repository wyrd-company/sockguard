package filter

import (
	"context"
	"encoding/json"
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
	dir := filepath.Join(f.ws, name)
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
	body, err := json.Marshal(ForkStartRecheckContainer{
		HostConfig: ForkStartRecheckHostConfig{Binds: binds, Mounts: hostMounts},
		Mounts:     mounts,
	})
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
	req := httptest.NewRequest(method, target, strings.NewReader(body))
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

// TestForkStartRecheckSwapAfterCreateIsDenied creates a container through the
// create check, then replaces its bind source with a symlink out of the
// allowlist. Every start and restart spelling is denied with the start
// reason and never reaches the daemon; the unchanged source and the restored
// source both start.
func TestForkStartRecheckSwapAfterCreateIsDenied(t *testing.T) {
	for _, route := range forkStartRecheckRoutes {
		t.Run(route.path, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			proj := filepath.Join(f.ws, "proj")
			policy := f.policy([]string{f.ws}, []string{f.ws})
			f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{bindMount(proj)}, []string{proj + ":/work"}, nil))

			assertForwarded(t, send(t, policy, http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Binds":["`+proj+`:/work"]}}`))
			assertForwarded(t, send(t, policy, http.MethodPost, route.path, ""))

			f.swap("proj", f.outside)
			assertDenied(t, send(t, policy, http.MethodPost, route.path, ""), "container_start_bind_source_denied",
				route.subject+` denied: bind mount source "`+proj+`" resolves to "`+f.outside+`", which is not allowlisted`)

			f.restore("proj")
			assertForwarded(t, send(t, policy, http.MethodPost, route.path, ""))
			if got := len(f.daemon.inspects()); got != 3 {
				t.Errorf("daemon saw %d inspects, want 3: %q", got, f.daemon.inspects())
			}
		})
	}
}

// TestForkStartRecheckReadsEveryBindSourceField proves each inspect field is
// read: a source that only one field carries is resolved, and a swap under it
// is denied.
func TestForkStartRecheckReadsEveryBindSourceField(t *testing.T) {
	tests := []struct {
		name       string
		body       func(f *forkStartRecheckFixture) string
		wantReason func(f *forkStartRecheckFixture) string
	}{
		{
			name: "mount point source",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, nil, nil)
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + filepath.Join(f.ws, "proj") + `" resolves to "` + f.outside + `", which is not allowlisted`
			},
		},
		{
			// The mount point holds the cleaned ws/proj, which is unchanged.
			// The spec as written walks through the swapped ws/up.
			name: "HostConfig.Binds spelled with ..",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, []string{f.ws + "/up/../proj:/work:rw"}, nil)
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + f.ws + `/up/../proj" resolves to "` + filepath.Join(f.outside, "proj") + `", which is not allowlisted`
			},
		},
		{
			name: "HostConfig.Mounts bind spelled with ..",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, nil, []ForkStartRecheckMount{bindMount(f.ws + "/up/../proj")})
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + f.ws + `/up/../proj" resolves to "` + filepath.Join(f.outside, "proj") + `", which is not allowlisted`
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			policy := f.policy([]string{f.ws}, nil)
			f.daemon.set(http.StatusOK, tt.body(f))
			assertForwarded(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""))

			// Both bodies resolve through ws/proj or ws/up; swapping both
			// out of the allowlist leaves the field under test as the only
			// one that can carry the denial.
			if strings.Contains(tt.name, "..") {
				f.swap("up", filepath.Join(f.outside, "sub"))
			} else {
				f.swap("proj", f.outside)
			}
			assertDenied(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""), "container_start_bind_source_denied", tt.wantReason(f))
		})
	}
}

// TestForkStartRecheckInspectFailureIsDenied fails the inspect in every way
// the inspector can see and asserts the start is denied with the inspect
// reason, distinct from the escape reason, and never reaches the daemon.
func TestForkStartRecheckInspectFailureIsDenied(t *testing.T) {
	const reason = `container start denied: container "c1" could not be inspected to re-check its bind sources`
	tests := []struct {
		name   string
		status int
		body   string
		policy func(f *forkStartRecheckFixture) PolicyConfig
	}{
		{name: "daemon error", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
		{name: "not found", status: http.StatusNotFound, body: `{"message":"no such container"}`},
		{name: "no content", status: http.StatusNoContent, body: ``},
		{name: "unparsable body", status: http.StatusOK, body: `{"Mounts":`},
		{name: "wrong body shape", status: http.StatusOK, body: `{"Mounts":{"Type":"bind"}}`},
		{name: "body over the response limit", status: http.StatusOK, body: `{"x":"` + strings.Repeat("a", MaxResponseBodyBytes) + `"}`},
		{
			name: "transport error",
			policy: func(f *forkStartRecheckFixture) PolicyConfig {
				p := f.policy([]string{f.ws}, nil)
				p.ForkStartRecheck.InspectContainer = NewForkStartRecheckInspectorWithRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return nil, net.ErrClosed
				}))
				return p
			},
		},
		{
			name: "no inspector configured",
			policy: func(f *forkStartRecheckFixture) PolicyConfig {
				p := f.policy([]string{f.ws}, nil)
				p.ForkStartRecheck.InspectContainer = nil
				return p
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			policy := f.policy([]string{f.ws}, nil)
			if tt.policy != nil {
				policy = tt.policy(f)
			} else {
				f.daemon.set(tt.status, tt.body)
			}
			assertDenied(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""), "container_start_inspect_failed", reason)
		})
	}
}

// TestForkStartRecheckLogsTheInspectCause pins that the cause of an inspect
// failure, which the deny reason leaves out, reaches the log.
func TestForkStartRecheckLogsTheInspectCause(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(http.StatusInternalServerError, `{}`)
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	got := sendLogged(t, logger, f.policy([]string{f.ws}, nil), http.MethodPost, "/containers/c1/start", "")
	assertDenied(t, got, "container_start_inspect_failed", `container start denied: container "c1" could not be inspected to re-check its bind sources`)
	for _, want := range []string{"level=WARN", "container start re-check: inspect failed", "upstream returned 500 Internal Server Error"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q does not hold %q", logs.String(), want)
		}
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// TestForkStartRecheckNarrowsNothingCreateAllowed covers the starts that must
// pass as before: no allowlist, an allowlist with "/", a source no allowlist
// admits as written, a container with no bind, and non-bind entries.
func TestForkStartRecheckNarrowsNothingCreateAllowed(t *testing.T) {
	tests := []struct {
		name        string
		compat      func(f *forkStartRecheckFixture) []string
		libpod      func(f *forkStartRecheckFixture) []string
		body        func(f *forkStartRecheckFixture) string
		wantInspect bool
	}{
		{
			// The default policy denies every bind at create. Nothing to
			// re-check, so no inspect: a failing daemon cannot deny the start.
			name: "no allowlist",
			body: func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			name:   "compat allowlist holds /",
			compat: func(*forkStartRecheckFixture) []string { return []string{"/"} },
			libpod: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body:   func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			name:   "libpod allowlist holds /",
			compat: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			libpod: func(*forkStartRecheckFixture) []string { return []string{"/"} },
			body:   func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			// Created under another policy; the start passes as it did.
			name:   "source outside every allowlist as written",
			compat: func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, []string{filepath.Join(f.ws, "proj") + ":/w"}, nil)
			},
			wantInspect: true,
		},
		{
			name:        "no bind",
			compat:      func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body:        func(*forkStartRecheckFixture) string { return `{"HostConfig":{"Binds":null},"Mounts":[]}` },
			wantInspect: true,
		},
		{
			name:   "named volume and volume mount",
			compat: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body: func(f *forkStartRecheckFixture) string {
				// The volume entries name the swapped ws/proj, so only their
				// type keeps them out of the re-check.
				proj := filepath.Join(f.ws, "proj")
				return inspectBody(t, []ForkStartRecheckMount{{Type: "volume", Source: proj}}, []string{"data:/data"}, []ForkStartRecheckMount{{Type: "volume", Source: proj}})
			},
			wantInspect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			var compat, libpod []string
			if tt.compat != nil {
				compat = tt.compat(f)
			}
			if tt.libpod != nil {
				libpod = tt.libpod(f)
			}
			f.swap("proj", f.outside)
			f.daemon.set(http.StatusOK, tt.body(f))
			for _, route := range forkStartRecheckRoutes {
				assertForwarded(t, send(t, f.policy(compat, libpod), http.MethodPost, route.path, ""))
			}
			if got := len(f.daemon.inspects()) > 0; got != tt.wantInspect {
				t.Errorf("daemon inspected = %v, want %v: %q", got, tt.wantInspect, f.daemon.inspects())
			}
		})
	}
}

// TestForkStartRecheckAllowlists checks which allowlist holds a source: each
// one that admits it as written is tried, and one that also admits the
// resolved form is enough. The compat and libpod allowlists apply to both
// route families, since the daemon mounts the same source whichever route
// created the container.
func TestForkStartRecheckAllowlists(t *testing.T) {
	tests := []struct {
		name   string
		compat func(f *forkStartRecheckFixture) []string
		libpod func(f *forkStartRecheckFixture) []string
		// source is the bind source under ws; empty means "proj".
		source     string
		target     func(f *forkStartRecheckFixture) string
		path       string
		wantDenied bool
	}{
		{
			name:       "libpod allowlist holds a compat start",
			libpod:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/containers/c1/start",
			wantDenied: true,
		},
		{
			name:       "compat allowlist holds a libpod start",
			compat:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/libpod/containers/c1/start",
			wantDenied: true,
		},
		{
			// ws/up/inner -> ws/proj: outside the narrow compat entry,
			// inside the libpod one.
			name:   "one admitting allowlist is enough",
			compat: func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			libpod: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			source: "up/inner",
			target: func(f *forkStartRecheckFixture) string { return filepath.Join(f.ws, "proj") },
			path:   "/containers/c1/start",
		},
		{
			name:       "every admitting allowlist fails",
			compat:     func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			libpod:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			source:     "up/inner",
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/containers/c1/start",
			wantDenied: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			var compat, libpod []string
			if tt.compat != nil {
				compat = tt.compat(f)
			}
			if tt.libpod != nil {
				libpod = tt.libpod(f)
			}
			name := tt.source
			if name == "" {
				name = "proj"
			}
			proj := filepath.Join(f.ws, name)
			f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{bindMount(proj)}, nil, nil))
			assertForwarded(t, send(t, f.policy(compat, libpod), http.MethodPost, tt.path, ""))
			f.swap(name, tt.target(f))
			got := send(t, f.policy(compat, libpod), http.MethodPost, tt.path, "")
			if !tt.wantDenied {
				assertForwarded(t, got)
				return
			}
			subject := "container start"
			if strings.HasPrefix(tt.path, "/libpod/") {
				subject = "libpod container start"
			}
			resolved := tt.target(f)
			assertDenied(t, got, "container_start_bind_source_denied",
				subject+` denied: bind mount source "`+proj+`" resolves to "`+resolved+`", which is not allowlisted`)
		})
	}
}

// TestForkStartRecheckOtherRoutesUnchanged sends the container routes beside
// start and restart, and near-miss spellings, and asserts none is inspected.
func TestForkStartRecheckOtherRoutesUnchanged(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(http.StatusInternalServerError, `{}`)
	policy := f.policy([]string{f.ws}, []string{f.ws})
	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/containers/c1/stop"},
		{http.MethodPost, "/containers/c1/kill"},
		{http.MethodPost, "/containers/c1/pause"},
		{http.MethodPost, "/containers/c1/unpause"},
		{http.MethodPost, "/containers/c1/wait"},
		{http.MethodPost, "/containers/c1/rename"},
		{http.MethodPost, "/containers/c1/start/x"},
		{http.MethodPost, "/containers/start"},
		{http.MethodPost, "/containers/restart"},
		{http.MethodPost, "/libpod/containers/start"},
		{http.MethodPost, "/libpod/containers/c1/stop"},
		{http.MethodPost, "/libpod/pods/c1/start"},
		{http.MethodGet, "/containers/c1/start"},
		{http.MethodGet, "/containers/c1/json"},
	} {
		assertForwarded(t, send(t, policy, req.method, req.path, ""))
	}
	if got := f.daemon.inspects(); len(got) != 0 {
		t.Errorf("daemon saw %q, want no inspect", got)
	}
}

// TestForkStartRecheckInspectsTheNamedContainer pins the identifier the
// inspect uses: everything between the prefix and the action, path-escaped.
func TestForkStartRecheckInspectsTheNamedContainer(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	policy := f.policy([]string{f.ws}, nil)
	for _, route := range []struct{ path, want string }{
		{"/v1.45/containers/c1/start", "GET /containers/c1/json"},
		{"/containers/a/b/restart", "GET /containers/a%2Fb/json"},
		{"/libpod/containers/web-1/start", "GET /containers/web-1/json"},
	} {
		before := len(f.daemon.inspects())
		send(t, policy, http.MethodPost, route.path, "")
		got := f.daemon.inspects()[before:]
		if len(got) != 1 || got[0] != route.want {
			t.Errorf("%s: daemon saw %q, want [%q]", route.path, got, route.want)
		}
	}
}

// TestForkStartRecheckIsTheOnlyStartInspector pins that no other POST
// inspector matches a start or restart path. The middleware runs only the
// highest-severity bucket of matching inspectors, so a second match could
// shadow the re-check or be shadowed by it.
func TestForkStartRecheckIsTheOnlyStartInspector(t *testing.T) {
	policy := compileRuntimePolicy(nil, PolicyConfig{}, newMutationEngine(MutationOptions{}))
	for _, route := range forkStartRecheckRoutes {
		var matched []string
		for _, p := range policy.inspectPoliciesByMethod[http.MethodPost] {
			if p.matches(NormalizePath(route.path)) {
				matched = append(matched, p.errorLogMessage)
			}
		}
		if len(matched) != 1 || matched[0] != "failed to re-check container start bind sources" {
			t.Errorf("%s: matching inspectors %q, want only the start re-check", route.path, matched)
		}
	}
}

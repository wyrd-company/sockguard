// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions, ../../../docs/fork-endpoints]
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// All host paths belong to this fixture. No test needs a daemon or host image.
type forkFieldChain struct {
	f              serveWorkspaceFixture
	roots          []string
	other, outside string
	handler        http.Handler
	store          *filter.WorkspaceExceptionStore
	mu             sync.Mutex
	calls          []forkFieldCall
}

type forkFieldCall struct{ method, uri, body string }

func newForkFieldChain(t *testing.T, edit func(*config.Config), reply http.HandlerFunc) *forkFieldChain {
	t.Helper()
	h := &forkFieldChain{f: newServeWorkspaceFixture(t)}
	base := filepath.Dir(h.f.root)
	h.other, h.outside = filepath.Join(h.f.root, "beta"), filepath.Join(base, "external")
	h.roots = []string{h.f.root, filepath.Join(base, "sockets"), filepath.Join(base, "staging")}
	for _, p := range append(append([]string{h.other, h.outside}, h.roots...), filepath.Join(h.roots[1], "alpha"), filepath.Join(h.roots[2], "alpha")) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bindfs.ConfineForTests(func() []string { return []string{base} })
	t.Cleanup(func() { bindfs.ConfineForTests(func() []string { return nil }) })
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		h.mu.Lock()
		h.calls = append(h.calls, forkFieldCall{r.Method, r.URL.RequestURI(), string(body)})
		h.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if reply != nil {
			reply(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"created"}`)
	}))
	t.Cleanup(daemon.Close)
	cfg := h.f.config("")
	cfg.Upstream.Endpoints = []config.UpstreamEndpoint{{Address: "tcp://" + strings.TrimPrefix(daemon.URL, "http://"), InsecureAllowPlainTCP: true}}
	cfg.Upstream.Flavor = "docker"
	cfg.Upstream.Failover.HealthInterval = "-1s"
	cfg.WorkspaceExceptions.PerWorkspaceRoots = h.roots
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	cfg.RequestBody.ContainerCreate.RequireNoRestartPolicy = true
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = h.roots
	if edit != nil {
		edit(&cfg)
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
	h.store = runtime.workspaceExceptions
	var teardown func()
	h.handler, teardown, _ = buildServeHandlerChainWithRuntime(serveHandlerBuild{Cfg: &cfg, Logger: newDiscardLogger(), Rules: rules, Deps: deps, Runtime: runtime})
	t.Cleanup(teardown)
	h.takeCalls() // discard startup probes
	return h
}

func (h *forkFieldChain) takeCalls() []forkFieldCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	calls := h.calls
	h.calls = nil
	return calls
}

func forkFieldJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (h *forkFieldChain) grants(t *testing.T, workspace string, grants map[string]any) {
	t.Helper()
	data := forkFieldJSON(t, map[string]any{"version": 1, "exceptions": []any{map[string]any{
		"workspace": workspace, "grants": grants,
		"approval": map[string]any{"by": map[string]string{"issuer": "https://id.example.org", "subject": "user-0001"}, "at": "2026-01-02T03:04:05Z"},
	}}})
	if err := os.WriteFile(h.f.file, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := h.store.Reload().State(); got != filter.WorkspaceExceptionsLoaded {
		t.Fatalf("fixture policy state = %s", got)
	}
}

func removeForkFieldPolicy(h *forkFieldChain) error {
	if err := os.Remove(h.f.file); err != nil && !os.IsNotExist(err) {
		return err
	}
	h.store.Reload()
	return nil
}

func (h *forkFieldChain) create(host map[string]any) map[string]any {
	hc := map[string]any{"Binds": []string{h.f.alpha + ":/workspace"}}
	for k, v := range host {
		hc[k] = v
	}
	return map[string]any{"Image": "busybox", "HostConfig": hc}
}

func (h *forkFieldChain) request(t *testing.T, method, uri, body string, headers http.Header, want int, reason string) []forkFieldCall {
	t.Helper()
	h.takeCalls()
	r := httptest.NewRequest(method, uri, strings.NewReader(body))
	r.Header = headers.Clone()
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, r)
	calls := h.takeCalls()
	var denial struct {
		Reason string `json:"reason"`
	}
	if want == http.StatusForbidden {
		_ = json.Unmarshal(rec.Body.Bytes(), &denial)
	}
	if rec.Code != want || !strings.Contains(denial.Reason, reason) {
		t.Fatalf("field admission: status=%d body=%s calls=%v; want=%d reason=%q", rec.Code, rec.Body.String(), calls, want, reason)
	}
	if want == http.StatusForbidden {
		for _, call := range calls {
			if call.method != http.MethodGet {
				t.Fatalf("denied write forwarded: %+v", call)
			}
		}
	} else {
		if len(calls) == 0 {
			t.Fatal("admitted request never reached daemon")
		}
		last := calls[len(calls)-1]
		if last.method != method || last.uri != uri {
			t.Fatalf("forwarded route: %+v; want %s %s", last, method, uri)
		}
		var got, expected any
		if body != "" {
			if json.Unmarshal([]byte(last.body), &got) != nil || json.Unmarshal([]byte(body), &expected) != nil || !reflect.DeepEqual(got, expected) {
				t.Fatalf("forwarded body: %s; want %s", last.body, body)
			}
		}
		if want == http.StatusCreated && rec.Body.String() != `{"Id":"created"}` {
			t.Fatalf("forwarded result: %s", rec.Body.String())
		}
	}
	return calls
}

func (h *forkFieldChain) postCreate(t *testing.T, body map[string]any, want int, reason string) {
	t.Helper()
	h.request(t, "POST", "/v1.51/containers/create", forkFieldJSON(t, body), http.Header{filter.WorkspaceHeader: []string{h.f.alpha}}, want, reason)
}

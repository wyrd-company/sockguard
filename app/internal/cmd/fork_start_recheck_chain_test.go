package cmd

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
	"github.com/codeswhat/sockguard/app/internal/config"
)

// forkStartRecheckChainDaemon answers the container inspect of "c1" with one
// bind source and records every request that reaches it.
type forkStartRecheckChainDaemon struct {
	source string
	mu     sync.Mutex
	seen   []string
}

func (d *forkStartRecheckChainDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	d.seen = append(d.seen, r.Method+" "+r.URL.Path)
	d.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/containers/c1/json":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"HostConfig": map[string]any{"Binds": []string{d.source + ":/work"}},
			"Mounts":     []map[string]string{{"Type": "bind", "Source": d.source, "Destination": "/work"}},
		})
	case r.Method == http.MethodPost:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *forkStartRecheckChainDaemon) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := slices.Clone(d.seen)
	d.seen = nil
	return out
}

// TestServeChainForkStartRecheckDeniesASwappedBindSource is the wiring proof
// for the start re-check: through the production chain, the inspect reaches
// the daemon through the upstream resolver, an unchanged source starts, and a
// source replaced with a symlink out of allowed_bind_mounts after create is
// denied before the start reaches the daemon.
func TestServeChainForkStartRecheckDeniesASwappedBindSource(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bindfs.RealRootForTest(t, root)
	ws, outside := filepath.Join(root, "ws"), filepath.Join(root, "outside")
	proj := filepath.Join(ws, "proj")
	for _, dir := range []string{proj, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	daemon := &forkStartRecheckChainDaemon{source: proj}
	addr := newEngineChain(t, "startre", daemon, func(cfg *config.Config) {
		cfg.Response.DenyVerbosity = "verbose"
		cfg.Upstream.Flavor = "docker"
		cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{ws}
		cfg.Rules = []config.RuleConfig{
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/start"}, Action: "allow"},
			{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/restart"}, Action: "allow"},
			{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
		}
	})
	_ = daemon.requests() // drop any start-up probe

	for _, action := range []string{"start", "restart"} {
		target := "http://" + addr + "/v1.45/containers/c1/" + action

		status, body := sendNamespaceChainRequest(t, target, "")
		if status != http.StatusNoContent {
			t.Fatalf("%s unchanged: status = %d, body %s; want 204", action, status, body)
		}
		if got, want := daemon.requests(), []string{"GET /containers/c1/json", "POST /v1.45/containers/c1/" + action}; !slices.Equal(got, want) {
			t.Fatalf("%s unchanged: daemon saw %q, want %q", action, got, want)
		}

		if err := os.Rename(proj, proj+".orig"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, proj); err != nil {
			t.Fatal(err)
		}
		status, body = sendNamespaceChainRequest(t, target, "")
		var denial struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(body, &denial)
		wantReason := "container " + action + ` denied: bind mount source "` + proj + `" resolves to "` + outside + `", which is not allowlisted`
		if status != http.StatusForbidden || denial.Reason != wantReason {
			t.Fatalf("%s swapped: status = %d, body %s; want 403 with reason %q", action, status, body, wantReason)
		}
		if got, want := daemon.requests(), []string{"GET /containers/c1/json"}; !slices.Equal(got, want) {
			t.Fatalf("%s swapped: daemon saw %q, want %q", action, got, want)
		}

		if err := os.Remove(proj); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(proj+".orig", proj); err != nil {
			t.Fatal(err)
		}
	}
}

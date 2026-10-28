package cmd

import (
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// TestForkClientProfileDenialUsesGlobalDenyVerbosity drives a privileged
// create through the serve chain under a client profile and under the default
// policy. The profile denial must carry the body the global
// response.deny_verbosity selects, and that body must match the default
// policy's denial of the same request.
func TestForkClientProfileDenialUsesGlobalDenyVerbosity(t *testing.T) {
	const createBody = `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	allowCreate := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/create"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	denyAll := []config.RuleConfig{
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}

	for _, verbosity := range []string{"verbose", "minimal"} {
		t.Run(verbosity, func(t *testing.T) {
			bodies := map[string]map[string]any{}
			for _, scope := range []string{"profile", "default"} {
				var reached atomic.Int32
				daemon := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Add(1)
					w.WriteHeader(http.StatusCreated)
				})
				addr := newEngineChain(t, "denyv-"+scope[:3]+verbosity[:3], daemon, func(cfg *config.Config) {
					cfg.Upstream.Flavor = "docker"
					cfg.Response.DenyVerbosity = verbosity
					if scope == "default" {
						cfg.Rules = allowCreate
						return
					}
					cfg.Rules = denyAll
					cfg.Clients.Profiles = []config.ClientProfileConfig{{Name: "workload", Rules: allowCreate}}
					cfg.Clients.DefaultProfile = "workload"
				})

				status, raw := postForkDenyVerbosityCreate(t, "http://"+addr+"/v1.45/containers/create", createBody)
				if reached.Load() != 0 {
					t.Fatalf("%s: daemon was reached for a privileged create", scope)
				}
				if status != http.StatusForbidden {
					t.Fatalf("%s: status = %d, want 403; body: %s", scope, status, raw)
				}
				var body map[string]any
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("%s: decode body %s: %v", scope, raw, err)
				}
				bodies[scope] = body
			}

			got := bodies["profile"]
			if got["message"] != "request denied by sockguard policy" {
				t.Errorf("profile denial message = %v", got["message"])
			}
			keys := slices.Sorted(maps.Keys(got))
			switch verbosity {
			case "verbose":
				reason, _ := got["reason"].(string)
				if got["method"] != http.MethodPost || got["path"] != "/v1.45/containers/create" || !strings.Contains(reason, "privileged") {
					t.Errorf("profile denial under verbose = %v, want method, path and a privileged reason", got)
				}
			case "minimal":
				if !slices.Equal(keys, []string{"message"}) {
					t.Errorf("profile denial under minimal has keys %v, want only message", keys)
				}
			}
			if !maps.Equal(got, bodies["default"]) {
				t.Errorf("profile denial = %v, default-policy denial = %v; want the same body", got, bodies["default"])
			}
		})
	}
}

func postForkDenyVerbosityCreate(t *testing.T, target, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", target, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

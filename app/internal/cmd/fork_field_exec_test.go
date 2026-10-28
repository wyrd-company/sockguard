// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions, ../../../docs/content/docs/configuration]
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestForkFieldExecCommandAndIndependentGuards(t *testing.T) {
	for _, mode := range []string{"off", "any", "root_allowed", "command_list", "env"} {
		t.Run(mode, func(t *testing.T) {
			var workspace string
			labels := map[string]string{}
			user, privileged := "1000", false
			argv := []string{"/bin/sh", "-c", "printf sample"}
			h := newForkFieldChain(t, func(c *config.Config) {
				c.Rules = []config.RuleConfig{
					{Match: config.MatchConfig{Method: "POST", Path: "/containers/*/exec"}, Action: "allow"},
					{Match: config.MatchConfig{Method: "POST", Path: "/exec/*/start"}, Action: "allow"},
				}
				p := &c.RequestBody.Exec
				p.AllowAnyCommand = mode != "off"
				p.AllowRootUser = mode == "root_allowed" // independent of arbitrary argv
				p.AllowPrivileged = false
				if mode == "command_list" {
					p.AllowedCommands = [][]string{{"true"}}
				}
				if mode == "env" {
					p.AllowedEnvValues = []string{"MODE=safe"}
				}
			}, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == "GET" && r.URL.Path == "/containers/sample/json":
					_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Labels": labels}})
				case r.Method == "GET" && r.URL.Path == "/exec/instance/json":
					_, _ = io.WriteString(w, execInspectJSON("sample", user, privileged, argv[0], argv[1:]...))
				case strings.HasSuffix(r.URL.Path, "/exec"):
					w.WriteHeader(201)
					_, _ = io.WriteString(w, `{"Id":"created"}`)
				case strings.HasSuffix(r.URL.Path, "/start"):
					w.WriteHeader(204)
				default:
					http.Error(w, "unexpected request", 404)
				}
			})
			workspace = h.f.alpha
			labels[filter.WorkspaceLocalFolderLabel] = workspace
			headers := http.Header{}
			headers.Set(filter.WorkspaceHeader, workspace)
			for _, start := range []bool{false, true} {
				name := "create"
				if start {
					name = "start"
				}
				t.Run(name, func(t *testing.T) {
					call := func(u string, p bool, env []string, want int, reason string) {
						t.Helper()
						user, privileged = u, p
						uri, body := "/v1.51/containers/sample/exec", forkFieldJSON(t, map[string]any{"Cmd": argv, "User": u, "Privileged": p, "Env": env})
						if start {
							uri, body = "/v1.51/exec/instance/start", `{"Detach":true,"Tty":false}`
						}
						calls := h.request(t, "POST", uri, body, headers, want, reason)
						// Workspace lookup is mandatory even when the body later denies.
						reads := 0
						for _, c := range calls {
							if c.uri == "/containers/sample/json" {
								reads++
							}
						}
						if reads != 1 {
							t.Fatalf("exec workspace lookup count=%d calls=%v", reads, calls)
						}
					}
					allowStatus := 201
					if start {
						allowStatus = 204
					}
					if mode == "off" {
						call("1000", false, nil, 403, "no commands are allowlisted")
						return
					}
					if mode == "command_list" {
						argv = []string{"true"}
						call("1000", false, nil, allowStatus, "")
						argv = []string{"/bin/sh", "-c", "printf sample"}
						call("1000", false, nil, 403, "is not allowlisted")
						return
					}
					call("1000", false, nil, allowStatus, "")
					if mode == "root_allowed" {
						call("root", false, nil, allowStatus, "")
					} else {
						call("root", false, nil, 403, "root exec user is not allowed")
					}
					call("1000", true, nil, 403, "privileged exec is not allowed")
					if mode == "env" && !start {
						call("1000", false, []string{"MODE=safe"}, allowStatus, "")
						call("1000", false, []string{"MODE=other"}, 403, "disallowed value")
					}
				})
			}
		})
	}
}

func TestForkFieldExecTargetRequiresActualSameKindLabel(t *testing.T) {
	var labels map[string]string
	h := newForkFieldChain(t, func(c *config.Config) {
		c.RequestBody.Exec.AllowAnyCommand = true
		c.RequestBody.Exec.AllowRootUser = false
		c.Rules = []config.RuleConfig{{Match: config.MatchConfig{Method: "POST", Path: "/containers/*/exec"}, Action: "allow"}, {Match: config.MatchConfig{Method: "POST", Path: "/exec/*/start"}, Action: "allow"}}
	}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			if strings.HasPrefix(r.URL.Path, "/exec/") {
				_, _ = io.WriteString(w, execInspectJSON("sample", "1000", false, "true"))
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"Config": map[string]any{"Labels": labels}})
			}
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Id":"created"}`)
	})
	for _, header := range []string{filter.WorkspaceHeader, filter.WorkspaceThrowawayHeader} {
		t.Run(header, func(t *testing.T) {
			same, opposite := filter.WorkspaceLocalFolderLabel, filter.WorkspaceThrowawayLabel
			if header == filter.WorkspaceThrowawayHeader {
				same, opposite = opposite, same
			}
			for _, route := range []string{"/v1.51/containers/sample/exec", "/v1.51/exec/instance/start"} {
				t.Run(route, func(t *testing.T) {
					for _, tc := range []struct {
						name   string
						target map[string]string
						want   int
						reason string
					}{
						{"same", map[string]string{same: h.f.alpha}, 201, ""},
						{"absent", nil, 403, "target container has no matching workspace label"},
						{"other_workspace", map[string]string{same: h.other}, 403, "disagrees with the request's workspace"},
						{"opposite", map[string]string{opposite: h.f.alpha}, 403, "workspace kind"},
						{"both", map[string]string{same: h.f.alpha, opposite: h.f.alpha}, 403, "workspace kind"},
					} {
						t.Run(tc.name, func(t *testing.T) {
							labels = map[string]string{same: h.f.alpha}
							headers := http.Header{}
							headers.Set(header, h.f.alpha)
							body := `{"Cmd":["true"],"User":"1000"}`
							if strings.HasSuffix(route, "/start") {
								body = `{"Detach":true}`
							}
							h.request(t, "POST", route, body, headers, 201, "")
							labels = tc.target
							h.request(t, "POST", route, body, headers, tc.want, tc.reason)
						})
					}
				})
			}
		})
	}
}

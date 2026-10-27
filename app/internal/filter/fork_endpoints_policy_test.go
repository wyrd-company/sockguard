// relationships:
//
//	references: [../../../docs/fork-endpoints]
package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Candidate contract only; no deployed Menagerie policy is supplied.
func TestForkEndpointsCandidatePolicy(t *testing.T) {
	var rules []*CompiledRule
	for _, route := range [][2]string{
		{"HEAD", "/_ping"}, {"GET", "/_ping"}, {"GET", "/containers/json"},
		{"GET", "/containers/*/json"}, {"GET", "/images/**/json"}, {"POST", "/images/create"},
		{"POST", "/containers/create"}, {"POST", "/containers/*/start"}, {"POST", "/containers/*/stop"},
		{"DELETE", "/containers/*"}, {"POST", "/containers/*/exec"}, {"POST", "/exec/*/start"},
		{"GET", "/exec/*/json"}, {"POST", "/grpc"}, {"POST", "/session"},
	} {
		rule, err := CompileRule(Rule{Methods: []string{route[0]}, Pattern: route[1], Action: ActionAllow})
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	opts := Options{PolicyConfig: PolicyConfig{
		ImagePull:       ImagePullOptions{AllowedRegistries: []string{"registry.example.test"}},
		ContainerRemove: ContainerRemoveOptions{AllowForce: true, AllowRemoveVolumes: true},
		Exec: ExecOptions{AllowAnyCommand: true, AllowRootUser: true,
			InspectStart: func(context.Context, string) (ExecInspectResult, bool, error) {
				return ExecInspectResult{Command: []string{"/bin/sh", "-c", "true"}}, true, nil
			}},
		Buildkit: BuildkitOptions{TunnelConfigured: true},
	}}
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"HEAD", "/_ping", "", 204}, {"GET", "/_ping", "", 204},
		{"GET", "/v1.48/containers/json?all=1", "", 204}, {"GET", "/containers/sample/json", "", 204},
		{"GET", "/images/registry.example.test/team/sample/json", "", 204},
		{"POST", "/images/create?fromImage=registry.example.test/team/sample&tag=latest", "", 204},
		{"POST", "/containers/create", `{"Image":"busybox","HostConfig":{}}`, 204},
		{"POST", "/containers/sample/start", "", 204}, {"POST", "/containers/sample/stop?t=10", "", 204},
		{"DELETE", "/containers/sample?force=1&v=1", "", 204},
		{"POST", "/containers/sample/exec", `{"Cmd":["/bin/sh","-c","true"],"User":"root"}`, 204},
		{"POST", "/exec/sample/start", `{"Detach":false,"Tty":false}`, 204}, {"GET", "/exec/sample/json", "", 204},
		// HTTP admission only: a downstream mediator must terminate the tunnels.
		{"POST", "/grpc", "", 204}, {"POST", "/session", "", 204},
		{"POST", "/images/sample/push", "", 403}, {"GET", "/images/get?names=sample", "", 403},
		{"GET", "/images/sample/get", "", 403}, {"POST", "/images/load", "archive", 403},
		{"POST", "/networks/create", `{}`, 403}, {"POST", "/build", "archive", 403},
		{"POST", "/moby.buildkit.v1.Control/Solve", "", 403},
		{"POST", "/containers/create", `{"Image":"busybox","HostConfig":{"Privileged":true}}`, 403},
		{"POST", "/images/create?fromImage=other.example.test/sample", "", 403},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			reached := false
			handler := MiddlewareWithOptions(rules, testLogger(), opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusNoContent)
			}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if response.Code != tc.want || reached != (tc.want == http.StatusNoContent) {
				t.Fatalf("status=%d reached=%t; want status=%d; body=%s", response.Code, reached, tc.want, response.Body.String())
			}
		})
	}
}

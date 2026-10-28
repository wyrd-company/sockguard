package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestExecAllowAnyCommandOnlyLiftsCommandAllowlistGate mirrors
// TestExecBlindWritesOnlyLiftsCommandAllowlistGate for AllowAnyCommand.
func TestExecAllowAnyCommandOnlyLiftsCommandAllowlistGate(t *testing.T) {
	tests := []struct {
		name       string
		opts       ExecOptions
		result     ExecInspectResult
		wantReason string
	}{
		{"off denies an empty allowlist", ExecOptions{}, ExecInspectResult{Command: []string{"id"}, User: "1000"}, "exec denied: no commands are allowlisted"},
		{"on admits any argv", ExecOptions{AllowAnyCommand: true}, ExecInspectResult{Command: []string{"/bin/sh", "-c", "id"}, User: "1000"}, ""},
		{"on still denies privileged", ExecOptions{AllowAnyCommand: true}, ExecInspectResult{Command: []string{"id"}, User: "1000", Privileged: true}, "exec denied: privileged exec is not allowed"},
		{"on still denies root", ExecOptions{AllowAnyCommand: true}, ExecInspectResult{Command: []string{"id"}, User: "0:0"}, "exec denied: root exec user is not allowed"},
		{"on still denies empty user", ExecOptions{AllowAnyCommand: true}, ExecInspectResult{Command: []string{"id"}}, "exec denied: root exec user is not allowed"},
		{"on still applies env", ExecOptions{AllowAnyCommand: true, DeniedEnvVars: []string{"LD_PRELOAD"}}, ExecInspectResult{Command: []string{"id"}, User: "1000", Env: []string{"LD_PRELOAD=/x.so"}}, `exec denied: environment variable "LD_PRELOAD" is denylisted`},
		{"on does not widen an allowlist", ExecOptions{AllowAnyCommand: true, AllowedCommands: [][]string{{"/bin/true"}}}, ExecInspectResult{Command: []string{"id"}, User: "1000"}, `exec denied: command "id" is not allowlisted`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newExecPolicy(tt.opts).denyReason(tt.result); got != tt.wantReason {
				t.Fatalf("denyReason() = %q, want %q", got, tt.wantReason)
			}
		})
	}
}

// TestMiddlewareExecAllowAnyCommandCoversLibpodPaths: the setting applies to
// the libpod exec create and start paths through the same policy.
func TestMiddlewareExecAllowAnyCommandCoversLibpodPaths(t *testing.T) {
	r1, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/containers/*/exec", Action: ActionAllow, Index: 0})
	r2, _ := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/libpod/exec/*/start", Action: ActionAllow, Index: 1})
	r3, _ := CompileRule(Rule{Methods: []string{"*"}, Pattern: "/**", Action: ActionDeny, Reason: "deny all", Index: 2})
	rules := []*CompiledRule{r1, r2, r3}
	stored := map[string]ExecInspectResult{
		"plain": {Command: []string{"/bin/sh", "-c", "make"}, User: "1000"},
		"root":  {Command: []string{"/bin/sh"}, User: "root"},
	}
	inspect := func(_ context.Context, id string) (ExecInspectResult, bool, error) {
		r, ok := stored[id]
		return r, ok, nil
	}

	for _, on := range []bool{false, true} {
		var forwarded int
		handler := MiddlewareWithOptions(rules, testLogger(), Options{
			PolicyConfig: PolicyConfig{Exec: ExecOptions{AllowAnyCommand: on, InspectStartLibpod: inspect}},
		})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			forwarded++
			w.WriteHeader(http.StatusOK)
		}))
		serve := func(path, body string) int {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
			return rec.Code
		}

		want := http.StatusForbidden
		if on {
			want = http.StatusOK
		}
		if got := serve("/v5.0.0/libpod/containers/abc/exec", `{"User":"1000","Cmd":["make"]}`); got != want {
			t.Fatalf("on=%t libpod create: status = %d, want %d", on, got, want)
		}
		if got := serve("/v5.0.0/libpod/exec/plain/start", `{}`); got != want {
			t.Fatalf("on=%t libpod start: status = %d, want %d", on, got, want)
		}
		if got := serve("/v5.0.0/libpod/exec/root/start", `{}`); got != http.StatusForbidden {
			t.Fatalf("on=%t libpod root start: status = %d, want 403", on, got)
		}
		wantForwarded := 0
		if on {
			wantForwarded = 2
		}
		if forwarded != wantForwarded {
			t.Fatalf("on=%t forwarded = %d, want %d", on, forwarded, wantForwarded)
		}
	}
}

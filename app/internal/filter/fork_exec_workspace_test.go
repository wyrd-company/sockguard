// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestForkExecWorkspaceHeader(t *testing.T) {
	h := newWSHarness(t, nil)
	rules := []*CompiledRule{}
	for _, pattern := range []string{"/containers/*/exec", "/exec/*/start"} {
		rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: pattern, Action: ActionAllow})
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	serve := func(apply bool, path string, header http.Header) (int, string) {
		cfg := PolicyConfig{ContainerCreate: h.options(func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = apply })}
		cfg.Exec.AllowAnyCommand = true
		cfg.ForkStartRecheck.InspectContainer = func(context.Context, string) (ForkStartRecheckContainer, error) {
			label := WorkspaceLocalFolderLabel
			if header.Get(WorkspaceThrowawayHeader) != "" {
				label = WorkspaceThrowawayLabel
			}
			return ForkStartRecheckContainer{Config: ForkStartRecheckConfig{Labels: map[string]string{label: h.f.alpha}}}, nil
		}
		cfg.Exec.InspectStart = func(context.Context, string) (ExecInspectResult, bool, error) {
			return ExecInspectResult{ContainerID: "sample", Command: []string{"true"}, User: "1000"}, true, nil
		}
		cfg.DenyResponseVerbosity = DenyResponseVerbosityVerbose
		handler := MiddlewareWithOptions(rules, testLogger(), Options{PolicyConfig: cfg})(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"Cmd":["true"],"User":"1000"}`))
		r.Header = header
		handler.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	valid := http.Header{WorkspaceHeader: {h.f.alpha}}
	throwaway := http.Header{WorkspaceThrowawayHeader: {h.f.alpha}}
	for _, path := range []string{"/v1.51/containers/sample/exec", "/v1.51/exec/0123/start"} {
		subject := "exec create"
		if strings.Contains(path, "/start") {
			subject = "exec start"
		}
		t.Run(subject, func(t *testing.T) {
			for name, header := range map[string]http.Header{
				"headerless":   {},
				"both headers": {WorkspaceHeader: {h.f.alpha}, WorkspaceThrowawayHeader: {h.f.alpha}},
				"invalid":      {WorkspaceHeader: {h.f.outside}},
			} {
				code, body := serve(true, path, header)
				if code != http.StatusForbidden || !strings.Contains(body, subject+" denied") {
					t.Fatalf("%s: status %d body %s", name, code, body)
				}
				if name == "invalid" && strings.Contains(body, h.f.outside) {
					t.Fatalf("deny reason quotes the header: %s", body)
				}
			}
			// With a valid header and matching target the request reaches
			// the exec body inspector.
			if code, body := serve(true, path, valid); strings.Contains(body, "workspace") {
				t.Fatalf("valid header: status %d body %s", code, body)
			}
			if code, body := serve(true, path, throwaway); strings.Contains(body, "workspace") {
				t.Fatalf("throwaway header: status %d body %s", code, body)
			}
			// A profile without apply_workspace_exceptions needs no header.
			if code, body := serve(false, path, http.Header{}); strings.Contains(body, "workspace") {
				t.Fatalf("profile without apply: status %d body %s", code, body)
			}
		})
	}
	if code, _ := serve(true, "/v1.51/containers/sample/exec", valid); code != http.StatusNoContent {
		t.Fatalf("exec create with a valid header: status %d, want 204", code)
	}
	if code, _ := serve(false, "/v1.51/containers/sample/exec", http.Header{}); code != http.StatusNoContent {
		t.Fatalf("exec create without apply: status %d, want 204", code)
	}
}

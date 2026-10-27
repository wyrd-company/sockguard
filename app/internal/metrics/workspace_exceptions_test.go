package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkspaceExceptionsLoadCounter(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	scrape := func() string {
		rec := httptest.NewRecorder()
		registry.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
	if body := scrape(); strings.Contains(body, "sockguard_workspace_exceptions_loads_total") {
		t.Fatal("the series must be absent until the first load")
	}
	registry.ObserveWorkspaceExceptionsLoad("ok")
	registry.ObserveWorkspaceExceptionsLoad("invalid")
	registry.ObserveWorkspaceExceptionsLoad("invalid")
	body := scrape()
	for _, want := range []string{
		"# TYPE sockguard_workspace_exceptions_loads_total counter",
		`sockguard_workspace_exceptions_loads_total{result="invalid"} 2`,
		`sockguard_workspace_exceptions_loads_total{result="ok"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape missing %q:\n%s", want, body)
		}
	}
	var nilRegistry *Registry
	nilRegistry.ObserveWorkspaceExceptionsLoad("ok")
}

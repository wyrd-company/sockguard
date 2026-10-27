package filter

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newNetworkInspectTestServer starts a mock daemon that records the escaped
// path of every request and answers with handler. The returned inspector
// dials it whatever the URL host says.
func newNetworkInspectTestServer(t *testing.T, handler http.HandlerFunc) (NetworkInspectFunc, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return NewDockerNetworkInspectorWithRoundTripper(transport), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func TestNetworkInspectorReturnsDriver(t *testing.T) {
	inspect, paths := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Name":"lan","Driver":"macvlan","Containers":{}}`))
	})
	driver, found, err := inspect(context.Background(), "lan")
	if err != nil || !found || driver != "macvlan" {
		t.Fatalf("inspect = (%q, %t, %v), want (macvlan, true, nil)", driver, found, err)
	}
	if got := paths(); len(got) != 1 || got[0] != "/networks/lan" {
		t.Fatalf("daemon paths = %v, want [/networks/lan]", got)
	}
}

func TestNetworkInspectorReportsNotFound(t *testing.T) {
	inspect, _ := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such network", http.StatusNotFound)
	})
	if _, found, err := inspect(context.Background(), "x"); err != nil || found {
		t.Fatalf("inspect = (found %t, %v), want (false, nil)", found, err)
	}
}

func TestNetworkInspectorFailsOnServerError(t *testing.T) {
	inspect, _ := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	if _, _, err := inspect(context.Background(), "x"); err == nil {
		t.Fatal("inspect error = nil, want an error for a 500")
	}
}

func TestNetworkInspectorFailsWithoutDriverField(t *testing.T) {
	inspect, _ := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Name":"x"}`))
	})
	if _, _, err := inspect(context.Background(), "x"); err == nil || !strings.Contains(err.Error(), "no Driver") {
		t.Fatalf("inspect error = %v, want a missing Driver error", err)
	}
}

// TestNetworkInspectorEscapesIdentifier: a reference holding "/" or ".."
// stays one path segment, so it cannot reach another daemon route.
func TestNetworkInspectorEscapesIdentifier(t *testing.T) {
	inspect, paths := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Driver":"bridge"}`))
	})
	if _, _, err := inspect(context.Background(), "../containers/x"); err != nil {
		t.Fatalf("inspect = %v", err)
	}
	if got := paths(); len(got) != 1 || got[0] != "/networks/..%2Fcontainers%2Fx" {
		t.Fatalf("daemon paths = %v, want [/networks/..%%2Fcontainers%%2Fx]", got)
	}
}

func TestNetworkInspectorRejectsControlCharacter(t *testing.T) {
	inspect, paths := newNetworkInspectTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Driver":"bridge"}`))
	})
	if _, _, err := inspect(context.Background(), "a\nb"); err == nil {
		t.Fatal("inspect error = nil, want a control character error")
	}
	if got := paths(); len(got) != 0 {
		t.Fatalf("daemon paths = %v, want none", got)
	}
}

// TestNetworkDriverPolicyWithoutInspectorDenies: a list with no runtime
// lookup wired denies every attach that needs one.
func TestNetworkDriverPolicyWithoutInspectorDenies(t *testing.T) {
	policy := newNetworkPolicy(NetworkOptions{Drivers: NetworkDriverOptions{AllowedDrivers: []string{"bridge"}}})
	req := httptest.NewRequest(http.MethodPost, "/v1.45/networks/app/connect", strings.NewReader(`{"Container":"c1"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect error = %v", err)
	}
	if want := `network connect denied: network "app" driver lookup is not configured`; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
}

// TestNetworkDriverPolicyNormalizesList: entries are trimmed, lowercased and
// deduplicated, and blank entries are dropped.
func TestNetworkDriverPolicyNormalizesList(t *testing.T) {
	policy := newNetworkDriverPolicy(NetworkDriverOptions{AllowedDrivers: []string{" Bridge ", "bridge", " ", "Overlay"}})
	if got := strings.Join(policy.allowed, ","); got != "bridge,overlay" {
		t.Fatalf("allowed = %q, want bridge,overlay", got)
	}
}

// TestNetworkDriverPolicyDeniesInspectedEmptyDriver: an inspected network
// whose Driver is empty is denied; only a create's own empty Driver means
// bridge.
func TestNetworkDriverPolicyDeniesInspectedEmptyDriver(t *testing.T) {
	inspect := func(context.Context, string) (string, bool, error) { return "", true, nil }
	policy := newNetworkPolicy(NetworkOptions{Drivers: NetworkDriverOptions{AllowedDrivers: []string{"bridge"}, Inspect: inspect}})
	req := httptest.NewRequest(http.MethodPost, "/v1.45/networks/app/connect", strings.NewReader(`{"Container":"c1"}`))
	reason, err := policy.inspect(nil, req, NormalizePath(req.URL.Path))
	if err != nil {
		t.Fatalf("inspect error = %v", err)
	}
	if want := `network connect denied: network "app" has driver "", which is not in allowed_drivers`; reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
}

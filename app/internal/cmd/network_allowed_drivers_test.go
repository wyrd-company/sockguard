package cmd

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// networkDriverDaemon is a mock Docker daemon on a unix socket. It answers
// GET /networks/{id} from drivers (an entry of "" is a network with no Driver
// field, a missing entry is a 404), answers failing with a 500, and records
// every request it receives.
type networkDriverDaemon struct {
	mu       sync.Mutex
	drivers  map[string]string
	failing  map[string]bool
	requests []string
}

func (d *networkDriverDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/v1.45")
	d.requests = append(d.requests, r.Method+" "+path)
	if r.Method == http.MethodGet && strings.HasPrefix(path, "/networks/") {
		id, err := url.PathUnescape(strings.TrimPrefix(path, "/networks/"))
		if err != nil || d.failing[id] {
			http.Error(w, "inspect failed", http.StatusInternalServerError)
			return
		}
		driver, ok := d.drivers[id]
		if !ok {
			http.Error(w, "network not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if driver == "" {
			_, _ = fmt.Fprintf(w, `{"Name":%q}`, id)
			return
		}
		_, _ = fmt.Fprintf(w, `{"Name":%q,"Driver":%q}`, id, driver)
		return
	}
	if r.Method == http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"created"}`))
		return
	}
	http.Error(w, "unexpected upstream request", http.StatusNotFound)
}

// seen returns the requests the daemon received, and how many were lookups
// and how many were forwarded writes.
func (d *networkDriverDaemon) seen() (lookups, writes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, r := range d.requests {
		if strings.HasPrefix(r, "GET /networks/") {
			lookups++
		} else if strings.HasPrefix(r, "POST ") {
			writes++
		}
	}
	return lookups, writes
}

// networkDriverNetworks are the mock daemon's existing networks.
var networkDriverNetworks = map[string]string{
	"app":    "bridge",
	"lan":    "macvlan",
	"HOST":   "host",
	"remote": "overlay",
	"blank":  "",
}

// newNetworkDriverChain loads networkYAML (the indented body of
// request_body.network) through config.LoadBytes, builds the production
// serve handler chain against a mock daemon, and returns both. extraYAML is
// appended at the top level.
func newNetworkDriverChain(t *testing.T, networkYAML, extraYAML string, failing ...string) (http.Handler, *networkDriverDaemon) {
	t.Helper()
	socketPath := shortSocketPath(t, "net-drv")
	_ = os.Remove(socketPath)
	daemon := &networkDriverDaemon{drivers: networkDriverNetworks, failing: map[string]bool{}}
	for _, id := range failing {
		daemon.failing[id] = true
	}
	startUnixHTTPUpstream(t, socketPath, daemon)

	yaml := fmt.Sprintf(`upstream:
  socket: %s
health:
  enabled: false
log:
  access_log: false
response:
  deny_verbosity: verbose
rules:
  - match: { method: POST, path: "/networks/create" }
    action: allow
  - match: { method: POST, path: "/networks/*/connect" }
    action: allow
  - match: { method: POST, path: "/containers/create" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
request_body:
  network:
%s
%s`, socketPath, networkYAML, extraYAML)
	cfg, err := config.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v\n%s", err, yaml)
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return buildServeHandler(t, cfg, newDiscardLogger(), nil, rules, newServeTestDeps()), daemon
}

const (
	networkDriversUnset  = "    allow_attachable: false"
	networkDriversBridge = "    allowed_drivers: [bridge]"
)

func serveNetworkDriverRequest(handler http.Handler, remoteAddr, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1.45"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// assertNetworkDriverDenied checks a 403 whose body carries wantReason and
// that the daemon saw no forwarded write.
func assertNetworkDriverDenied(t *testing.T, rec *httptest.ResponseRecorder, daemon *networkDriverDaemon, wantReason string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), wantReason) {
		t.Fatalf("body = %s, want reason containing %q", rec.Body.String(), wantReason)
	}
	if _, writes := daemon.seen(); writes != 0 {
		t.Fatalf("daemon saw %d forwarded writes, want 0", writes)
	}
}

func assertNetworkDriverForwarded(t *testing.T, rec *httptest.ResponseRecorder, daemon *networkDriverDaemon) {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	if _, writes := daemon.seen(); writes != 1 {
		t.Fatalf("daemon saw %d forwarded writes, want 1", writes)
	}
}

// TestNetworkAllowedDriversUnsetChecksNothing pins the upstream behavior: with
// allowed_drivers unset, a macvlan create and an attach to a macvlan network
// are forwarded and no network lookup is made.
func TestNetworkAllowedDriversUnsetChecksNothing(t *testing.T) {
	cases := map[string][2]string{
		"create macvlan":       {"/networks/create", `{"Name":"x","Driver":"macvlan"}`},
		"create NetworkMode":   {"/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"lan"}}`},
		"create EndpointsConf": {"/containers/create", `{"Image":"alpine","NetworkingConfig":{"EndpointsConfig":{"lan":{}}}}`},
		"connect":              {"/networks/lan/connect", `{"Container":"c1"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handler, daemon := newNetworkDriverChain(t, networkDriversUnset, "")
			assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", tc[0], tc[1]), daemon)
			if lookups, _ := daemon.seen(); lookups != 0 {
				t.Fatalf("daemon saw %d network lookups, want 0", lookups)
			}
		})
	}
}

// TestNetworkAllowedDriversDeniesCreateWithDriverNotListed: the deny reason
// names the driver, and nothing reaches the daemon.
func TestNetworkAllowedDriversDeniesCreateWithDriverNotListed(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x","Driver":"macvlan"}`), daemon,
		`network create denied: network driver \"macvlan\" is not in allowed_drivers`)
}

// TestNetworkAllowedDriversAdmitsListedDriver: a listed driver, in any case,
// is forwarded.
func TestNetworkAllowedDriversAdmitsListedDriver(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x","Driver":"Bridge"}`), daemon)
}

// TestNetworkAllowedDriversKeepsCustomDriverGate: listing a custom driver does
// not lift allow_custom_drivers.
func TestNetworkAllowedDriversKeepsCustomDriverGate(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, "    allowed_drivers: [weave]", "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x","Driver":"weave"}`), daemon,
		`network create denied: driver \"weave\" is not allowed`)
	handler, daemon = newNetworkDriverChain(t, "    allowed_drivers: [weave]\n    allow_custom_drivers: true", "")
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x","Driver":"weave"}`), daemon)
}

// TestNetworkAllowedDriversEmptyDriverIsBridge: an empty Driver is admitted by
// [bridge] and denied, as "bridge", by a list without it.
func TestNetworkAllowedDriversEmptyDriverIsBridge(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x"}`), daemon)

	handler, daemon = newNetworkDriverChain(t, "    allowed_drivers: [overlay]\n    allow_swarm_scope: true", "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/create", `{"Name":"x","Driver":""}`), daemon,
		`network driver \"bridge\" is not in allowed_drivers`)
}

// TestNetworkAllowedDriversDeniesNetworkModeAttach: a container create whose
// NetworkMode names an existing macvlan network is denied after a lookup; one
// naming a bridge network is forwarded.
func TestNetworkAllowedDriversDeniesNetworkModeAttach(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"lan"}}`), daemon,
		`container create denied: network \"lan\" has driver \"macvlan\", which is not in allowed_drivers`)
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"app"}}`), daemon)
}

// TestNetworkAllowedDriversDeniesEndpointsConfigAttach: every EndpointsConfig
// key is looked up.
func TestNetworkAllowedDriversDeniesEndpointsConfigAttach(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create",
		`{"Image":"alpine","HostConfig":{"NetworkMode":"app"},"NetworkingConfig":{"EndpointsConfig":{"app":{},"lan":{}}}}`), daemon,
		`network \"lan\" has driver \"macvlan\"`)
}

// TestNetworkAllowedDriversDeniesEndpointNetworkID: dockerd prefers an
// endpoint's NetworkID over its key for a user-defined network, so the
// NetworkID is looked up too.
func TestNetworkAllowedDriversDeniesEndpointNetworkID(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create",
		`{"Image":"alpine","HostConfig":{"NetworkMode":"app"},"NetworkingConfig":{"EndpointsConfig":{"app":{"NetworkID":"lan"}}}}`), daemon,
		`network \"lan\" has driver \"macvlan\"`)
}

// TestNetworkAllowedDriversDeniesConnect: the connect path network is looked
// up, and so is a body EndpointConfig.NetworkID.
func TestNetworkAllowedDriversDeniesConnect(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/lan/connect", `{"Container":"c1"}`), daemon,
		`network connect denied: network \"lan\" has driver \"macvlan\"`)
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/app/connect", `{"Container":"c1","EndpointConfig":{"NetworkID":"lan"}}`), daemon,
		`network connect denied: network \"lan\" has driver \"macvlan\"`)
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/lan/connect", ``), daemon,
		`network connect denied: network \"lan\" has driver \"macvlan\"`)
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/networks/app/connect", `{"Container":"c1"}`), daemon)
}

// TestNetworkAllowedDriversFailsClosed: a failed lookup, an unknown network
// and an inspect answer without a Driver all deny.
func TestNetworkAllowedDriversFailsClosed(t *testing.T) {
	cases := map[string][2]string{
		"lookup failed":   {"app", `network connect denied: network \"app\" driver lookup failed`},
		"not found":       {"missing", `network connect denied: network \"missing\" not found for driver check`},
		"no Driver field": {"blank", `network connect denied: network \"blank\" driver lookup failed`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "", "app")
			assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/networks/"+tc[0]+"/connect", `{"Container":"c1"}`), daemon, tc[1])
		})
	}
}

// TestNetworkAllowedDriversNetworkModeNamespaceModes: "" and "default" are
// checked as bridge without a lookup; "none" is not a network; "host" stays
// under allow_host_network; "HOST" is a network name to dockerd and is looked
// up when allow_host_network lets it past the host rule, which folds case.
func TestNetworkAllowedDriversNetworkModeNamespaceModes(t *testing.T) {
	for _, mode := range []string{"", "default", "none"} {
		t.Run("forwarded "+mode, func(t *testing.T) {
			handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
			assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"`+mode+`"}}`), daemon)
			if lookups, _ := daemon.seen(); lookups != 0 {
				t.Fatalf("daemon saw %d network lookups, want 0", lookups)
			}
		})
	}
	t.Run("default without bridge", func(t *testing.T) {
		handler, daemon := newNetworkDriverChain(t, "    allowed_drivers: [macvlan]", "")
		assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine"}`), daemon,
			`container create denied: default network driver \"bridge\" is not in allowed_drivers`)
	})
	t.Run("host", func(t *testing.T) {
		handler, daemon := newNetworkDriverChain(t, networkDriversBridge, "")
		assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`), daemon,
			"container create denied: host network mode is not allowed")
	})
	t.Run("HOST", func(t *testing.T) {
		// allow_host_network lets "HOST" past the case-folding host rule, so
		// only the driver check can deny it.
		handler, daemon := newNetworkDriverChain(t, networkDriversBridge+"\n  container_create:\n    allow_host_network: true", "")
		assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, "", "/containers/create", `{"Image":"alpine","HostConfig":{"NetworkMode":"HOST"}}`), daemon,
			`network \"HOST\" has driver \"host\"`)
	})
}

// TestNetworkAllowedDriversIsScopedToItsClientProfile: a profile that sets
// allowed_drivers applies it to its own clients only.
func TestNetworkAllowedDriversIsScopedToItsClientProfile(t *testing.T) {
	handler, daemon := newNetworkDriverChain(t, networkDriversUnset, `clients:
  source_ip_profiles:
    - profile: workspaces
      cidrs: ["192.0.2.0/24"]
  profiles:
    - name: workspaces
      rules:
        - match: { method: POST, path: "/containers/create" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
      request_body:
        network:
          allowed_drivers: [bridge]
`)
	const assigned, unassigned = "192.0.2.10:4000", "198.51.100.10:4000"
	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"lan"}}`
	assertNetworkDriverDenied(t, serveNetworkDriverRequest(handler, assigned, "/containers/create", body), daemon,
		`container create denied: network \"lan\" has driver \"macvlan\"`)
	if lookups, _ := daemon.seen(); lookups != 1 {
		t.Fatalf("daemon saw %d network lookups, want 1", lookups)
	}
	assertNetworkDriverForwarded(t, serveNetworkDriverRequest(handler, unassigned, "/containers/create", body), daemon)
}

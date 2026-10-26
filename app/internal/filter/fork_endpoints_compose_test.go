// relationships:
//
//	references: [../../../docs/fork-endpoints]
package filter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Candidate Compose contract only; no deployed Menagerie policy is supplied.
// Bodies follow the shapes devcontainer-builder 0.2.0 pkg/host/dockercompose
// sends (network.go, volume.go, object_state.go, spawn.go).
var forkComposeRoutes = [][2]string{
	{"HEAD", "/_ping"}, {"GET", "/containers/json"}, {"GET", "/containers/*/json"},
	{"GET", "/images/**/json"}, {"POST", "/containers/create"}, {"POST", "/containers/*/start"},
	{"POST", "/containers/*/stop"}, {"DELETE", "/containers/*"},
	{"GET", "/networks"}, {"POST", "/networks/create"}, {"DELETE", "/networks/*"},
	{"GET", "/volumes"}, {"POST", "/volumes/create"}, {"DELETE", "/volumes/*"},
}

// Broad grants a reader might reach for instead of the narrow rows above.
var forkComposeBroadRoutes = [][2]string{{"*", "/networks/**"}, {"*", "/volumes/**"}}

const (
	forkComposeLabels  = `"Labels":{"com.docker.compose.project":"sample","com.docker.compose.version":"2.0.0"}`
	forkComposeNetwork = `{"Name":"sample_back","Driver":"","Internal":false,"Attachable":false,` + forkComposeLabels + `}`
	forkComposeVolume  = `{"Name":"sample_data","Driver":"",` + forkComposeLabels + `}`
	forkComposeObjects = "/srv/sample-objects"
)

// forkComposeSidecar is a non-primary service create. replace swaps one
// fragment of the valid control so each negative differs in one field.
func forkComposeSidecar(old, replacement string) string {
	body := `{"Image":"busybox",` + forkComposeLabels + `,` +
		`"HostConfig":{"Binds":["sample_data:/data"],"Mounts":[{"Type":"bind","Source":"` +
		forkComposeObjects + `/objects-1/probecfg","Target":"/etc/probe.conf","ReadOnly":true}],"NetworkMode":""},` +
		`"NetworkingConfig":{"EndpointsConfig":{"sample_back":{"Aliases":["side"]}}}}`
	if old == "" {
		return body
	}
	if !strings.Contains(body, old) {
		panic("fork compose fixture: fragment not found: " + old)
	}
	return strings.Replace(body, old, replacement, 1)
}

func forkComposeHandler(t *testing.T, routes [][2]string) func(method, path, body string) (int, bool) {
	t.Helper()
	var rules []*CompiledRule
	for _, route := range routes {
		rule, err := CompileRule(Rule{Methods: []string{route[0]}, Pattern: route[1], Action: ActionAllow})
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	opts := Options{PolicyConfig: PolicyConfig{
		ContainerCreate: ContainerCreateOptions{AllowedBindMounts: []string{forkComposeObjects}},
		ContainerRemove: ContainerRemoveOptions{AllowForce: true},
	}}
	return func(method, path, body string) (int, bool) {
		reached := false
		handler := MiddlewareWithOptions(rules, testLogger(), opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusNoContent)
		}))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, path, strings.NewReader(body)))
		return response.Code, reached
	}
}

func TestForkEndpointsComposeCandidatePolicy(t *testing.T) {
	serve := forkComposeHandler(t, forkComposeRoutes)
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		// Up: ensureNetworks, ensureVolumes, allocateObjects, bringUp.
		{"network list by name", "GET", `/v1.51/networks?filters={"name":{"sample_back":true}}`, "", 204},
		{"network create", "POST", "/v1.51/networks/create", forkComposeNetwork, 204},
		{"volume list by name", "GET", `/v1.51/volumes?filters={"name":{"sample_data":true}}`, "", 204},
		{"volume create", "POST", "/v1.51/volumes/create", forkComposeVolume, 204},
		{"object ledger volume create", "POST", "/v1.51/volumes/create",
			`{"Name":"dcb-objects-1","Labels":{"devcontainer.compose.objects":"` + forkComposeObjects + `/objects-1"}}`, 204},
		{"sidecar create", "POST", "/v1.51/containers/create?name=sample-side-1", forkComposeSidecar("", ""), 204},
		{"project container list", "GET", `/v1.51/containers/json?all=1&filters={"label":{"com.docker.compose.project=sample":true}}`, "", 204},
		// Up removeRetiredObjects and Remove teardown.
		{"volume remove", "DELETE", "/v1.51/volumes/dcb-objects-1?force=1", "", 204},
		{"network remove", "DELETE", "/v1.51/networks/sample_back", "", 204},
		{"container remove", "DELETE", "/v1.51/containers/sample?force=1", "", 204},

		// One field differs from the valid control in each row.
		{"network attachable", "POST", "/networks/create", strings.Replace(forkComposeNetwork, `"Attachable":false`, `"Attachable":true`, 1), 403},
		{"network driver opts", "POST", "/networks/create", strings.Replace(forkComposeNetwork, `"Driver":""`, `"Driver":"","Options":{"com.docker.network.bridge.name":"br0"}`, 1), 403},
		{"network custom driver", "POST", "/networks/create", strings.Replace(forkComposeNetwork, `"Driver":""`, `"Driver":"sample/plugin:latest"`, 1), 403},
		{"volume driver opts", "POST", "/volumes/create", strings.Replace(forkComposeVolume, `"Driver":""`, `"Driver":"local","DriverOpts":{"type":"tmpfs","device":"tmpfs","o":"size=64m"}`, 1), 403},
		// Denied twice: by the driver-opts gate and by the bind-device check.
		{"volume bind device", "POST", "/volumes/create", strings.Replace(forkComposeVolume, `"Driver":""`, `"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/etc"}`, 1), 403},
		{"sidecar extra_hosts", "POST", "/containers/create", forkComposeSidecar(`"NetworkMode":""`, `"NetworkMode":"","ExtraHosts":["sample:192.0.2.1"]`), 403},
		{"sidecar group_add", "POST", "/containers/create", forkComposeSidecar(`"NetworkMode":""`, `"NetworkMode":"","GroupAdd":["sample"]`), 403},
		{"sidecar privileged", "POST", "/containers/create", forkComposeSidecar(`"NetworkMode":""`, `"NetworkMode":"","Privileged":true`), 403},
		{"sidecar ipv4_address", "POST", "/containers/create", forkComposeSidecar(`"Aliases":["side"]`, `"Aliases":["side"],"IPAMConfig":{"IPv4Address":"192.0.2.10"}`), 403},
		{"sidecar mac_address", "POST", "/containers/create", forkComposeSidecar(`"Aliases":["side"]`, `"Aliases":["side"],"MacAddress":"02:42:ac:11:00:02"`), 403},
		{"sidecar bind outside objects root", "POST", "/containers/create", forkComposeSidecar(forkComposeObjects+`/objects-1/probecfg`, `/etc/shadow`), 403},
		// Watch (not called by Menagerie): restart and archive sync stay denied.
		{"watch restart", "POST", "/containers/sample/restart?t=10", "", 403},
		{"watch sync archive", "PUT", "/containers/sample/archive?path=/workspace", "archive", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, reached := serve(tc.method, tc.path, tc.body)
			if status != tc.want || reached != (tc.want == http.StatusNoContent) {
				t.Fatalf("status=%d reached=%t; want status=%d", status, reached, tc.want)
			}
		})
	}
}

// Broad /networks/** and /volumes/** grants admit routes devcontainer-builder
// never calls; the narrow rows deny them.
func TestForkEndpointsComposeBroadGrantsWiden(t *testing.T) {
	narrow := forkComposeHandler(t, forkComposeRoutes)
	broad := forkComposeHandler(t, append(append([][2]string{}, forkComposeRoutes...), forkComposeBroadRoutes...))
	for _, tc := range []struct{ method, path, body string }{
		{"POST", "/networks/sample_back/connect", `{"Container":"unrelated"}`},
		{"POST", "/networks/sample_back/disconnect", `{"Container":"unrelated"}`},
		{"POST", "/networks/prune", ""},
		{"POST", "/volumes/prune", ""},
		{"GET", "/volumes/sample_data", ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			if status, reached := narrow(tc.method, tc.path, tc.body); status != http.StatusForbidden || reached {
				t.Fatalf("narrow: status=%d reached=%t; want 403", status, reached)
			}
			if status, reached := broad(tc.method, tc.path, tc.body); status != http.StatusNoContent || !reached {
				t.Fatalf("broad: status=%d reached=%t; want admitted", status, reached)
			}
		})
	}
}

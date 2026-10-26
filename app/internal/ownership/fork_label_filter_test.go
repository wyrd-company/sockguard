package ownership

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/dockerfilters"
	"github.com/codeswhat/sockguard/app/internal/visibility"
)

const forkTestOwner = "sample-owner"

// forkTestResource is one container or volume the fake daemon holds.
type forkTestResource struct {
	name   string
	volume bool
	labels map[string]string
}

// forkTestResources holds two workspaces under one owner, plus a resource of
// another owner that carries the first workspace's labels.
var forkTestResources = []forkTestResource{
	{"alpha-app", false, map[string]string{
		ownerLabelForTest:              "sample-owner",
		"devcontainer.local_folder":    "/srv/alpha",
		"devcontainer.compose.primary": "true",
		"com.docker.compose.project":   "alpha",
		"com.docker.compose.service":   "app",
	}},
	{"alpha-side", false, map[string]string{
		ownerLabelForTest:            "sample-owner",
		"devcontainer.local_folder":  "/srv/alpha",
		"com.docker.compose.project": "alpha",
		"com.docker.compose.service": "side",
	}},
	{"alpha-records", true, map[string]string{
		ownerLabelForTest:              "sample-owner",
		"devcontainer.local_folder":    "/srv/alpha",
		"devcontainer.compose.objects": "1",
	}},
	{"beta-app", false, map[string]string{
		ownerLabelForTest:              "sample-owner",
		"devcontainer.local_folder":    "/srv/beta",
		"devcontainer.compose.primary": "true",
		"com.docker.compose.project":   "beta",
		"com.docker.compose.service":   "app",
	}},
	{"beta-side", false, map[string]string{
		ownerLabelForTest:            "sample-owner",
		"devcontainer.local_folder":  "/srv/beta",
		"com.docker.compose.project": "beta",
		"com.docker.compose.service": "side",
	}},
	{"beta-records", true, map[string]string{
		ownerLabelForTest:              "sample-owner",
		"devcontainer.local_folder":    "/srv/beta",
		"devcontainer.compose.objects": "1",
	}},
	{"gamma-single", false, map[string]string{
		ownerLabelForTest:           "sample-owner",
		"devcontainer.local_folder": "/srv/gamma",
	}},
	{"other-owner-alpha", false, map[string]string{
		ownerLabelForTest:              "other-owner",
		"devcontainer.local_folder":    "/srv/alpha",
		"devcontainer.compose.primary": "true",
		"com.docker.compose.project":   "alpha",
		"com.docker.compose.service":   "app",
	}},
}

// forkTestMatchLabels is Docker's api/types/filters.Args.MatchKVList: every
// value must match, a bare key matches any value of that label.
func forkTestMatchLabels(values []string, labels map[string]string) bool {
	for _, value := range values {
		key, want, hasValue := strings.Cut(value, "=")
		got, ok := labels[key]
		if !ok || hasValue && got != want {
			return false
		}
	}
	return true
}

// forkTestList sends one GET through visibility and ownership to a fake daemon
// that applies the forwarded `label` filter to forkTestResources, and returns
// the matched names and the forwarded `label` values.
func forkTestList(t *testing.T, target string, visOpts visibility.Options) (names, forwarded []string) {
	t.Helper()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filters, err := dockerfilters.Decode(r.URL.Query().Get("filters"))
		if err != nil {
			t.Errorf("fake daemon cannot decode forwarded filters: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		forwarded = filters["label"]
		volumes := strings.HasSuffix(r.URL.Path, "/volumes") || strings.HasSuffix(r.URL.Path, "/volumes/json")
		for _, resource := range forkTestResources {
			if resource.volume == volumes && forkTestMatchLabels(forwarded, resource.labels) {
				names = append(names, resource.name)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	})
	inner := middlewareWithDeps(testLogger(), Options{Owner: forkTestOwner}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)
	handler := visibility.Middleware("", testLogger(), visOpts)(inner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200; body: %s", target, rec.Code, rec.Body.String())
	}
	return names, forwarded
}

func forkTestQuery(path, filter string) string {
	return path + "?all=1&filters=" + url.QueryEscape(filter)
}

// TestForkOwnershipDCBLookupsStayInTheirWorkspace: with one owner for every
// workspace, each devcontainer-builder 0.2.0 lookup returns only the
// requested workspace's resources. The filters are the legacy map shape DCB
// sends (see TestForkEndpointsDCBLabelLookupsKeepClientLabels).
func TestForkOwnershipDCBLookupsStayInTheirWorkspace(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, filter string
		want               []string
	}{
		// pkg/host/docker/spawn.go findLabeled (single-container path)
		{"single container alpha", "/v1.51/containers/json",
			`{"label":{"devcontainer.local_folder=/srv/alpha":true}}`,
			[]string{"alpha-app", "alpha-side"}},
		{"single container gamma", "/v1.51/containers/json",
			`{"label":{"devcontainer.local_folder=/srv/gamma":true}}`,
			[]string{"gamma-single"}},
		// pkg/host/dockercompose/existing.go FindExisting
		{"compose service alpha side", "/v1.51/containers/json",
			`{"label":{"com.docker.compose.project=alpha":true,"com.docker.compose.service=side":true}}`,
			[]string{"alpha-side"}},
		{"compose service beta app", "/v1.51/containers/json",
			`{"label":{"com.docker.compose.project=beta":true,"com.docker.compose.service=app":true}}`,
			[]string{"beta-app"}},
		// pkg/host/dockercompose/manage.go findPrimary
		{"compose primary beta", "/v1.51/containers/json",
			`{"label":{"devcontainer.local_folder=/srv/beta":true,"devcontainer.compose.primary=true":true}}`,
			[]string{"beta-app"}},
		// pkg/host/dockercompose/object_state.go objectRecords
		{"object records alpha", "/v1.51/volumes",
			`{"label":{"devcontainer.compose.objects":true,"devcontainer.local_folder=/srv/alpha":true}}`,
			[]string{"alpha-records"}},
		// The modern array shape selects the same resources.
		{"compose primary alpha, array shape", "/v1.51/containers/json",
			`{"label":["devcontainer.local_folder=/srv/alpha","devcontainer.compose.primary=true"]}`,
			[]string{"alpha-app"}},
		// A false legacy entry is not a filter (dockerfilters.Decode).
		{"false legacy entry is not a filter", "/v1.51/containers/json",
			`{"label":{"devcontainer.local_folder=/srv/gamma":true,"devcontainer.local_folder=/srv/beta":false}}`,
			[]string{"gamma-single"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			names, forwarded := forkTestList(t, forkTestQuery(tc.path, tc.filter), visibility.Options{})
			if !slices.Equal(names, tc.want) {
				t.Fatalf("lookup returned %v, want %v (forwarded label filter %v)", names, tc.want, forwarded)
			}
			if !slices.Contains(forwarded, ownerLabelForTest+"="+forkTestOwner) {
				t.Fatalf("forwarded label filter %v lacks the owner label", forwarded)
			}
		})
	}
}

// TestForkOwnershipClientOwnerKeyNeverWidens: a client value that names the
// owner label key is dropped in every spelling and both filter shapes, so the
// lookup still returns only the proxy owner's resources.
func TestForkOwnershipClientOwnerKeyNeverWidens(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		ownerLabelForTest + "=other-owner",
		ownerLabelForTest,
		ownerLabelForTest + "!=" + forkTestOwner,
		" " + ownerLabelForTest + " =other-owner",
		ownerLabelForTest + " !=" + forkTestOwner,
	} {
		encodedValue, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for shape, filter := range map[string]string{
			"array":  `{"label":["devcontainer.local_folder=/srv/alpha",` + string(encodedValue) + `]}`,
			"legacy": `{"label":{"devcontainer.local_folder=/srv/alpha":true,` + string(encodedValue) + `:true}}`,
		} {
			t.Run(shape+" "+value, func(t *testing.T) {
				t.Parallel()
				names, forwarded := forkTestList(t, forkTestQuery("/v1.51/containers/json", filter), visibility.Options{})
				want := []string{ownerLabelForTest + "=" + forkTestOwner, "devcontainer.local_folder=/srv/alpha"}
				if !slices.Equal(forwarded, want) {
					t.Fatalf("forwarded label filter = %q, want %q", forwarded, want)
				}
				if slices.Contains(names, "other-owner-alpha") {
					t.Fatalf("lookup returned another owner's container: %v", names)
				}
			})
		}
	}
}

// TestForkOwnershipKeepsClientLabelsOnEngineLists pins the endpoint scope:
// every in-scope list forwards the client value with the owner label.
func TestForkOwnershipKeepsClientLabelsOnEngineLists(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/v1.51/containers/json", "/v1.51/images/json", "/v1.51/networks", "/v1.51/volumes",
		"/libpod/containers/json", "/libpod/images/json", "/libpod/pods/json",
		"/libpod/networks/json", "/libpod/volumes/json",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, path+"?filters="+url.QueryEscape(`{"label":["tier=dev"]}`), Options{Owner: forkTestOwner}, visibility.Options{})
			assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=" + forkTestOwner, "tier=dev"})
		})
	}
}

// TestForkOwnershipSwarmListsAndEventsKeepTheDrop: Swarm lists and event
// streams forward exactly the owner selector, as upstream does.
func TestForkOwnershipSwarmListsAndEventsKeepTheDrop(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ path, key string }{
		{"/v1.51/services", "label"},
		{"/v1.51/tasks", "label"},
		{"/v1.51/secrets", "label"},
		{"/v1.51/configs", "label"},
		{"/v1.51/nodes", "node.label"},
		{"/v1.51/events", "label"},
		{"/libpod/events", "label"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			filter := `{"` + tc.key + `":["tier=dev"]}`
			got := forwardedFilters(t, tc.path+"?filters="+url.QueryEscape(filter), Options{Owner: forkTestOwner}, visibility.Options{})
			assertFilterValues(t, got, tc.key, []string{ownerLabelForTest + "=" + forkTestOwner})
		})
	}
}

// TestForkOwnershipKeptClientLabelsComposeWithVisibility: visibility selectors
// survive, and a client value equal to one is forwarded once.
func TestForkOwnershipKeptClientLabelsComposeWithVisibility(t *testing.T) {
	t.Parallel()
	_, forwarded := forkTestList(t,
		forkTestQuery("/v1.51/containers/json", `{"label":["tier=prod","devcontainer.local_folder=/srv/alpha"]}`),
		visibility.Options{VisibleResourceLabels: []string{"tier=prod"}},
	)
	want := []string{ownerLabelForTest + "=" + forkTestOwner, "tier=prod", "devcontainer.local_folder=/srv/alpha"}
	if !slices.Equal(forwarded, want) {
		t.Fatalf("forwarded label filter = %q, want %q", forwarded, want)
	}
}

// TestForkOwnershipMalformedFiltersFailClosed: an in-scope list with a filter
// the decoder rejects is refused with 400 and never reaches the daemon.
func TestForkOwnershipMalformedFiltersFailClosed(t *testing.T) {
	t.Parallel()
	for name, filter := range map[string]string{
		"bad json":            `{"label":`,
		"non-string element":  `{"label":["devcontainer.local_folder=/srv/alpha",1]}`,
		"non-bool legacy":     `{"label":{"devcontainer.local_folder=/srv/alpha":"yes"}}`,
		"scalar filter value": `{"label":"devcontainer.local_folder=/srv/alpha"}`,
		"oversized":           `{"label":["` + strings.Repeat("a", dockerfilters.MaxEncodedBytes) + `"]}`,
	} {
		for _, path := range []string{"/v1.51/containers/json", "/v1.51/volumes", "/libpod/containers/json"} {
			t.Run(name+" "+path, func(t *testing.T) {
				t.Parallel()
				reached := false
				upstream := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached = true
					w.WriteHeader(http.StatusOK)
				})
				handler := middlewareWithDeps(testLogger(), Options{Owner: forkTestOwner}, fakeInspector{}.inspectResource, fakeInspector{}.inspectExec)(upstream)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+"?filters="+url.QueryEscape(filter), nil))
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
				}
				if reached {
					t.Fatal("malformed filter reached the daemon")
				}
			})
		}
	}
}

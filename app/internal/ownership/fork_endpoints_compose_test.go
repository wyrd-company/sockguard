// relationships:
//
//	references: [../../../docs/fork-endpoints]
package ownership

import (
	"net/url"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/visibility"
)

// TestForkEndpointsDCBLabelLookupsKeepClientLabels pins that, with ownership
// on, the label selectors devcontainer-builder 0.2.0 uses to find a
// workspace's containers and object records reach the daemon with the owner
// label. DCB does not re-check labels on the result, so the daemon-side AND is
// its only workspace scope. See fork_label_filter.go.
func TestForkEndpointsDCBLabelLookupsKeepClientLabels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, path, filter string
		client             []string
	}{
		// pkg/host/dockercompose/existing.go FindExisting
		{"compose service", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"com.docker.compose.project=sample":true,"com.docker.compose.service=side":true}}`,
			[]string{"com.docker.compose.project=sample", "com.docker.compose.service=side"}},
		// pkg/host/dockercompose/manage.go findPrimary
		{"compose primary", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"devcontainer.local_folder=/srv/sample":true,"devcontainer.compose.primary=true":true}}`,
			[]string{"devcontainer.local_folder=/srv/sample", "devcontainer.compose.primary=true"}},
		// pkg/host/docker/spawn.go findExisting via findLabeled (single-container path)
		{"single container", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"devcontainer.local_folder=/srv/sample":true}}`,
			[]string{"devcontainer.local_folder=/srv/sample"}},
		// pkg/host/dockercompose/object_state.go objectRecords
		{"object records", "/v1.51/volumes?filters=",
			`{"label":{"devcontainer.compose.objects":true,"devcontainer.local_folder=/srv/sample":true}}`,
			[]string{"devcontainer.compose.objects", "devcontainer.local_folder=/srv/sample"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, tc.path+url.QueryEscape(tc.filter), Options{Owner: "sample-owner"}, visibility.Options{})
			assertFilterValues(t, got, "label", append([]string{ownerLabelForTest + "=sample-owner"}, tc.client...))
		})
	}
}

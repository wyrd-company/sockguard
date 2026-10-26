// relationships:
//
//	references: [../../../docs/fork-endpoints]
package ownership

import (
	"net/url"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/visibility"
)

// TestForkEndpointsDCBLabelLookupsLoseClientLabels pins an incompatibility,
// not a requirement: with ownership on, the label selectors that
// devcontainer-builder 0.2.0 uses to find a workspace's containers and
// object records do not reach the daemon. Every owned resource matches, and
// DCB does not re-check labels on the result. Update this test when the
// fork's ownership filter or DCB changes.
func TestForkEndpointsDCBLabelLookupsLoseClientLabels(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, path, filter string }{
		// pkg/host/dockercompose/existing.go FindExisting
		{"compose service", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"com.docker.compose.project=sample":true,"com.docker.compose.service=side":true}}`},
		// pkg/host/dockercompose/manage.go findPrimary
		{"compose primary", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"devcontainer.local_folder=/srv/sample":true,"devcontainer.compose.primary=true":true}}`},
		// pkg/host/docker/spawn.go findExisting via findLabeled (single-container path)
		{"single container", "/v1.51/containers/json?all=1&filters=",
			`{"label":{"devcontainer.local_folder=/srv/sample":true}}`},
		// pkg/host/dockercompose/object_state.go objectRecords
		{"object records", "/v1.51/volumes?filters=",
			`{"label":{"devcontainer.compose.objects":true,"devcontainer.local_folder=/srv/sample":true}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := forwardedFilters(t, tc.path+url.QueryEscape(tc.filter), Options{Owner: "sample-owner"}, visibility.Options{})
			assertFilterValues(t, got, "label", []string{ownerLabelForTest + "=sample-owner"})
		})
	}
}

// relationships:
//
// references: [../../../docs/content/docs/symlink-bind-sources]
package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/dockerresource"
)

// Fork-owned: a named volume's Mounts.Source is its mount point, not the
// host device. Read the volume through the same resolver as container inspect.

// ForkStartRecheckVolume is the part of volume inspect needed by the re-check.
type ForkStartRecheckVolume struct {
	Driver  string            `json:"Driver"`
	Options map[string]string `json:"Options"`
}

// ForkStartRecheckVolumeInspectFunc reads a named volume from the daemon.
type ForkStartRecheckVolumeInspectFunc func(context.Context, string) (ForkStartRecheckVolume, error)

// NewForkStartRecheckVolumeInspectorWithRoundTripper uses the shared upstream
// transport and its existing timeouts, including for libpod starts.
func NewForkStartRecheckVolumeInspectorWithRoundTripper(rt http.RoundTripper) ForkStartRecheckVolumeInspectFunc {
	client := &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, name string) (ForkStartRecheckVolume, error) {
		target, _ := dockerresource.InspectPath(dockerresource.KindVolume, name)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+target, nil) // #nosec G704 -- the injected resolver targets the engine; InspectPath escapes the identifier.
		if err != nil {
			return ForkStartRecheckVolume{}, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected resolver selects the upstream, not the URL host.
		if err != nil {
			return ForkStartRecheckVolume{}, err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return ForkStartRecheckVolume{}, fmt.Errorf("volume inspect status %d", resp.StatusCode)
		}
		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return ForkStartRecheckVolume{}, err
		}
		var volume ForkStartRecheckVolume
		if err := json.Unmarshal(body, &volume); err != nil {
			return ForkStartRecheckVolume{}, err
		}
		if strings.TrimSpace(volume.Driver) == "" {
			return ForkStartRecheckVolume{}, fmt.Errorf("volume inspect missing driver")
		}
		return volume, nil
	}
}

type forkStartRecheckVolumes struct {
	sources []forkStartRecheckSource
	mounts  []WorkspaceExceptionMount
}

func (p forkStartRecheckPolicy) volumeSources(ctx context.Context, subject string, container ForkStartRecheckContainer) (forkStartRecheckVolumes, error) {
	var out forkStartRecheckVolumes
	for _, mount := range container.Mounts {
		if !strings.EqualFold(mount.Type, "volume") {
			continue
		}
		failed := func() (forkStartRecheckVolumes, error) {
			return forkStartRecheckVolumes{}, newRequestRejectionErrorWithCode(http.StatusForbidden, forkStartRecheckReasonCodeVolumeFailed,
				fmt.Sprintf("%s denied: volume %q could not be inspected to re-check its bind devices", subject, mount.Name))
		}
		if mount.Name == "" || p.inspectVolume == nil {
			return failed()
		}
		volume, err := p.inspectVolume(ctx, mount.Name)
		if err != nil {
			// Neither dependency errors nor response bodies are logged: driver
			// options may contain credentials, even on a malformed response.
			return failed()
		}
		devices := localVolumeBindDevices(volume.Driver, volume.Options)
		if len(devices) == 0 {
			continue
		}
		out.mounts = append(out.mounts, WorkspaceExceptionMount{Type: "volume", VolumeDriver: volume.Driver, VolumeDriverOptions: volume.Options})
		for _, raw := range devices {
			clean, ok := normalizeBindMount(raw)
			if !ok {
				// A relative device has no admitted spelling under a plain
				// allowlist. Workspace profiles keep create's absolute-path
				// rule, even if the other family's base allowlist holds "/".
				if p.workspace != nil {
					return out, forkStartRecheckWorkspaceDenied(forkStartRecheckReasonCodeOutsideWorkspace,
						fmt.Sprintf("%s denied: bind mount source %q is not an absolute path", subject, raw))
				}
				continue
			}
			out.sources = append(out.sources, forkStartRecheckSource{raw: raw, clean: clean})
		}
	}
	return out, nil
}

// forkStartRecheckMatchRequest keeps named-volume devices as volumes, so they
// participate in bind agreement without becoming a workspace bind mount.
func forkStartRecheckMatchRequest(container ForkStartRecheckContainer, volumes []WorkspaceExceptionMount) WorkspaceExceptionRequest {
	req := WorkspaceExceptionRequest{Mounts: volumes}
	for _, source := range forkStartRecheckSources(container) {
		req.Mounts = append(req.Mounts, WorkspaceExceptionMount{Type: "bind", Source: source.raw})
	}
	return req
}

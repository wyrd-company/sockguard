// relationships:
//
//	references: [../../../docs/fork-endpoints, ../../../docs/content/docs/workspace-exceptions]
package cmd

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

func forkFieldComposeRules() []config.RuleConfig {
	var rules []config.RuleConfig
	for _, route := range [][2]string{{"POST", "/containers/create"}, {"GET", "/containers/json"}, {"GET", "/networks"}, {"POST", "/networks/create"}, {"GET", "/volumes"}, {"POST", "/volumes/create"}, {"DELETE", "/volumes/*"}} {
		rules = append(rules, config.RuleConfig{Match: config.MatchConfig{Method: route[0], Path: route[1]}, Action: "allow"})
	}
	return append(rules, config.RuleConfig{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny", Reason: "candidate route denied"})
}

func TestForkFieldComposePrimaryAndSidecar(t *testing.T) {
	h := newForkFieldChain(t, func(c *config.Config) { c.Rules = forkFieldComposeRules() }, nil)
	h.grants(t, h.f.alpha, map[string]any{"privileged": true})
	for _, primary := range []bool{true, false} {
		name := "sidecar"
		if primary {
			name = "primary"
		}
		t.Run(name, func(t *testing.T) {
			labels := map[string]string{"com.docker.compose.project": "sample", "com.docker.compose.service": name, "com.docker.compose.version": "2.0.0"}
			if primary {
				labels[filter.WorkspaceLocalFolderLabel] = h.f.alpha
			}
			mounts := []any{map[string]any{"Type": "bind", "Source": filepath.Join(h.roots[2], "alpha", "objects-1", "config"), "Target": "/etc/sample.conf", "ReadOnly": true}}
			b := h.create(map[string]any{"Mounts": mounts})
			b["Labels"] = labels
			b["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{"sample_back": map[string]any{"Aliases": []string{name}}}}
			hc := b["HostConfig"].(map[string]any)
			if !primary {
				hc["Binds"] = []string{"sample_data:/data:rw"}
			}
			h.postCreate(t, b, 201, "") // sidecar has no identity label; header scopes it
			hc["Privileged"] = true
			if primary {
				h.postCreate(t, b, 201, "")
			} else {
				// Isolate the workspace-mount guard with an eligible label.
				labels[filter.WorkspaceLocalFolderLabel] = h.f.alpha
				h.postCreate(t, b, 403, "privileged containers are not allowed") // no workspace mount, no extras
				delete(labels, filter.WorkspaceLocalFolderLabel)
				hc["Binds"] = []string{"sample_data:/data:rw", h.f.alpha + ":/workspace:ro"}
				hc["Privileged"] = false
				h.postCreate(t, b, 201, "") // unlabeled sidecar with own-W bind: BASE only
				labels[filter.WorkspaceLocalFolderLabel] = h.f.alpha
				hc["Privileged"] = true
				h.postCreate(t, b, 201, "")
			}
			// A label claim cannot override the workspace header.
			labels[filter.WorkspaceLocalFolderLabel] = h.other
			h.postCreate(t, b, 403, "disagrees with the request's workspace")
			labels[filter.WorkspaceLocalFolderLabel] = h.f.alpha
			h.postCreate(t, b, 201, "")
			// Same label and workspace mount still cannot import another workspace.
			hc["Mounts"] = []any{map[string]any{"Type": "bind", "Source": filepath.Join(h.roots[2], "beta", "config"), "Target": "/etc/sample.conf", "ReadOnly": true}}
			h.postCreate(t, b, 403, "privileged containers are not allowed")
		})
	}
}

func TestForkFieldComposeNetworkVolumeListAndWatchInventory(t *testing.T) {
	h := newForkFieldChain(t, func(c *config.Config) {
		c.Rules = forkFieldComposeRules()
		c.RequestBody.Network.AllowedDrivers = []string{"bridge"}
	}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			if strings.HasSuffix(r.URL.Path, "/volumes") {
				_, _ = io.WriteString(w, `{"Volumes":[],"Warnings":[]}`)
			} else {
				_, _ = io.WriteString(w, `[]`)
			}
			return
		}
		if r.Method == "DELETE" {
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Id":"created"}`)
	})
	headers := http.Header{}
	headers.Set(filter.WorkspaceHeader, h.f.alpha)
	labels := `"Labels":{"com.docker.compose.project":"sample","com.docker.compose.version":"2.0.0"}`
	network := `{"Name":"sample_back","Driver":"bridge","Internal":false,"Attachable":false,` + labels + `}`
	volume := `{"Name":"sample_data","Driver":"local",` + labels + `}`
	filterURI := func(path, filters string) string {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		return path + sep + "filters=" + url.QueryEscape(filters)
	}
	for _, tc := range []struct {
		name, method, uri, body string
		want                    int
		reason                  string
	}{
		{"network_list", "GET", filterURI("/v1.51/networks", `{"name":{"sample_back":true}}`), "", 200, ""},
		{"network_create", "POST", "/v1.51/networks/create", network, 201, ""},
		{"volume_list", "GET", filterURI("/v1.51/volumes", `{"name":{"sample_data":true}}`), "", 200, ""},
		{"object_records", "GET", filterURI("/v1.51/volumes", `{"label":{"devcontainer.compose.objects":true,"devcontainer.local_folder=`+h.f.alpha+`":true}}`), "", 200, ""},
		{"volume_create", "POST", "/v1.51/volumes/create", volume, 201, ""},
		{"object_ledger_create", "POST", "/v1.51/volumes/create", `{"Name":"dcb-objects-1","Labels":{"devcontainer.compose.objects":"` + h.roots[2] + `/alpha/objects-1","devcontainer.local_folder":"` + h.f.alpha + `"}}`, 201, ""},
		{"project_container_list", "GET", filterURI("/v1.51/containers/json?all=1", `{"label":{"com.docker.compose.project=sample":true}}`), "", 200, ""},
		{"object_mount_list", "GET", "/v1.51/containers/json?all=1", "", 200, ""},
		{"retired_object_remove", "DELETE", "/v1.51/volumes/dcb-objects-1?force=1", "", 204, ""},
		{"attachable", "POST", "/networks/create", strings.Replace(network, `"Attachable":false`, `"Attachable":true`, 1), 403, "attachable"},
		{"non_bridge", "POST", "/networks/create", strings.Replace(network, `"bridge"`, `"macvlan"`, 1), 403, "driver"},
		{"network_options", "POST", "/networks/create", strings.Replace(network, `"Driver":"bridge"`, `"Driver":"bridge","Options":{"sample":"value"}`, 1), 403, "driver options"},
		{"volume_options", "POST", "/volumes/create", strings.Replace(volume, `"Driver":"local"`, `"Driver":"local","DriverOpts":{"type":"tmpfs","o":"size=64m","device":"tmpfs"}`, 1), 403, "driver options"},
		{"watch_restart", "POST", "/containers/sample/restart?t=10", "", 403, "candidate route denied"},
		{"podman_rootfs", "POST", "/libpod/containers/create", `{"rootfs":"` + h.outside + `"}`, 403, "candidate route denied"},
		{"podman_init_path", "POST", "/libpod/containers/create", `{"image":"busybox","init":true,"init_path":"` + h.outside + `/init"}`, 403, "candidate route denied"},
		{"podman_start", "POST", "/libpod/containers/sample/start", "", 403, "candidate route denied"},
	} {
		t.Run(tc.name, func(t *testing.T) { h.request(t, tc.method, tc.uri, tc.body, headers, tc.want, tc.reason) })
	}
}

// These are create-time checks, not claims about an inspected container at
// start. The Docker daemon itself rejects Podman's O/upperdir/workdir mode.
func TestForkFieldOverlayDirectoriesDeniedAtCreate(t *testing.T) {
	h := newForkFieldChain(t, nil, nil)
	for _, kind := range []string{"Binds", "Volumes"} {
		for _, option := range []string{"upperdir", "workdir"} {
			t.Run(kind+"/"+option, func(t *testing.T) {
				h.postCreate(t, forkFieldMountBody(h, kind, h.f.alpha), 201, "")
				b := h.create(nil)
				spec := h.f.alpha + ":/data:O," + option + "=" + h.outside
				if kind == "Binds" {
					b["HostConfig"].(map[string]any)["Binds"] = []string{spec}
				} else {
					b["Volumes"] = map[string]any{spec: map[string]any{}}
				}
				h.postCreate(t, b, 403, "overlay option")
			})
		}
	}
}

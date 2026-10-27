// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions, ../../../docs/content/docs/symlink-bind-sources]
package cmd

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

func TestForkFieldRestartGrantNames(t *testing.T) {
	h := newForkFieldChain(t, nil, nil)
	for _, grant := range []string{"none", "same", "other"} {
		t.Run(grant, func(t *testing.T) {
			if err := removeForkFieldPolicy(h); err != nil {
				t.Fatal(err)
			}
			if grant != "none" {
				ws := h.f.alpha
				if grant == "other" {
					ws = h.other
				}
				h.grants(t, ws, map[string]any{"restartPolicy": []string{"on-failure"}})
			}
			for _, name := range []string{"", "no", "on-failure", "always", "unless-stopped"} {
				t.Run("name="+name, func(t *testing.T) {
					want, reason := 201, ""
					if name != "" && name != "no" && !(grant == "same" && name == "on-failure") {
						want, reason = 403, "restart policy"
					}
					h.postCreate(t, h.create(map[string]any{"RestartPolicy": map[string]any{"Name": name, "MaximumRetryCount": 3}}), want, reason)
				})
			}
		})
	}
}

func TestForkFieldWorkspaceIdentityAndGrantMatch(t *testing.T) {
	h := newForkFieldChain(t, func(c *config.Config) {
		// A base-allowlisted external path must still withhold grants when
		// it is not one of this workspace's extraBindSources.
		c.RequestBody.ContainerCreate.AllowedBindMounts = append(c.RequestBody.ContainerCreate.AllowedBindMounts, filepath.Join(filepath.Dir(c.WorkspaceExceptions.WorkspaceRoot), "external"))
	}, nil)
	for _, tc := range []struct {
		name   string
		edit   func(map[string]any, http.Header)
		want   int
		reason string
	}{
		{"header_only", func(b map[string]any, hdr http.Header) {}, 201, ""},
		{"same_label", func(b map[string]any, hdr http.Header) {
			b["Labels"] = map[string]string{filter.WorkspaceLocalFolderLabel: h.f.alpha}
		}, 201, ""},
		{"label_is_not_identity", func(b map[string]any, hdr http.Header) {
			b["Labels"] = map[string]string{filter.WorkspaceLocalFolderLabel: h.f.alpha}
			hdr.Del(filter.WorkspaceHeader)
		}, 403, "the request names no workspace"},
		{"both_headers", func(b map[string]any, hdr http.Header) { hdr.Set(filter.WorkspaceThrowawayHeader, h.f.alpha) }, 403, "more than one workspace"},
		{"repeated_header", func(b map[string]any, hdr http.Header) { hdr.Add(filter.WorkspaceHeader, h.f.alpha) }, 403, "more than one workspace"},
		{"empty_header", func(b map[string]any, hdr http.Header) { hdr.Set(filter.WorkspaceHeader, "") }, 403, "valid workspace"},
		{"noncanonical_header", func(b map[string]any, hdr http.Header) {
			b["HostConfig"].(map[string]any)["Privileged"] = false
			hdr.Set(filter.WorkspaceHeader, h.f.alpha+"/.")
		}, 403, "valid workspace"},
		{"label_mismatch", func(b map[string]any, hdr http.Header) {
			b["Labels"] = map[string]string{filter.WorkspaceLocalFolderLabel: h.other}
		}, 403, "disagrees with the request's workspace"},
		{"opposite_label", func(b map[string]any, hdr http.Header) {
			b["Labels"] = map[string]string{filter.WorkspaceThrowawayLabel: h.f.alpha}
		}, 403, "workspace kind"},
		{"both_labels", func(b map[string]any, hdr http.Header) {
			b["Labels"] = map[string]string{filter.WorkspaceLocalFolderLabel: h.f.alpha, filter.WorkspaceThrowawayLabel: h.f.alpha}
		}, 403, "workspace kind"},
		{"no_workspace_mount", func(b map[string]any, hdr http.Header) { b["HostConfig"].(map[string]any)["Binds"] = []string{} }, 403, "privileged containers are not allowed"},
		{"bind_disagreement", func(b map[string]any, hdr http.Header) {
			b["HostConfig"].(map[string]any)["Binds"] = []string{h.f.alpha + ":/workspace", h.outside + ":/external"}
		}, 403, "privileged containers are not allowed"},
		{"throwaway_never_grants", func(b map[string]any, hdr http.Header) {
			hdr.Del(filter.WorkspaceHeader)
			hdr.Set(filter.WorkspaceThrowawayHeader, h.f.alpha)
		}, 403, "privileged containers are not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.grants(t, h.f.alpha, map[string]any{"privileged": true})
			h.postCreate(t, h.create(map[string]any{"Privileged": true}), 201, "")
			body := h.create(map[string]any{"Privileged": true})
			hdr := http.Header{}
			hdr.Set(filter.WorkspaceHeader, h.f.alpha)
			tc.edit(body, hdr)
			if tc.name == "noncanonical_header" {
				control := hdr.Clone()
				control.Set(filter.WorkspaceHeader, h.f.alpha)
				h.request(t, "POST", "/v1.51/containers/create", forkFieldJSON(t, body), control, 201, "")
			}
			h.request(t, "POST", "/v1.51/containers/create", forkFieldJSON(t, body), hdr, tc.want, tc.reason)
		})
	}
}

func TestForkFieldWorkspaceRootsKeepScopeWithoutExtras(t *testing.T) {
	h := newForkFieldChain(t, nil, nil)
	for _, state := range []string{"matched", "unmatched", "invalid", "missing"} {
		t.Run(state, func(t *testing.T) {
			h.grants(t, h.f.alpha, map[string]any{"privileged": true})
			switch state {
			case "unmatched":
				h.grants(t, h.other, map[string]any{"privileged": true})
			case "invalid":
				if err := os.WriteFile(h.f.file, []byte(`{"version":1,"exceptions":[],"invalid":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
				h.store.Reload()
			case "missing":
				if err := removeForkFieldPolicy(h); err != nil {
					t.Fatal(err)
				}
			}
			for _, root := range h.roots {
				t.Run(filepath.Base(root), func(t *testing.T) {
					own := filepath.Join(root, "alpha")
					b := h.create(map[string]any{"Binds": []string{h.f.alpha + ":/workspace", own + ":/own"}})
					h.postCreate(t, b, 201, "")
					b["HostConfig"].(map[string]any)["Binds"] = []string{h.f.alpha + ":/workspace", filepath.Join(root, "beta") + ":/other"}
					h.postCreate(t, b, 403, "outside this workspace's folder")
					if state == "matched" {
						h.postCreate(t, h.create(map[string]any{"Privileged": true, "Binds": []string{h.f.alpha + ":/workspace", own + ":/own"}}), 201, "")
					} else {
						h.postCreate(t, h.create(map[string]any{"Privileged": true}), 403, "privileged containers are not allowed")
					}
				})
			}
		})
	}
}

func forkFieldMountBody(h *forkFieldChain, kind, source string) map[string]any {
	b := h.create(nil)
	hc := b["HostConfig"].(map[string]any)
	switch kind {
	case "Binds":
		hc["Binds"] = []string{h.f.alpha + ":/workspace", source + ":/data:ro"}
	case "Mounts":
		hc["Mounts"] = []any{map[string]any{"Type": "bind", "Source": source, "Target": "/data", "ReadOnly": true}}
	case "Volumes":
		b["Volumes"] = map[string]any{source + ":/data:ro": map[string]any{}}
	}
	return b
}

func TestForkFieldSymlinkRawCleanedResolvedAndExtraGrant(t *testing.T) {
	h := newForkFieldChain(t, nil, nil)
	inside := filepath.Join(h.f.alpha, "inside")
	outsideChild := filepath.Join(h.outside, "child")
	for _, p := range []string{inside, outsideChild} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(h.f.alpha, "link")
	if err := os.Symlink(outsideChild, link); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"Binds", "Mounts", "Volumes"} {
		t.Run(kind, func(t *testing.T) {
			for _, shape := range []struct{ name, source string }{
				{"resolved_escape", link},
				// Cleaned path is W/inside; kernel resolution of raw link/../inside is external/inside.
				{"raw_dotdot_escape", link + "/../inside"},
				{"cleaned_external", h.f.alpha + "/../../" + filepath.Base(h.outside) + "/child"},
			} {
				t.Run(shape.name, func(t *testing.T) {
					if err := removeForkFieldPolicy(h); err != nil {
						t.Fatal(err)
					}
					h.postCreate(t, forkFieldMountBody(h, kind, inside), 201, "")
					h.postCreate(t, forkFieldMountBody(h, kind, shape.source), 403, "not allowlisted")
					h.grants(t, h.f.alpha, map[string]any{"extraBindSources": []string{h.outside}})
					h.postCreate(t, forkFieldMountBody(h, kind, shape.source), 201, "")
					h.grants(t, h.other, map[string]any{"extraBindSources": []string{h.outside}})
					h.postCreate(t, forkFieldMountBody(h, kind, shape.source), 403, "not allowlisted")
				})
			}
		})
	}
}

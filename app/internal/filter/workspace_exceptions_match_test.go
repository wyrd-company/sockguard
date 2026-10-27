// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// wsCreate is a container create body: Labels, HostConfig and any other
// top-level fields.
type wsCreate struct {
	labels     map[string]string
	hostConfig map[string]any
	top        map[string]any
	// headers are the request headers. Nil derives the workspace header
	// from the identity labels (the label equals the header, as the
	// workspace manager sends it); a non-nil map is sent as it is.
	headers map[string][]string
}

func (c wsCreate) header() http.Header {
	h := http.Header{}
	if c.headers != nil {
		for k, v := range c.headers {
			h[http.CanonicalHeaderKey(k)] = v
		}
		return h
	}
	if w, ok := c.labels[WorkspaceLocalFolderLabel]; ok {
		h.Add(WorkspaceHeader, w)
	}
	if w, ok := c.labels[WorkspaceThrowawayLabel]; ok {
		h.Add(WorkspaceThrowawayHeader, w)
	}
	return h
}

func (c wsCreate) body(t *testing.T) string {
	t.Helper()
	doc := map[string]any{"Image": "busybox"}
	for k, v := range c.top {
		doc[k] = v
	}
	if c.labels != nil {
		doc["Labels"] = c.labels
	}
	if c.hostConfig != nil {
		doc["HostConfig"] = c.hostConfig
	}
	return string(mustJSON(t, doc))
}

// wsRequest is a create for workspace ws that binds ws, with extra
// HostConfig fields.
func wsRequest(ws string, hostConfig map[string]any) wsCreate {
	hc := map[string]any{"Binds": []string{ws + ":/workspaces/project"}}
	for k, v := range hostConfig {
		hc[k] = v
	}
	return wsCreate{labels: map[string]string{WorkspaceLocalFolderLabel: ws}, hostConfig: hc}
}

type wsHarness struct {
	t     *testing.T
	f     workspaceExceptionsFixture
	store *WorkspaceExceptionStore
	logs  *bytes.Buffer
}

func newWSHarness(t *testing.T, entries func(f workspaceExceptionsFixture) []map[string]any) *wsHarness {
	t.Helper()
	f := newWorkspaceExceptionsFixture(t)
	h := &wsHarness{t: t, f: f, logs: &bytes.Buffer{}}
	if entries != nil {
		writeAtomic(t, f.file, mustJSON(t, workspaceDoc(entries(f)...)))
	}
	h.store = newTestWorkspaceStore(t, f, nil)
	return h
}

// options is the base policy: the root, outside and staging folders are
// allowlisted for binds, and the block opts in to exceptions.
func (h *wsHarness) options(edit func(*ContainerCreateOptions)) ContainerCreateOptions {
	opts := ContainerCreateOptions{
		AllowedBindMounts:        []string{h.f.root, h.f.outside, h.f.staging},
		ApplyWorkspaceExceptions: true,
		WorkspaceExceptions:      h.store,
	}
	if edit != nil {
		edit(&opts)
	}
	return opts
}

func (h *wsHarness) inspect(opts ContainerCreateOptions, req wsCreate) string {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(req.body(h.t)))
	r.Header = req.header()
	logger := slog.New(slog.NewJSONHandler(h.logs, nil))
	reason, err := newContainerCreatePolicy(opts).inspectWithWorkspaceExceptions(logger, r, "/containers/create")
	if err != nil {
		h.t.Fatalf("inspect error: %v", err)
	}
	return reason
}

func (h *wsHarness) admit(opts ContainerCreateOptions, req wsCreate) {
	h.t.Helper()
	if reason := h.inspect(opts, req); reason != "" {
		h.t.Fatalf("want admitted, got %q", reason)
	}
}

func (h *wsHarness) deny(opts ContainerCreateOptions, req wsCreate, want ...string) string {
	h.t.Helper()
	reason := h.inspect(opts, req)
	if reason == "" {
		h.t.Fatal("want denied, got admitted")
	}
	for _, w := range want {
		if !strings.Contains(reason, w) {
			h.t.Fatalf("deny reason %q does not contain %q", reason, w)
		}
	}
	return reason
}

func privilegedGrant(f workspaceExceptionsFixture) []map[string]any {
	return []map[string]any{workspaceEntryDoc(f.alpha, map[string]any{"privileged": true})}
}

func TestWorkspaceExceptionAppliesGrantToMatchedWorkspace(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	privileged := map[string]any{"Privileged": true}
	h.admit(h.options(nil), wsRequest(h.f.alpha, privileged))
	// The workspace comes from the header: the label may be absent.
	unlabeled := wsRequest(h.f.alpha, privileged)
	unlabeled.labels = nil
	unlabeled.headers = map[string][]string{WorkspaceHeader: {h.f.alpha}}
	h.admit(h.options(nil), unlabeled)
	// Controls: the base policy denies the request for a workspace without
	// an entry, and the profile denies a create without a header.
	h.deny(h.options(nil), wsRequest(h.f.gamma, privileged), "privileged containers are not allowed")
	headerless := wsRequest(h.f.alpha, privileged)
	headerless.headers = map[string][]string{}
	h.deny(h.options(nil), headerless, "the request names no workspace")
}

// A request for workspace X cannot use workspace Y's exception.
func TestWorkspaceExceptionDoesNotCrossWorkspaces(t *testing.T) {
	h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{
			workspaceEntryDoc(f.alpha, nil),
			workspaceEntryDoc(f.beta, map[string]any{"privileged": true}),
		}
	})
	privileged := map[string]any{"Privileged": true}
	h.deny(h.options(nil), wsRequest(h.f.alpha, privileged), "privileged containers are not allowed")
	// beta's label on a request that mounts alpha.
	forged := wsRequest(h.f.alpha, privileged)
	forged.labels[WorkspaceLocalFolderLabel] = h.f.beta
	h.deny(h.options(nil), forged, "workspace exception not applied", "outside the workspace")
	h.admit(h.options(nil), wsRequest(h.f.beta, privileged))
}

// A forged devcontainer.local_folder label with bind sources outside that
// workspace gets no exception. Binds outside every per-workspace root are
// still admitted by the base policy; binds into another workspace's folder
// are denied by scoping.
func TestWorkspaceExceptionForgedLabelBindsOutsideWorkspace(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	for name, tc := range map[string]struct {
		binds  []string
		scoped bool
	}{
		"only outside":           {[]string{h.f.outside + ":/data"}, false},
		"workspace plus outside": {[]string{h.f.alpha + ":/workspaces/project", h.f.outside + ":/data"}, false},
		"sibling workspace":      {[]string{h.f.alpha + ":/workspaces/project", h.f.gamma + ":/other"}, true},
		"dot-dot out":            {[]string{h.f.alpha + "/../gamma:/other"}, true},
	} {
		t.Run(name, func(t *testing.T) {
			req := wsRequest(h.f.alpha, map[string]any{"Privileged": true})
			req.hostConfig["Binds"] = tc.binds
			h.deny(h.options(nil), req, "privileged containers are not allowed", "workspace exception not applied")
			delete(req.hostConfig, "Privileged")
			if tc.scoped {
				h.deny(h.options(nil), req, "outside this workspace's folder")
				return
			}
			// Control: the base policy admits these binds.
			h.admit(h.options(nil), req)
		})
	}
}

func TestWorkspaceExceptionBindAgreementRules(t *testing.T) {
	h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{
			workspaceEntryDoc(f.alpha, map[string]any{"privileged": true}),
			workspaceEntryDoc(filepath.Join(f.root, "delta"), map[string]any{"privileged": true}),
			workspaceEntryDoc(filepath.Join(f.root, "epsilon"), map[string]any{"privileged": true}),
			workspaceEntryDoc(filepath.Join(f.root, "zeta"), map[string]any{"privileged": true}),
		}
	})
	zeta := filepath.Join(h.f.root, "zeta")
	if err := os.WriteFile(zeta, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.f.outside, filepath.Join(h.f.alpha, "link-out")); err != nil {
		t.Fatal(err)
	}
	delta := filepath.Join(h.f.root, "delta")
	if err := os.Symlink(h.f.alpha, delta); err != nil {
		t.Fatal(err)
	}
	privileged := map[string]any{"Privileged": true}
	for _, tc := range []struct {
		name  string
		req   wsCreate
		cause string
	}{
		{"symlink inside workspace resolves outside", func() wsCreate {
			r := wsRequest(h.f.alpha, privileged)
			r.hostConfig["Binds"] = []string{h.f.alpha + ":/w", h.f.alpha + "/link-out:/data"}
			return r
		}(), "outside the workspace"},
		{"no workspace mount", func() wsCreate {
			r := wsRequest(h.f.alpha, privileged)
			r.hostConfig["Binds"] = []string{"named-volume:/data"}
			return r
		}(), "no bind source is the workspace"},
		{"mounts bind outside", func() wsCreate {
			r := wsRequest(h.f.alpha, privileged)
			r.hostConfig["Mounts"] = []map[string]any{{"Type": "bind", "Source": h.f.outside, "Target": "/data"}}
			return r
		}(), "outside the workspace"},
		{"volumes host-path key outside", func() wsCreate {
			r := wsRequest(h.f.alpha, privileged)
			r.top = map[string]any{"Volumes": map[string]any{h.f.outside + ":/data": map[string]any{}}}
			return r
		}(), "outside the workspace"},
		{"local volume bind device outside", func() wsCreate {
			r := wsRequest(h.f.alpha, privileged)
			r.hostConfig["Mounts"] = []map[string]any{{"Type": "volume", "Source": "sample", "Target": "/data", "VolumeOptions": map[string]any{
				"DriverConfig": map[string]any{"Name": "local", "Options": map[string]string{"type": "none", "o": "bind", "device": h.f.outside}},
			}}}
			return r
		}(), "outside the workspace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.deny(h.options(nil), tc.req, "privileged containers are not allowed", "not applied", tc.cause)
		})
	}
	// A header workspace that is a symlink, missing or a file is not a
	// workspace at all: the create is denied before any match, and the
	// reason does not quote the header.
	for name, ws := range map[string]string{"symlink": delta, "missing": filepath.Join(h.f.root, "epsilon"), "file": zeta} {
		t.Run("header workspace "+name, func(t *testing.T) {
			reason := h.deny(h.options(nil), wsRequest(ws, nil), "the workspace header does not name a valid workspace")
			if strings.Contains(reason, ws) {
				t.Fatalf("reason quotes the header: %q", reason)
			}
		})
	}
	// Positive control: a bind inside the workspace and a Mounts bind of it.
	inside := wsRequest(h.f.alpha, privileged)
	inside.hostConfig["Binds"] = []string{h.f.alpha + "/sub:/sub"}
	inside.hostConfig["Mounts"] = []map[string]any{{"Type": "bind", "Source": h.f.alpha, "Target": "/w"}}
	h.admit(h.options(nil), inside)
}

func TestWorkspaceExceptionExtraBindSources(t *testing.T) {
	h := newWSHarness(t, nil)
	extra := filepath.Join(h.f.base, "extra")
	if err := os.MkdirAll(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{extra}}))))
	h.store.Reload()
	req := wsRequest(h.f.alpha, nil)
	req.hostConfig["Binds"] = []string{h.f.alpha + ":/w", extra + "/cache:/cache"}
	h.admit(h.options(nil), req)
	// For another workspace the base allowlist, which lacks extra, decides.
	other := wsRequest(h.f.gamma, nil)
	other.hostConfig["Binds"] = []string{h.f.gamma + ":/w", extra + "/cache:/cache"}
	h.deny(h.options(nil), other, "is not allowlisted")
}

func TestWorkspaceExceptionRequiresOptIn(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	h.deny(h.options(func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = false }),
		wsRequest(h.f.alpha, map[string]any{"Privileged": true}), "privileged containers are not allowed")
}

func TestWorkspaceExceptionInvalidFileDenyReason(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	writeAtomic(t, h.f.file, []byte(`{"version":1,"exceptions":[],"unknown":true}`))
	h.store.Reload()
	reason := h.deny(h.options(nil), wsRequest(h.f.alpha, map[string]any{"Privileged": true}), "privileged containers are not allowed", "workspace exceptions unavailable: policy file invalid")
	// A request the base policy admits is unaffected.
	h.admit(h.options(nil), wsRequest(h.f.alpha, nil))
	if !strings.Contains(h.logs.String(), `"workspace_exception":"not_applied:policy_file_invalid"`) {
		t.Fatalf("log missing invalid-file outcome: %s (reason %q)", h.logs.String(), reason)
	}
}

func TestWorkspaceExceptionGrantsOpenOnlyTheirGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grants   map[string]any
		base     func(*ContainerCreateOptions)
		admitted map[string]any
		// neighbor is a request the same grant must not admit.
		neighbor map[string]any
	}{
		{"privileged", map[string]any{"privileged": true}, nil,
			map[string]any{"Privileged": true}, map[string]any{"CapAdd": []string{"SYS_ADMIN"}}},
		{"capAdd name", map[string]any{"capAdd": []string{"SYS_PTRACE"}}, nil,
			map[string]any{"CapAdd": []string{"CAP_SYS_PTRACE"}}, map[string]any{"CapAdd": []string{"NET_ADMIN"}}},
		{"capAdd ALL", map[string]any{"capAdd": []string{"ALL"}}, nil,
			map[string]any{"CapAdd": []string{"SYS_ADMIN", "NET_ADMIN"}}, map[string]any{"Privileged": true}},
		{"namespace pid", map[string]any{"namespaces": []string{"pid"}}, nil,
			map[string]any{"PidMode": "host"}, map[string]any{"PidMode": "ns:/proc/1/ns/pid"}},
		{"namespace ipc", map[string]any{"namespaces": []string{"ipc"}}, nil,
			map[string]any{"IpcMode": "host"}, map[string]any{"IpcMode": "ns:/proc/1/ns/ipc"}},
		{"namespace network", map[string]any{"namespaces": []string{"network"}}, nil,
			map[string]any{"NetworkMode": "host"}, map[string]any{"NetworkMode": "ns:/proc/1/ns/net"}},
		{"namespace userns", map[string]any{"namespaces": []string{"userns"}}, nil,
			map[string]any{"UsernsMode": "host"}, map[string]any{"UsernsMode": "ns:/proc/1/ns/user"}},
		{"namespace cgroupns", map[string]any{"namespaces": []string{"cgroupns"}}, nil,
			map[string]any{"CgroupnsMode": "host"}, map[string]any{"CgroupnsMode": "ns:/proc/1/ns/cgroup"}},
		{"namespace pid is not ipc", map[string]any{"namespaces": []string{"pid"}}, nil,
			map[string]any{"PidMode": "host"}, map[string]any{"IpcMode": "host"}},
		{"devices", map[string]any{"devices": []string{"/dev/fuse"}}, nil,
			map[string]any{"Devices": []map[string]string{{"PathOnHost": "/dev/fuse"}}}, map[string]any{"Devices": []map[string]string{{"PathOnHost": "/dev/sda"}}}},
		{"deviceCgroupRules", map[string]any{"deviceCgroupRules": []string{"c 10:229 rwm"}}, nil,
			map[string]any{"DeviceCgroupRules": []string{"c 10:229 rwm"}}, map[string]any{"DeviceCgroupRules": []string{"b 8:0 rwm"}}},
		{"gpus", map[string]any{"gpus": true}, nil,
			map[string]any{"DeviceRequests": []map[string]any{{"Driver": "", "Count": -1, "Capabilities": [][]string{{"gpu"}}}}}, map[string]any{"Privileged": true}},
		{"seccomp=unconfined deny flag", map[string]any{"securityOpt": []string{"seccomp=unconfined"}}, func(o *ContainerCreateOptions) { o.DenyUnconfinedSeccomp, o.DenyUnconfinedAppArmor = true, true },
			map[string]any{"SecurityOpt": []string{"seccomp=unconfined"}}, map[string]any{"SecurityOpt": []string{"apparmor=unconfined"}}},
		{"seccomp=unconfined allowlist", map[string]any{"securityOpt": []string{"seccomp=unconfined"}}, func(o *ContainerCreateOptions) { o.AllowedSeccompProfiles = []string{"default"} },
			map[string]any{"SecurityOpt": []string{"seccomp=unconfined"}}, map[string]any{"SecurityOpt": []string{"seccomp={}"}}},
		{"apparmor=unconfined", map[string]any{"securityOpt": []string{"apparmor=unconfined"}}, func(o *ContainerCreateOptions) { o.DenyUnconfinedSeccomp, o.DenyUnconfinedAppArmor = true, true },
			map[string]any{"SecurityOpt": []string{"apparmor=unconfined"}}, map[string]any{"SecurityOpt": []string{"seccomp=unconfined", "apparmor=unconfined"}}},
		{"apparmor profile", map[string]any{"securityOpt": []string{"apparmor=sample-profile"}}, func(o *ContainerCreateOptions) { o.AllowedAppArmorProfiles = []string{"docker-default"} },
			map[string]any{"SecurityOpt": []string{"apparmor=sample-profile"}}, map[string]any{"SecurityOpt": []string{"apparmor=other-profile"}}},
		{"label=disable", map[string]any{"securityOpt": []string{"label=disable"}}, func(o *ContainerCreateOptions) { o.DenySelinuxDisable = true; o.DenySelinuxLabelOverride = true },
			map[string]any{"SecurityOpt": []string{"label=disable"}}, map[string]any{"SecurityOpt": []string{"label=type:sample_t"}}},
		{"systempaths=unconfined", map[string]any{"securityOpt": []string{"systempaths=unconfined"}}, func(o *ContainerCreateOptions) { o.DenyUnconfinedSystemPaths = true; o.DenyUnconfinedSeccomp = true },
			map[string]any{"SecurityOpt": []string{"systempaths=unconfined"}, "MaskedPaths": []string{}}, map[string]any{"SecurityOpt": []string{"seccomp=unconfined"}}},
		{"runtimes", map[string]any{"runtimes": []string{"sample-runc"}}, nil,
			map[string]any{"Runtime": "sample-runc"}, map[string]any{"Runtime": "other-runc"}},
		{"sysctls", map[string]any{"sysctls": []string{"net.ipv4.ip_forward"}}, nil,
			map[string]any{"Sysctls": map[string]string{"net.ipv4.ip_forward": "1"}}, map[string]any{"Sysctls": map[string]string{"net.ipv4.ip_forward": "1", "net.core.somaxconn": "1024"}}},
		{"no grant opens host UTS", fullWorkspaceGrants(), nil,
			map[string]any{"Privileged": true}, map[string]any{"UTSMode": "host"}},
		{"no grant opens ExtraHosts", fullWorkspaceGrants(), nil,
			map[string]any{"Privileged": true}, map[string]any{"ExtraHosts": []string{"sample:192.0.2.1"}}},
		{"no grant opens GroupAdd", fullWorkspaceGrants(), nil,
			map[string]any{"Privileged": true}, map[string]any{"GroupAdd": []string{"sample"}}},
		{"no grant opens CgroupParent", fullWorkspaceGrants(), nil,
			map[string]any{"Privileged": true}, map[string]any{"CgroupParent": "/sample"}},
		{"no grant opens VolumesFrom", fullWorkspaceGrants(), nil,
			map[string]any{"Privileged": true}, map[string]any{"VolumesFrom": []string{"sample"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
				return []map[string]any{workspaceEntryDoc(f.alpha, tc.grants)}
			})
			opts := h.options(tc.base)
			h.admit(opts, wsRequest(h.f.alpha, tc.admitted))
			h.deny(opts, wsRequest(h.f.gamma, tc.admitted))
			h.deny(opts, wsRequest(h.f.alpha, tc.neighbor))
		})
	}
}

// Grants never open settings outside the grant table: the require_*
// hardening, required labels and resource limits keep their base values, and
// the workspace mount itself needs the base bind allowlist.
func TestWorkspaceExceptionLeavesOtherSettingsAlone(t *testing.T) {
	h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{workspaceEntryDoc(f.alpha, fullWorkspaceGrants())}
	})
	for name, tc := range map[string]struct {
		base func(*ContainerCreateOptions)
		want string
	}{
		"require_non_root_user":          {func(o *ContainerCreateOptions) { o.RequireNonRootUser = true }, "non-root"},
		"require_no_new_privileges":      {func(o *ContainerCreateOptions) { o.RequireNoNewPrivileges = true }, "no-new-privileges"},
		"required_labels":                {func(o *ContainerCreateOptions) { o.RequiredLabels = []string{"sample.owner"} }, "required label"},
		"require_memory_limit":           {func(o *ContainerCreateOptions) { o.RequireMemoryLimit = true }, "memory limit"},
		"workspace root not allowlisted": {func(o *ContainerCreateOptions) { o.AllowedBindMounts = []string{h.f.outside} }, "is not allowlisted"},
	} {
		t.Run(name, func(t *testing.T) {
			req := wsRequest(h.f.alpha, map[string]any{"Privileged": true})
			h.admit(h.options(nil), req)
			h.deny(h.options(tc.base), req, tc.want)
		})
	}
}

func fullWorkspaceGrants() map[string]any {
	return map[string]any{
		"privileged": true, "capAdd": []string{"ALL"}, "namespaces": []string{"pid", "ipc", "network", "userns", "cgroupns"},
		"devices": []string{"/dev/fuse"}, "deviceCgroupRules": []string{"c 10:229 rwm"}, "gpus": true,
		"securityOpt": []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"},
		"runtimes":    []string{"sample-runc"}, "sysctls": []string{"net.ipv4.ip_forward"}, "restartPolicy": []string{"always", "unless-stopped", "on-failure"},
	}
}

// For every request the base policy admits, the effective policy admits it
// too: an exception never closes a gate.
func TestWorkspaceExceptionNeverClosesABaseGate(t *testing.T) {
	bases := map[string]func(*ContainerCreateOptions){
		"defaults": nil,
		"open": func(o *ContainerCreateOptions) {
			o.AllowPrivileged, o.AllowAllCapabilities, o.AllowHostPID, o.AllowHostNetwork, o.AllowSysctls = true, true, true, true, true
			o.AllowAllDevices, o.AllowDeviceRequests, o.AllowDeviceCgroupRules = true, true, true
		},
		"empty profile allowlists": func(o *ContainerCreateOptions) { o.AllowedSeccompProfiles, o.AllowedAppArmorProfiles = nil, nil },
		"constrained profiles": func(o *ContainerCreateOptions) {
			o.AllowedSeccompProfiles, o.AllowedAppArmorProfiles = []string{"default", "sample.json"}, []string{"docker-default", "sample"}
		},
	}
	requests := []map[string]any{
		nil,
		{"Privileged": true},
		{"PidMode": "host"},
		{"PidMode": "ns:/proc/1/ns/pid"},
		{"NetworkMode": "host"},
		{"SecurityOpt": []string{"seccomp=sample.json"}},
		{"SecurityOpt": []string{"apparmor=sample"}},
		{"SecurityOpt": []string{"seccomp=custom", "apparmor=custom"}},
		{"Sysctls": map[string]string{"net.core.somaxconn": "1024"}},
		{"CapAdd": []string{"NET_ADMIN"}},
		{"Devices": []map[string]string{{"PathOnHost": "/dev/sda"}}},
		{"DeviceRequests": []map[string]any{{"Driver": "", "Count": -1}}},
		{"RestartPolicy": map[string]any{"Name": "always"}},
	}
	grantSets := map[string]map[string]any{"none": {}, "full": fullWorkspaceGrants(), "narrow": {
		"capAdd": []string{"SYS_PTRACE"}, "securityOpt": []string{"apparmor=other"}, "sysctls": []string{"net.ipv4.ip_forward"},
	}}
	for baseName, base := range bases {
		for grantName, grants := range grantSets {
			h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
				return []map[string]any{workspaceEntryDoc(f.alpha, grants)}
			})
			for i, hc := range requests {
				off := h.options(func(o *ContainerCreateOptions) {
					if base != nil {
						base(o)
					}
					o.ApplyWorkspaceExceptions = false
				})
				on := h.options(base)
				req := wsRequest(h.f.alpha, hc)
				if h.inspect(off, req) == "" && h.inspect(on, req) != "" {
					t.Fatalf("base %s, grants %s, request %d: base admits but the exception denies: %q", baseName, grantName, i, h.inspect(on, req))
				}
			}
		}
	}
}

func TestRequireNoRestartPolicy(t *testing.T) {
	h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{
			workspaceEntryDoc(f.alpha, map[string]any{"restartPolicy": []string{"unless-stopped"}}),
			workspaceEntryDoc(f.beta, nil),
		}
	})
	restart := func(ws, name string) wsCreate {
		return wsRequest(ws, map[string]any{"RestartPolicy": map[string]any{"Name": name, "MaximumRetryCount": 0}})
	}
	require := func(o *ContainerCreateOptions) { o.RequireNoRestartPolicy = true }

	// Default off: any policy passes, as before.
	h.admit(h.options(nil), restart(h.f.gamma, "always"))
	// Empty and "no" pass; a missing RestartPolicy passes.
	h.admit(h.options(require), restart(h.f.gamma, ""))
	h.admit(h.options(require), restart(h.f.gamma, "no"))
	h.admit(h.options(require), wsRequest(h.f.gamma, nil))
	// Any other name is denied.
	for _, name := range []string{"always", "unless-stopped", "on-failure", "No"} {
		h.deny(h.options(require), restart(h.f.gamma, name), `restart policy "`+name+`" is not allowed`)
	}
	// The grant admits exactly the listed names for its workspace.
	h.admit(h.options(require), restart(h.f.alpha, "unless-stopped"))
	h.deny(h.options(require), restart(h.f.alpha, "always"), `restart policy "always" is not allowed`)
	h.deny(h.options(require), restart(h.f.beta, "unless-stopped"), `restart policy "unless-stopped" is not allowed`)
	// A grant needs a match: alpha's label on a request mounting gamma.
	forged := restart(h.f.gamma, "unless-stopped")
	forged.labels[WorkspaceLocalFolderLabel] = h.f.alpha
	h.deny(h.options(require), forged, "not applied")
	// The gate works without exceptions; a grant is then not consulted.
	noApply := func(o *ContainerCreateOptions) { o.RequireNoRestartPolicy, o.ApplyWorkspaceExceptions = true, false }
	h.deny(h.options(noApply), restart(h.f.alpha, "unless-stopped"), `restart policy "unless-stopped" is not allowed`)
}

// Compose: devcontainer-builder 0.2.0 puts devcontainer.local_folder only on
// the primary service (pkg/host/dockercompose/labels.go containerLabels); a
// service's own Compose labels are merged under the managed ones, so a
// sidecar's label is whatever the Compose file says. The workspace comes from
// the header the workspace manager's client sends on every service's create,
// so a sidecar matches with no label, and a label that names another
// workspace is refused.
func TestWorkspaceExceptionComposeServices(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	composeLabels := func(service string, folder string) map[string]string {
		l := map[string]string{"com.docker.compose.project": "sample", "com.docker.compose.service": service, "com.docker.compose.oneoff": "False"}
		if folder != "" {
			l[WorkspaceLocalFolderLabel] = folder
		}
		return l
	}
	configBind := map[string]any{"Type": "bind", "Source": h.f.staging + "/objects-1/probecfg", "Target": "/etc/probe.conf", "ReadOnly": true}
	service := func(labels map[string]string, binds []string, mounts []map[string]any) wsCreate {
		hc := map[string]any{"Privileged": true, "Binds": binds}
		if mounts != nil {
			hc["Mounts"] = mounts
		}
		return wsCreate{labels: labels, hostConfig: hc, headers: map[string][]string{WorkspaceHeader: {h.f.alpha}}}
	}

	h.admit(h.options(nil), service(composeLabels("app", h.f.alpha), []string{h.f.alpha + ":/workspaces/project"}, nil))
	h.admit(h.options(nil), service(composeLabels("worker", ""), []string{h.f.alpha + "/src:/src"}, nil))
	h.deny(h.options(nil), service(composeLabels("db", ""), []string{"sample_data:/data"}, nil), "privileged containers are not allowed", "no bind source is the workspace")
	h.deny(h.options(nil), service(composeLabels("worker", h.f.beta), []string{h.f.alpha + "/src:/src"}, nil), "workspace label devcontainer.local_folder disagrees with the request's workspace")
	// A config staged outside the workspace breaks agreement.
	h.deny(h.options(nil), service(composeLabels("worker", ""), []string{h.f.alpha + "/src:/src"}, []map[string]any{configBind}), "not applied", "outside the workspace")
	h.deny(h.options(nil), service(composeLabels("app", h.f.alpha), []string{h.f.alpha + ":/workspaces/project"}, []map[string]any{configBind}), "not applied")
	// Granting the staging folder as an extra bind source restores the match.
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"privileged": true, "extraBindSources": []string{h.f.staging}}))))
	h.store.Reload()
	h.admit(h.options(nil), service(composeLabels("app", h.f.alpha), []string{h.f.alpha + ":/workspaces/project"}, []map[string]any{configBind}))
	// A service created without the header is refused.
	headerless := service(composeLabels("worker", h.f.alpha), []string{h.f.alpha + "/src:/src"}, nil)
	headerless.headers = map[string][]string{}
	h.deny(h.options(nil), headerless, "the request names no workspace")
}

func TestWorkspaceExceptionDecisionLog(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	type line map[string]any
	read := func() []line {
		var out []line
		for _, raw := range strings.Split(strings.TrimSpace(h.logs.String()), "\n") {
			var l line
			if raw == "" || json.Unmarshal([]byte(raw), &l) != nil || l["msg"] != "container create workspace exception" {
				continue
			}
			out = append(out, l)
		}
		h.logs.Reset()
		return out
	}
	h.admit(h.options(nil), wsRequest(h.f.alpha, map[string]any{"Privileged": true}))
	got := read()
	if len(got) != 1 || got[0]["workspace_exception"] != "applied" || got[0]["decision"] != "allow" ||
		got[0]["approval_by_issuer"] != "https://id.example.org" || got[0]["approval_by_subject"] != "user-0001" || got[0]["approval_at"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("applied log: %v", got)
	}
	h.deny(h.options(nil), wsRequest(h.f.gamma, map[string]any{"Privileged": true}))
	if got := read(); len(got) != 1 || got[0]["workspace_exception"] != "none" || got[0]["decision"] != "deny" {
		t.Fatalf("none log: %v", got)
	}
	forged := wsRequest(h.f.outside, nil)
	forged.labels[WorkspaceLocalFolderLabel] = h.f.alpha
	h.admit(h.options(nil), forged)
	if got := read(); len(got) != 1 || got[0]["workspace_exception"] != "not_applied:"+WorkspaceCauseBindSourceOutside || got[0]["approval_by_subject"] != nil {
		t.Fatalf("not applied log: %v", got)
	}
	throwaway := wsCreate{hostConfig: map[string]any{"Binds": []string{h.f.alpha + ":/w"}}, headers: map[string][]string{WorkspaceThrowawayHeader: {h.f.alpha}}}
	h.admit(h.options(nil), throwaway)
	if got := read(); len(got) != 0 {
		t.Fatalf("a throwaway create must not log an exception decision: %v", got)
	}
}

// holdingBody blocks the first Read until release is closed and reports on
// reading that the read was reached.
type holdingBody struct {
	reached chan struct{}
	release chan struct{}
	r       io.Reader
	started bool
}

func (b *holdingBody) Read(p []byte) (int, error) {
	if !b.started {
		b.started = true
		close(b.reached)
		<-b.release
	}
	return b.r.Read(p)
}

// A request held before a replace is evaluated against the old file; a new
// request against the new one.
func TestWorkspaceExceptionReloadHeldRequestKeepsItsSnapshot(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	opts := h.options(nil)
	body := &holdingBody{reached: make(chan struct{}), release: make(chan struct{}), r: strings.NewReader(wsRequest(h.f.alpha, map[string]any{"Privileged": true}).body(t))}
	held := httptest.NewRequest(http.MethodPost, "/containers/create", body)
	held.Header.Set(WorkspaceHeader, h.f.alpha)
	type result struct {
		reason string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		reason, err := newContainerCreatePolicy(opts).inspectWithWorkspaceExceptions(testLogger(), held, "/containers/create")
		done <- result{reason, err}
	}()
	select {
	case <-body.reached:
	case res := <-done:
		t.Fatalf("the request finished before its body was read: %+v", res)
	}
	// Revoke the grant while the request is held in its body read.
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, nil))))
	if h.store.Reload().State() != WorkspaceExceptionsLoaded {
		t.Fatal("replacement did not load")
	}
	close(body.release)
	res := <-done
	if res.err != nil || res.reason != "" {
		t.Fatalf("held request must use the snapshot it took at admission: reason %q err %v", res.reason, res.err)
	}
	h.deny(opts, wsRequest(h.f.alpha, map[string]any{"Privileged": true}), "privileged containers are not allowed")
}

// The middleware runs the wrapper for Docker-compat create.
func TestWorkspaceExceptionThroughMiddleware(t *testing.T) {
	h := newWSHarness(t, privilegedGrant)
	rule, err := CompileRule(Rule{Methods: []string{http.MethodPost}, Pattern: "/containers/create", Action: ActionAllow})
	if err != nil {
		t.Fatal(err)
	}
	serve := func(req wsCreate) int {
		handler := MiddlewareWithOptions([]*CompiledRule{rule}, testLogger(), Options{PolicyConfig: PolicyConfig{ContainerCreate: h.options(nil)}})(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1.51/containers/create", strings.NewReader(req.body(t)))
		r.Header = req.header()
		handler.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := serve(wsRequest(h.f.alpha, map[string]any{"Privileged": true})); code != http.StatusNoContent {
		t.Fatalf("matched create: status %d, want 204", code)
	}
	if code := serve(wsRequest(h.f.gamma, map[string]any{"Privileged": true})); code != http.StatusForbidden {
		t.Fatalf("unmatched create: status %d, want 403", code)
	}
}

func TestMatchWorkspaceExceptionAPI(t *testing.T) {
	h := newWSHarness(t, func(f workspaceExceptionsFixture) []map[string]any {
		return []map[string]any{workspaceEntryDoc(f.alpha, map[string]any{"extraBindSources": []string{f.staging}, "restartPolicy": []string{"always"}})}
	})
	snap := h.store.Load()
	m := MatchWorkspaceException(snap, h.f.alpha, WorkspaceExceptionRequest{
		Binds:  []string{h.f.alpha + ":/w"},
		Mounts: []WorkspaceExceptionMount{{Type: "bind", Source: h.f.staging + "/x"}},
	})
	if !m.Applied() || m.LogValue() != "applied" || len(m.ExtraBindSources()) != 1 || m.RestartPolicies()[0] != "always" || m.Approval().Subject != "user-0001" {
		t.Fatalf("match: %+v", m)
	}
	if m := MatchWorkspaceException(snap, "", WorkspaceExceptionRequest{}); m.Outcome != WorkspaceExceptionNone || m.Applied() || m.ExtraBindSources() != nil {
		t.Fatalf("no workspace: %+v", m)
	}
	if m := MatchWorkspaceException(nil, h.f.alpha, WorkspaceExceptionRequest{}); m.Outcome != WorkspaceExceptionNone {
		t.Fatalf("nil snapshot: %+v", m)
	}
	// The workspace is matched byte-equal, not cleaned.
	if m := MatchWorkspaceException(snap, h.f.alpha+"/", WorkspaceExceptionRequest{Binds: []string{h.f.alpha + ":/w"}}); m.Outcome != WorkspaceExceptionNone {
		t.Fatalf("trailing slash workspace: %+v", m)
	}
}

// Two effective policies built from one base policy do not share list
// storage: a request for one workspace never sees another's extra bind
// sources. The duplicate base entry leaves spare capacity in the base list.
func TestWithWorkspaceGrantsDoesNotShareBaseSlices(t *testing.T) {
	base := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: []string{"/srv/a", "/srv/a", "/srv/b"}})
	if cap(base.allowedBindMounts) <= len(base.allowedBindMounts) {
		t.Fatalf("fixture needs spare capacity: len %d cap %d", len(base.allowedBindMounts), cap(base.allowedBindMounts))
	}
	req := &containerCreateRequest{}
	first := base.withWorkspaceGrants(workspaceGrants{extraBindSources: []string{"/srv/extra-one"}}, req)
	second := base.withWorkspaceGrants(workspaceGrants{extraBindSources: []string{"/srv/extra-two"}}, req)
	if !slices.Contains(first.allowedBindMounts, "/srv/extra-one") || slices.Contains(first.allowedBindMounts, "/srv/extra-two") {
		t.Fatalf("first effective list %v was changed by the second", first.allowedBindMounts)
	}
	if !slices.Contains(second.allowedBindMounts, "/srv/extra-two") || len(base.allowedBindMounts) != 2 {
		t.Fatalf("second %v, base %v", second.allowedBindMounts, base.allowedBindMounts)
	}
}

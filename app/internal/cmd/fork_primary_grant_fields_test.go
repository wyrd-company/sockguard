// relationships:
//
// references: [../../../docs/content/docs/workspace-exceptions]
package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// Each row needs exactly its own grant. The complete forwarded body and result
// prove admission; removing that grant and removing primary eligibility are
// independent refusals. All host inputs are owned temporary fixtures.
func TestPrimaryGrantEveryCreateField(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			extra := filepath.Join(filepath.Dir(f.root), "extra")
			device := filepath.Join(filepath.Dir(f.root), "device")
			if err := os.Mkdir(extra, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(device, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d)
			rows := []struct {
				name, field, grant string
				value, allowed     any
			}{
				{"privileged", "Privileged", "privileged", true, true},
				{"capAdd", "CapAdd", "capAdd", []string{"SYS_PTRACE"}, []string{"SYS_PTRACE"}},
				{"capAdd-ALL", "CapAdd", "capAdd", []string{"ALL"}, []string{"ALL"}},
				{"host-pid", "PidMode", "namespaces", "host", []string{"pid"}},
				{"host-ipc", "IpcMode", "namespaces", "host", []string{"ipc"}},
				{"host-network", "NetworkMode", "namespaces", "host", []string{"network"}},
				{"host-userns", "UsernsMode", "namespaces", "host", []string{"userns"}},
				{"host-cgroupns", "CgroupnsMode", "namespaces", "host", []string{"cgroupns"}},
				{"devices", "Devices", "devices", []any{map[string]string{"PathOnHost": device, "PathInContainer": "/dev/sample", "CgroupPermissions": "rwm"}}, []string{device}},
				{"deviceCgroupRules", "DeviceCgroupRules", "deviceCgroupRules", []string{"c 10:229 rwm"}, []string{"c 10:229 rwm"}},
				{"gpus", "DeviceRequests", "gpus", []any{map[string]any{"Count": -1, "Capabilities": [][]string{{"gpu"}}}}, true},
				{"extraBindSources", "Binds", "extraBindSources", []string{f.alpha + ":/workspace", extra + ":/extra:ro"}, []string{extra}},
				{"extraBindMount", "Mounts", "extraBindSources", []any{map[string]string{"Type": "bind", "Source": extra, "Target": "/extra"}}, []string{extra}},
				{"seccomp", "SecurityOpt", "securityOpt", []string{"seccomp=unconfined"}, []string{"seccomp=unconfined"}},
				{"apparmor-unconfined", "SecurityOpt", "securityOpt", []string{"apparmor=unconfined"}, []string{"apparmor=unconfined"}},
				{"apparmor-profile", "SecurityOpt", "securityOpt", []string{"apparmor=sample-profile"}, []string{"apparmor=sample-profile"}},
				{"selinux", "SecurityOpt", "securityOpt", []string{"label=disable"}, []string{"label=disable"}},
				{"systempaths", "SecurityOpt", "securityOpt", []string{"systempaths=unconfined"}, []string{"systempaths=unconfined"}},
				{"runtimes", "Runtime", "runtimes", "sample-runtime", []string{"sample-runtime"}},
				{"sysctls", "Sysctls", "sysctls", map[string]string{"net.ipv4.ip_forward": "1"}, []string{"net.ipv4.ip_forward"}},
				{"restart-always", "RestartPolicy", "restartPolicy", map[string]string{"Name": "always"}, []string{"always"}},
				{"restart-unless-stopped", "RestartPolicy", "restartPolicy", map[string]string{"Name": "unless-stopped"}, []string{"unless-stopped"}},
				{"restart-on-failure", "RestartPolicy", "restartPolicy", map[string]any{"Name": "on-failure", "MaximumRetryCount": 3}, []string{"on-failure"}},
			}
			for _, route := range []string{"/containers/create", "/v1.45/containers/create"} {
				t.Run(route, func(t *testing.T) {
					for _, row := range rows {
						t.Run(row.name, func(t *testing.T) {
							for _, tc := range []struct {
								name, label, header, state string
								want                       int
							}{
								{"primary", "same", "dev", "loaded", 201},
								{"grant-removed", "same", "dev", "removed", 403},
								{"unlabeled-own-workspace-denied", "", "dev", "loaded", 403},
								{"throwaway-denied", "throwaway", "throwaway", "loaded", 403},
								{"missing-policy", "same", "dev", "missing", 403},
								{"invalid-policy", "same", "dev", "invalid", 403},
							} {
								t.Run(tc.name, func(t *testing.T) {
									grants := map[string]any{row.grant: row.allowed}
									if tc.state == "removed" {
										grants = map[string]any{}
									}
									primaryGrantWritePolicy(t, f, grants)
									if tc.state == "missing" {
										if err := os.Remove(f.file); err != nil {
											t.Fatal(err)
										}
									}
									if tc.state == "invalid" {
										if err := os.WriteFile(f.file, []byte(`{"invalid":true}`), 0o600); err != nil {
											t.Fatal(err)
										}
									}
									store.Reload()
									hc := map[string]any{"Binds": []string{f.alpha + ":/workspace"}, row.field: row.value}
									labels := map[string]string{}
									if tc.label == "same" {
										labels[filter.WorkspaceLocalFolderLabel] = f.alpha
									}
									if tc.label == "throwaway" {
										labels[filter.WorkspaceThrowawayLabel] = f.alpha
									}
									body := map[string]any{"Image": "busybox", "Labels": labels, "HostConfig": hc}
									header := filter.WorkspaceHeader
									if tc.header == "throwaway" {
										header = filter.WorkspaceThrowawayHeader
									}
									primaryGrantAssertCreate(t, h, d, route, f.alpha, header, body, tc.want)
								})
							}
						})
					}
				})
			}
			// An entry does not narrow unlabeled BASE admission.
			for _, state := range []string{"loaded", "missing", "invalid"} {
				t.Run("unlabeled-BASE-"+state, func(t *testing.T) {
					primaryGrantWritePolicy(t, f, map[string]any{"privileged": true})
					if state == "missing" {
						if err := os.Remove(f.file); err != nil {
							t.Fatal(err)
						}
					}
					if state == "invalid" {
						if err := os.WriteFile(f.file, []byte(`{"invalid":true}`), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					store.Reload()
					for _, restart := range []string{"", "no"} {
						primaryGrantAssertCreate(t, h, d, "/containers/create", f.alpha, filter.WorkspaceHeader, map[string]any{"Image": "busybox", "HostConfig": map[string]any{"Binds": []string{f.alpha + ":/workspace"}, "RestartPolicy": map[string]string{"Name": restart}}}, 201)
					}
				})
			}
		})
	}
}

func primaryGrantAssertCreate(t *testing.T, h http.Handler, d *primaryGrantDaemon, route, workspace, header string, body map[string]any, want int) {
	t.Helper()
	input := forkFieldJSON(t, body)
	r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(input))
	r.Header.Set(header, workspace)
	d.mu.Lock()
	d.writes = nil
	d.bodies = nil
	d.mu.Unlock()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	d.mu.Lock()
	defer d.mu.Unlock()
	t.Logf("GRANT_RESULT expected=%d actual=%d writes=%v input=%s forwarded=%v response=%s", want, w.Code, d.writes, input, d.bodies, w.Body.String())
	if w.Code != want {
		t.Errorf("PRIMARY_GRANT_STATUS: got %d want %d", w.Code, want)
	}
	if want == 403 {
		if len(d.writes) != 0 {
			t.Errorf("PRIMARY_GRANT_FORBIDDEN_WRITE: %v bodies=%v", d.writes, d.bodies)
		}
		return
	}
	if len(d.writes) != 1 || len(d.bodies) != 1 {
		t.Fatalf("admitted create writes=%v bodies=%v", d.writes, d.bodies)
	}
	var actual, expected any
	if json.Unmarshal([]byte(d.bodies[0]), &actual) != nil || json.Unmarshal([]byte(input), &expected) != nil || !reflect.DeepEqual(actual, expected) {
		t.Errorf("PRIMARY_GRANT_FORWARDED_BODY: %v want %v", actual, expected)
	}
	if w.Body.String() != `{"Id":"sample-id"}` {
		t.Errorf("forwarded daemon result=%s", w.Body.String())
	}
}

func TestPrimaryGrantNonOptedProfilesStayBase(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d, func(c *config.Config) {
				c.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = false
				if named {
					c.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
					c.Clients.Profiles[0].RequestBody.ContainerCreate.ApplyWorkspaceExceptions = false
				}
			})
			primaryGrantWritePolicy(t, f, map[string]any{"privileged": true})
			store.Reload()
			for _, labels := range []map[string]string{nil, {filter.WorkspaceLocalFolderLabel: f.alpha}} {
				body := map[string]any{"Image": "busybox", "Labels": labels, "HostConfig": map[string]any{"Binds": []string{f.alpha + ":/workspace"}, "Privileged": true}}
				primaryGrantAssertCreate(t, h, d, "/containers/create", f.alpha, filter.WorkspaceHeader, body, 403)
				body["HostConfig"].(map[string]any)["Privileged"] = false
				primaryGrantAssertCreate(t, h, d, "/containers/create", "invalid", filter.WorkspaceHeader, body, 201)
			}
		})
	}
}

func TestPrimaryGrantBaseOpenGatesStayOpen(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d, func(c *config.Config) {
				open := func(p *config.ContainerCreateRequestBodyConfig) {
					p.AllowPrivileged = true
					p.DenyUnconfinedSeccomp = false
					p.DenyUnconfinedAppArmor = false
					p.DenySelinuxDisable = false
					p.DenyUnconfinedSystemPaths = false
					p.AllowedSeccompProfiles = nil
					p.AllowedAppArmorProfiles = nil
				}
				open(&c.RequestBody.ContainerCreate)
				for i := range c.Clients.Profiles {
					open(&c.Clients.Profiles[i].RequestBody.ContainerCreate)
				}
			})
			primaryGrantWritePolicy(t, f, map[string]any{})
			store.Reload()
			for _, option := range []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"} {
				t.Run(option, func(t *testing.T) {
					primaryGrantAssertCreate(t, h, d, "/containers/create", f.alpha, filter.WorkspaceHeader, map[string]any{"Image": "busybox", "HostConfig": map[string]any{"Binds": []string{f.alpha + ":/workspace"}, "Privileged": true, "SecurityOpt": []string{option}}}, 201)
				})
			}
		})
	}
}

// Native libpod create is outside the workspace-grant surface. Unlike the
// separate route-denial controls, these reach libpod's own body policy.
func TestPrimaryGrantLibpodCreateOwnPolicyControl(t *testing.T) {
	for _, named := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "named"}[named], func(t *testing.T) {
			f := newServeWorkspaceFixture(t)
			bindfs.RealRootForTest(t, filepath.Dir(f.root))
			d := &primaryGrantDaemon{}
			h, store := primaryGrantChain(t, f, named, d, func(c *config.Config) {
				c.Rules = append(c.Rules, config.RuleConfig{Match: config.MatchConfig{Method: "POST", Path: "/libpod/containers/create"}, Action: "allow"})
				for i := range c.Clients.Profiles {
					c.Clients.Profiles[i].Rules = c.Rules
				}
			})
			primaryGrantWritePolicy(t, f, map[string]any{"privileged": true})
			store.Reload()
			for _, route := range []string{"/libpod/containers/create", "/v5.0.0/libpod/containers/create"} {
				body := map[string]any{"image": "busybox", "systemd": "false", "labels": map[string]string{filter.WorkspaceLocalFolderLabel: f.alpha}, "privileged": false}
				primaryGrantAssertCreate(t, h, d, route, f.alpha, filter.WorkspaceHeader, body, 201)
				body["privileged"] = true
				primaryGrantAssertCreate(t, h, d, route, f.alpha, filter.WorkspaceHeader, body, 403)
			}
		})
	}
}

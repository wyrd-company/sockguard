// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions, ../../../docs/fork-endpoints]
package cmd

import (
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// Source inventory: devcontainer-builder 0.2.0 c432d28f97ce18f07f8e032187ab7c211e8a6595,
// also audited at 957eecde0c08d72b31f9c1e443ae2c270b5c5eee:
// pkg/host/docker/{runargs,spawn,gpu,ports,up}.go and
// pkg/host/dockercompose/{spawn,gpu,volume,network,up,watch}.go.
// Each row changes one HostConfig field. An empty baseline is a positive
// control even for fields that have no workspace grant. The passthrough rows
// pin existing base admission; a workspace exception must never narrow it.
func TestForkHostConfigFieldMatrix(t *testing.T) {
	h := newForkFieldChain(t, func(c *config.Config) {
		p := &c.RequestBody.ContainerCreate
		p.DenyUnconfinedSeccomp = true
		p.DenyUnconfinedAppArmor = true
		p.DenySelinuxDisable = true
		p.DenyUnconfinedSystemPaths = true
	}, nil)
	allGrants := map[string]any{
		"privileged": true, "capAdd": []string{"SYS_PTRACE"},
		"namespaces": []string{"network", "pid", "ipc", "userns", "cgroupns"},
		"devices":    []string{"/dev/fuse"}, "deviceCgroupRules": []string{"c 10:229 rwm"},
		"gpus": true, "securityOpt": []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"},
		"runtimes": []string{"sample-runtime"}, "sysctls": []string{"net.ipv4.ip_forward"},
		"restartPolicy": []string{"unless-stopped"}, "extraBindSources": []string{h.outside},
	}
	rows := []struct {
		name    string
		value   any
		reason  string
		granted bool
	}{
		{"Privileged", true, "privileged containers are not allowed", true},
		{"CapAdd", []string{"SYS_PTRACE"}, `capability "SYS_PTRACE" is not in the allowed list`, true},
		{"SecurityOpt", []string{"seccomp=unconfined"}, "unconfined seccomp profile is not allowed", true},
		{"NetworkMode", "host", "host network mode is not allowed", true},
		{"PidMode", "host", "host PID mode is not allowed", true},
		{"IpcMode", "host", "host IPC mode is not allowed", true},
		{"UsernsMode", "host", "host user namespace mode is not allowed", true},
		{"CgroupnsMode", "host", "host cgroup namespace mode is not allowed", true},
		{"UTSMode", "host", "host UTS mode is not allowed", false},
		{"CgroupParent", "sample.slice", "custom cgroup parent is not allowed", false},
		{"Runtime", "sample-runtime", `runtime "sample-runtime" is not allowlisted`, true},
		{"Sysctls", map[string]string{"net.ipv4.ip_forward": "1"}, "setting sysctls is not allowed", true},
		{"Devices", []any{map[string]string{"PathOnHost": "/dev/fuse", "PathInContainer": "/dev/fuse", "CgroupPermissions": "rwm"}}, `device "/dev/fuse" is not allowlisted`, true},
		{"DeviceCgroupRules", []string{"c 10:229 rwm"}, "device cgroup rules are not allowed", true},
		{"DeviceRequests", []any{map[string]any{"Count": -1, "Capabilities": [][]string{{"gpu"}}}}, "device requests are not allowed", true},
		{"VolumesFrom", []string{"sample:ro"}, "VolumesFrom is not allowed", false},
		{"ExtraHosts", []string{"sample:192.0.2.1"}, "ExtraHosts is not allowed", false},
		{"GroupAdd", []string{"1000"}, "supplemental group IDs are not allowed", false},
		{"RestartPolicy", map[string]any{"Name": "unless-stopped"}, `restart policy "unless-stopped" is not allowed`, true},
		{"Binds", []string{h.f.alpha + ":/workspace", h.outside + ":/external:ro"}, "is not allowlisted", true},
		{"Mounts", []any{map[string]string{"Type": "bind", "Source": h.outside, "Target": "/external"}}, "is not allowlisted", true},
		{"Init", true, "", true}, {"ReadonlyRootfs", true, "", true},
		{"PublishAllPorts", true, "", true}, {"AutoRemove", false, "", true},
		{"VolumeDriver", "local", "", true}, {"Isolation", "default", "", true},
		{"Memory", int64(134217728), "", true}, {"MemorySwap", int64(268435456), "", true},
		{"MemoryReservation", int64(67108864), "", true}, {"ShmSize", int64(67108864), "", true},
		{"NanoCpus", int64(1000000000), "", true}, {"CpuShares", 512, "", true},
		{"CpusetCpus", "0", "", true}, {"CpusetMems", "0", "", true},
		{"PidsLimit", 128, "", true}, {"OomScoreAdj", 100, "", true},
		{"OomKillDisable", true, "", true}, {"CapDrop", []string{"ALL"}, "", true},
		{"Dns", []string{"192.0.2.53"}, "", true}, {"DnsSearch", []string{"example.test"}, "", true},
		{"DnsOptions", []string{"ndots:1"}, "", true}, {"Links", []string{"sample:alias"}, "", true},
		{"PortBindings", map[string]any{"8080/tcp": []any{map[string]string{"HostIp": "127.0.0.1", "HostPort": "18080"}}}, "", true},
		{"Ulimits", []any{map[string]any{"Name": "nofile", "Soft": 1024, "Hard": 2048}}, "", true},
		{"Tmpfs", map[string]string{"/tmp": "rw,nosuid,nodev"}, "", true},
		{"Annotations", map[string]string{"example.test/note": "sample"}, "", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if err := removeForkFieldPolicy(h); err != nil {
				t.Fatal(err)
			}
			h.postCreate(t, h.create(nil), 201, "")
			want := 201
			if row.reason != "" {
				want = 403
			}
			h.postCreate(t, h.create(map[string]any{row.name: row.value}), want, row.reason)
			h.grants(t, h.f.alpha, allGrants)
			h.postCreate(t, h.create(map[string]any{"Privileged": true}), 201, "")
			want = 403
			reason := row.reason
			if row.granted {
				want = 201
				reason = ""
			}
			h.postCreate(t, h.create(map[string]any{row.name: row.value}), want, reason)
		})
	}
}

// Unconfined SecurityOpt values have optional base deny flags. The strict
// matrix above sets those flags; the default policy permits these values.
// Neither a missing entry nor a matched entry closes a base-open gate.
func TestForkFieldBaseOpenSecurityOptionsStayOpen(t *testing.T) {
	h := newForkFieldChain(t, nil, nil)
	for _, option := range []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"} {
		t.Run(option, func(t *testing.T) {
			if err := removeForkFieldPolicy(h); err != nil {
				t.Fatal(err)
			}
			body := h.create(map[string]any{"SecurityOpt": []string{option}})
			h.postCreate(t, body, 201, "")
			h.grants(t, h.f.alpha, map[string]any{"privileged": true})
			h.postCreate(t, body, 201, "")
		})
	}
}

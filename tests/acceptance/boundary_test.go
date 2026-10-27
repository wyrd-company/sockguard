//go:build sockguardacceptance

// relationships:
//
//	references: [suite_test.go, ../../docs/content/docs/workspace-exceptions.mdx]
package acceptance

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/volume"
	"github.com/docker/docker/pkg/stdcopy"
)

func testGrants(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("alpha")
	other := f.workspace("beta")
	own := map[string]any{"Binds": []string{w + ":/workspace"}}
	for name, labels := range map[string]map[string]string{"unlabeled": {}, "primary": {primaryLabel: w}, "throwaway": {commandLabel: w}} {
		t.Run("Base_"+name, func(t *testing.T) {
			h := workspaceHeader
			if name == "throwaway" {
				h = throwawayHeader
			}
			id, s, b := f.create(t, p, w, h, labels, own)
			expect(t, s, 201, b)
			s, b = p.request(t, "POST", "/containers/"+id+"/start", w, "", nil)
			denied(t, s, b, "names no workspace")
			s, b = p.request(t, "POST", "/containers/"+id+"/start", w, h, nil)
			expect(t, s, 204, b)
		})
	}
	for name, labels := range map[string]map[string]string{"mismatch": {primaryLabel: other}, "opposite": {commandLabel: w}, "both": {primaryLabel: w, commandLabel: w}} {
		t.Run("LabelDenial_"+name, func(t *testing.T) {
			_, s, b := f.create(t, p, w, workspaceHeader, labels, own)
			denied(t, s, b, "workspace")
		})
	}
	_, s, b := f.create(t, p, w, "", map[string]string{primaryLabel: w}, own)
	denied(t, s, b, "names no workspace")
	// Each grant class is a separate effect; create-only positives do not claim
	// the host has GPU devices, alternate runtimes or namespace support.
	t.Run("SecurityOptBaseAdmission", func(t *testing.T) {
		_, s, b := f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, map[string]any{"Binds": []string{w + ":/workspace"}, "SecurityOpt": []string{"seccomp=unconfined"}})
		expect(t, s, 201, b)
		t.Log("Exact baseline admits seccomp=unconfined without a grant; no grant necessity or stricter policy is claimed. Strict grant effect remains covered by composed field tests.")
	})
	cases := []struct {
		name   string
		field  map[string]any
		grants map[string]any
		reason string
	}{
		{"Privileged", map[string]any{"Privileged": true}, map[string]any{"privileged": true}, "privileged"},
		{"Capabilities", map[string]any{"CapAdd": []string{"SYS_PTRACE"}}, map[string]any{"capAdd": []string{"SYS_PTRACE"}}, "capabil"},
		{"Devices", map[string]any{"Devices": []map[string]string{{"PathOnHost": "/dev/null", "PathInContainer": "/dev/example", "CgroupPermissions": "r"}}}, map[string]any{"devices": []string{"/dev/null"}}, "device"},
		{"DeviceCgroupRules", map[string]any{"DeviceCgroupRules": []string{"c 1:3 r"}}, map[string]any{"deviceCgroupRules": []string{"c 1:3 r"}}, "device"},
		{"GPUCreateOnly", map[string]any{"DeviceRequests": []map[string]any{{"Count": 1, "Capabilities": [][]string{{"gpu"}}}}}, map[string]any{"gpus": true}, "device"},
		{"RuntimeCreateOnly", map[string]any{"Runtime": "runc"}, map[string]any{"runtimes": []string{"runc"}}, "runtime"},
		{"HostUserNamespace", map[string]any{"UsernsMode": "host"}, map[string]any{"namespaces": []string{"userns"}}, "user"},
		{"HostCgroupNamespace", map[string]any{"CgroupnsMode": "host"}, map[string]any{"namespaces": []string{"cgroupns"}}, "cgroup"},
		{"HostPID", map[string]any{"PidMode": "host"}, map[string]any{"namespaces": []string{"pid"}}, "pid"},
		{"HostIPC", map[string]any{"IpcMode": "host"}, map[string]any{"namespaces": []string{"ipc"}}, "ipc"},
		{"HostNetwork", map[string]any{"NetworkMode": "host"}, map[string]any{"namespaces": []string{"network"}}, "network"},
		{"RestartPolicy", map[string]any{"RestartPolicy": map[string]any{"Name": "unless-stopped"}}, map[string]any{"restartPolicy": []string{"unless-stopped"}}, "restart"},
		{"Sysctl", map[string]any{"Sysctls": map[string]string{"net.ipv4.ip_forward": "0"}}, map[string]any{"sysctls": []string{"net.ipv4.ip_forward"}}, "sysctl"},
		{"ExtraBindSources", map[string]any{"Binds": []string{w + ":/workspace", other + ":/extra"}}, map[string]any{"extraBindSources": []string{other}}, "workspace"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.policy(nil)
			host := map[string]any{"Binds": []string{w + ":/workspace"}}
			for k, v := range tc.field {
				host[k] = v
			}
			_, s, b := f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, host)
			denied(t, s, b, tc.reason)
			before := p.inspect(t)
			f.policy([]map[string]any{grant(w, tc.grants)})
			// File watcher reload is asynchronous. Poll the actual intended create;
			// successful attempts carry run labels and are cleaned unconditionally.
			deadline := time.Now().Add(10 * time.Second)
			for {
				_, s, b = f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, host)
				if s == 201 {
					break
				}
				if s != 403 || time.Now().After(deadline) {
					t.Fatalf("grant did not admit matching primary: status=%d body=%s", s, b)
				}
				time.Sleep(25 * time.Millisecond)
			}
			after := p.inspect(t)
			if before.ID != after.ID || before.State.Pid != after.State.Pid || before.State.StartedAt != after.State.StartedAt {
				t.Fatal("proxy restarted across live exception edit")
			}
			for _, control := range []struct {
				name, h string
				labels  map[string]string
			}{{"UnlabeledSidecar", workspaceHeader, map[string]string{}}, {"ThrowawayUnlabeled", throwawayHeader, map[string]string{}}, {"ThrowawayLabeled", throwawayHeader, map[string]string{commandLabel: w}}} {
				t.Run(control.name, func(t *testing.T) {
					_, s, b := f.create(t, p, w, control.h, control.labels, host)
					denied(t, s, b, tc.reason)
				})
			}
		})
	}
	f.policy(nil)
	// Own socket folder and own 0700 subfolder admit; sibling never does.
	ownSocket := filepath.Join(f.root, "workspace-sockets", "alpha", "private")
	must(t, os.Mkdir(ownSocket, 0700))
	_, s, b = f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, map[string]any{"Binds": []string{ownSocket + ":/socket"}})
	expect(t, s, 201, b)
	siblingSocket := filepath.Join(f.root, "workspace-sockets", "beta")
	_, s, b = f.create(t, p, w, workspaceHeader, nil, map[string]any{"Binds": []string{siblingSocket + ":/socket"}})
	denied(t, s, b, "workspace")
	link := filepath.Join(w, "escape")
	must(t, os.Symlink(other, link))
	_, s, b = f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, map[string]any{"Binds": []string{link + ":/outside"}})
	denied(t, s, b, "workspace")
	// Profiles never reach native libpod/overlay or an unapproved network driver.
	s, b = p.request(t, "POST", "/libpod/containers/create", w, workspaceHeader, map[string]any{})
	denied(t, s, b, "libpod")
	s, b = p.request(t, "POST", "/networks/create", w, workspaceHeader, map[string]any{"Name": "blocked-" + f.run, "Driver": "macvlan", "Labels": map[string]string{runLabel: f.run}})
	denied(t, s, b, "driver")
}

func testBindSwap(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("bind-a")
	other := f.workspace("bind-b")
	source := filepath.Join(w, "data")
	must(t, os.Mkdir(source, 0755))
	write(t, filepath.Join(source, "marker"), []byte("original"))
	write(t, filepath.Join(other, "marker"), []byte("replacement"))
	id, s, b := f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, map[string]any{"Binds": []string{source + ":/data"}})
	expect(t, s, 201, b)
	s, b = p.request(t, "POST", "/containers/"+id+"/start", w, workspaceHeader, nil)
	expect(t, s, 204, b)
	c, _ := p.client(t, w, workspaceHeader)
	if got := strings.TrimSpace(f.exec(t, c, id, []string{"cat", "/data/marker"})); got != "original" {
		t.Fatalf("real bind mount marker=%q", got)
	}
	must(t, f.direct.ContainerStop(f.ctx, id, container.StopOptions{}))
	must(t, os.Rename(source, source+"-saved"))
	must(t, os.Symlink(other, source))
	s, b = p.request(t, "POST", "/containers/"+id+"/start", w, workspaceHeader, nil)
	denied(t, s, b, "outside the request's workspace")
	s, b = p.request(t, "POST", "/containers/"+id+"/restart", w, workspaceHeader, nil)
	denied(t, s, b, "not in the Menagerie profile")
	variant := f.startProxy(t, "restart-route")
	s, b = variant.request(t, "POST", "/containers/"+id+"/restart", w, "", nil)
	denied(t, s, b, "names no workspace")
	s, b = variant.request(t, "POST", "/containers/"+id+"/restart", w, workspaceHeader, nil)
	denied(t, s, b, "outside the request's workspace")
	must(t, os.Remove(source))
	must(t, os.Rename(source+"-saved", source))
	s, b = variant.request(t, "POST", "/containers/"+id+"/restart", w, workspaceHeader, nil)
	expect(t, s, 204, b)
	t.Log("restart-route is a controlled route-enabled variant; exact baseline restart remains route-denied")
}

func testVolumeSwap(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("volume-a")
	other := f.workspace("volume-b")
	create := func(name string) (string, string) {
		source := filepath.Join(w, name)
		must(t, os.Mkdir(source, 0755))
		write(t, filepath.Join(source, "marker"), []byte("original-"+name))
		target := filepath.Join(other, name)
		must(t, os.Mkdir(target, 0755))
		write(t, filepath.Join(target, "marker"), []byte("replacement-"+name))
		// DriverOpts are denied by the exact profile. This owned fixture is
		// created directly, then start inspects its device using the actual proxy.
		v, e := f.direct.VolumeCreate(f.ctx, volume.CreateOptions{Name: "device-" + name + "-" + f.run, Driver: "local", DriverOpts: map[string]string{"type": "none", "o": "bind", "device": source}, Labels: map[string]string{runLabel: f.run, "com.sockguard.owner": "menagerie"}})
		must(t, e)
		c, e := f.direct.ContainerCreate(f.ctx, &container.Config{Image: f.baseImage, Cmd: []string{"sleep", "3600"}, Labels: map[string]string{runLabel: f.run, primaryLabel: w, "com.sockguard.owner": "menagerie"}}, &container.HostConfig{Mounts: []mount.Mount{{Type: mount.TypeBind, Source: w, Target: "/workspace"}, {Type: mount.TypeVolume, Source: v.Name, Target: "/data"}}}, nil, nil, "")
		must(t, e)
		return c.ID, source
	}
	id, source := create("proxy")
	s, b := p.request(t, "POST", "/containers/"+id+"/start", w, workspaceHeader, nil)
	expect(t, s, 204, b)
	c, _ := p.client(t, w, workspaceHeader)
	if got := strings.TrimSpace(f.exec(t, c, id, []string{"cat", "/data/marker"})); got != "original-proxy" {
		t.Fatalf("unchanged-device marker=%q", got)
	}
	inspected, e := f.direct.ContainerInspect(f.ctx, id)
	must(t, e)
	t.Logf("REAL_VOLUME_MOUNTS=%+v", inspected.Mounts)
	must(t, f.direct.ContainerStop(f.ctx, id, container.StopOptions{}))
	must(t, os.Rename(source, source+"-saved"))
	must(t, os.Symlink(filepath.Join(other, "proxy"), source))
	s, b = p.request(t, "POST", "/containers/"+id+"/start", w, workspaceHeader, nil)
	denied(t, s, b, "outside the request's workspace")
	// Separate named variant, reusing the existing proxy variant if present.
	restart := f.startProxy(t, "restart-route-volume")
	s, b = restart.request(t, "POST", "/containers/"+id+"/restart", w, workspaceHeader, nil)
	denied(t, s, b, "outside the request's workspace")
	must(t, os.Remove(source))
	must(t, os.Rename(source+"-saved", source))
	s, b = restart.request(t, "POST", "/containers/"+id+"/restart", w, workspaceHeader, nil)
	expect(t, s, 204, b)
	// The independent direct-daemon control does not reuse proxy-denied state.
	directID, directSource := create("direct")
	must(t, f.direct.ContainerStart(f.ctx, directID, container.StartOptions{}))
	before := strings.TrimSpace(f.exec(t, f.direct, directID, []string{"cat", "/data/marker"}))
	if before != "original-direct" {
		t.Fatalf("direct control initial marker=%q", before)
	}
	must(t, f.direct.ContainerStop(f.ctx, directID, container.StopOptions{}))
	must(t, os.Rename(directSource, directSource+"-saved"))
	must(t, os.Symlink(filepath.Join(other, "direct"), directSource))
	must(t, f.direct.ContainerStart(f.ctx, directID, container.StartOptions{}))
	after := strings.TrimSpace(f.exec(t, f.direct, directID, []string{"cat", "/data/marker"}))
	switch after {
	case "replacement-direct":
		t.Logf("DEVICE_MECHANISM_RERESOLVED before=%q after=%q source=%s target=%s", before, after, directSource, filepath.Join(other, "direct"))
	case "original-direct":
		t.Logf("DEVICE_MECHANISM_NOT_RERESOLVED before=%q after=%q; approved proxy recheck retained, mechanism limit recorded", before, after)
	default:
		t.Fatalf("direct marker control inconclusive: %q", after)
	}
}

func tarBytes(t *testing.T, headers []*tar.Header, contents map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, h := range headers {
		if data, ok := contents[h.Name]; ok {
			h.Size = int64(len(data))
		}
		must(t, tw.WriteHeader(h))
		if data, ok := contents[h.Name]; ok {
			_, e := tw.Write([]byte(data))
			must(t, e)
		}
		t.Logf("TAR_ENTRY name=%q type=%d target=%q mode=%o", h.Name, h.Typeflag, h.Linkname, h.Mode)
	}
	must(t, tw.Close())
	return b.Bytes()
}
func testArchive(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("copy")
	id, s, b := f.create(t, p, w, throwawayHeader, map[string]string{commandLabel: w}, map[string]any{"Binds": []string{w + ":/workspace"}}, []string{"sh", "-c", "printf command-output"})
	expect(t, s, 201, b)
	c, _ := p.client(t, w, throwawayHeader)
	t.Run("CapturedConsumerArchive", func(t *testing.T) {
		data, e := os.ReadFile("/src/tests/acceptance/testdata/consumer-archive.tar")
		must(t, e)
		metadata, e := os.ReadFile("/src/tests/acceptance/testdata/consumer-archive.json")
		must(t, e)
		var input struct {
			Hash   string `json:"archive_sha256"`
			Source string `json:"source_path"`
			Target string `json:"container_target"`
			Commit string `json:"producer_commit"`
		}
		must(t, json.Unmarshal(metadata, &input))
		if digest(data) != input.Hash {
			t.Fatal("captured consumer tar bytes drifted")
		}
		if input.Target != "/" {
			t.Fatal("captured consumer target differs from accepted profile")
		}
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, e := tr.Next()
			if e == io.EOF {
				break
			}
			must(t, e)
			if strings.HasPrefix(h.Name, "/") {
				t.Fatal("actual consumer emitted absolute tar entry name")
			}
			t.Logf("ACTUAL_PRODUCER_ENTRY commit=%s name=%q link=%q type=%d", input.Commit, h.Name, h.Linkname, h.Typeflag)
		}
		must(t, c.CopyToContainer(f.ctx, id, input.Target, bytes.NewReader(data), container.CopyToContainerOptions{CopyUIDGID: true}))
		out, _, e := c.CopyFromContainer(f.ctx, id, input.Source)
		must(t, e)
		defer out.Close()
		copied := tar.NewReader(out)
		found := false
		for {
			h, e := copied.Next()
			if e == io.EOF {
				break
			}
			must(t, e)
			if strings.HasSuffix(h.Name, "/sub/file") {
				b, e := io.ReadAll(copied)
				must(t, e)
				found = string(b) == "consumer-copy-marker"
			}
		}
		if !found {
			t.Fatal("actual consumer tar roundtrip lost marker")
		}
		t.Logf("ACTUAL_PRODUCER_COPY target=%s source=%s archive=%s", input.Target, input.Source, input.Hash)
	})

	headers := []*tar.Header{{Name: "tmp/candidate", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "tmp/candidate/file", Typeflag: tar.TypeReg, Mode: 0644}, {Name: "tmp/candidate/sub", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "tmp/candidate/relative", Typeflag: tar.TypeSymlink, Linkname: "file", Mode: 0777}, {Name: "tmp/candidate/hard", Typeflag: tar.TypeLink, Linkname: "tmp/candidate/file", Mode: 0644}, {Name: "tmp/candidate/absolute", Typeflag: tar.TypeSymlink, Linkname: "/tmp/candidate/file", Mode: 0777}}
	payload := tarBytes(t, headers, map[string]string{"tmp/candidate/file": "copy-marker"})
	must(t, c.CopyToContainer(f.ctx, id, "/", bytes.NewReader(payload), container.CopyToContainerOptions{}))
	r, _, e := c.CopyFromContainer(f.ctx, id, "/tmp/candidate")
	must(t, e)
	tr := tar.NewReader(r)
	found := false
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		must(t, e)
		t.Logf("COPY_OUT_ENTRY name=%q link=%q type=%d", h.Name, h.Linkname, h.Typeflag)
		if h.Name == "candidate/file" {
			data, e := io.ReadAll(tr)
			must(t, e)
			found = string(data) == "copy-marker"
		}
	}
	must(t, r.Close())
	if !found {
		t.Fatal("copy-out lost ordinary file marker")
	}
	for _, tc := range []struct {
		name, reason string
		h            *tar.Header
	}{{"SetID", "setuid/setgid", &tar.Header{Name: "tmp/blocked", Typeflag: tar.TypeReg, Mode: 04755}}, {"Device", "device node", &tar.Header{Name: "tmp/blocked", Typeflag: tar.TypeChar, Mode: 0600, Devmajor: 1, Devminor: 3}}, {"AbsoluteName", "must be relative", &tar.Header{Name: "/tmp/blocked", Typeflag: tar.TypeReg, Mode: 0644}}, {"Traversal", "must be relative", &tar.Header{Name: "../blocked", Typeflag: tar.TypeReg, Mode: 0644}}} {
		t.Run(tc.name, func(t *testing.T) {
			s, b := p.request(t, "PUT", "/containers/"+id+"/archive?path=/", w, throwawayHeader, tarBytes(t, []*tar.Header{tc.h}, nil))
			denied(t, s, b, tc.reason)
		})
	}
	// Owned in-container paths only. Observe whether the daemon follows an
	// admitted absolute symlink for a later regular entry; never target host paths.
	through := tarBytes(t, []*tar.Header{{Name: "tmp/destination", Typeflag: tar.TypeDir, Mode: 0755}, {Name: "tmp/link", Typeflag: tar.TypeSymlink, Linkname: "/tmp/destination", Mode: 0777}, {Name: "tmp/link/marker", Typeflag: tar.TypeReg, Mode: 0644}}, map[string]string{"tmp/link/marker": "through-link"})
	e = c.CopyToContainer(f.ctx, id, "/", bytes.NewReader(through), container.CopyToContainerOptions{})
	if e != nil {
		t.Logf("WRITE_THROUGH_RESULT daemon_rejected=%v", e)
	} else {
		r, _, e := c.CopyFromContainer(f.ctx, id, "/tmp/destination/marker")
		must(t, e)
		tr := tar.NewReader(r)
		_, e = tr.Next()
		must(t, e)
		data, e := io.ReadAll(tr)
		must(t, e)
		must(t, r.Close())
		if string(data) != "through-link" {
			t.Fatal("write-through marker differs")
		}
		t.Log("WRITE_THROUGH_RESULT owned absolute-link marker reached /tmp/destination/marker")
	}
	// Attach and wait are actual consumer command-container API calls.
	a, e := c.ContainerAttach(f.ctx, id, container.AttachOptions{Stream: true, Stdout: true, Stderr: true})
	must(t, e)
	defer a.Close()
	s, b = p.request(t, "POST", "/containers/"+id+"/start", w, throwawayHeader, nil)
	expect(t, s, 204, b)
	var attached bytes.Buffer
	_, e = stdcopy.StdCopy(&attached, &attached, a.Reader)
	must(t, e)
	if attached.String() != "command-output" {
		t.Fatalf("attach output=%q", attached.String())
	}
	status, errs := c.ContainerWait(f.ctx, id, container.WaitConditionNotRunning)
	select {
	case e := <-errs:
		must(t, e)
	case result := <-status:
		if result.StatusCode != 0 {
			t.Fatalf("command container exit=%d", result.StatusCode)
		}
		t.Logf("COMMAND_WAIT status=%d output=%q", result.StatusCode, attached.String())
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	foreign, e := f.direct.ContainerCreate(f.ctx, &container.Config{Image: f.baseImage, Labels: map[string]string{runLabel: f.run, "com.sockguard.owner": "different-owner"}}, nil, nil, nil, "")
	must(t, e)
	s, b = p.request(t, "GET", "/containers/"+foreign.ID+"/archive?path=/tmp", w, throwawayHeader, nil)
	if s == 200 {
		t.Fatal("read exfiltration reached foreign-owner fixture")
	}
	t.Logf("FOREIGN_READ status=%d body=%s", s, b)
}

func testExec(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("exec")
	id, s, b := f.create(t, p, w, workspaceHeader, map[string]string{primaryLabel: w}, nil)
	expect(t, s, 201, b)
	s, b = p.request(t, "POST", "/containers/"+id+"/start", w, workspaceHeader, nil)
	expect(t, s, 204, b)
	c, _ := p.client(t, w, workspaceHeader)
	if got := strings.TrimSpace(f.exec(t, c, id, []string{"sh", "-c", "printf arbitrary-argv"})); got != "arbitrary-argv" {
		t.Fatal("allow_any_command did not execute argv")
	}
	s, b = p.request(t, "POST", "/containers/"+id+"/exec", w, workspaceHeader, map[string]any{"User": "0", "Cmd": []string{"id", "-u"}})
	expect(t, s, 201, b)
	s, b = p.request(t, "POST", "/containers/"+id+"/exec", w, workspaceHeader, map[string]any{"User": "1000", "Privileged": true, "Cmd": []string{"true"}})
	denied(t, s, b, "privileged")
	s, b = p.request(t, "POST", "/containers/"+id+"/exec", w, "", map[string]any{"User": "1000", "Cmd": []string{"true"}})
	denied(t, s, b, "names no workspace")
	unlabeled, s, b := f.create(t, p, w, workspaceHeader, nil, nil)
	expect(t, s, 201, b)
	s, b = p.request(t, "POST", "/containers/"+unlabeled+"/exec", w, workspaceHeader, map[string]any{"User": "1000", "Cmd": []string{"true"}})
	denied(t, s, b, "no matching workspace label")
	strict := f.startProxy(t, "strict-root")
	s, b = strict.request(t, "POST", "/containers/"+id+"/exec", w, workspaceHeader, map[string]any{"User": "0", "Cmd": []string{"true"}})
	denied(t, s, b, "root")
	t.Log("Root denial measured ONLY under named strict-root variant. Actual profile root=true admitted root independently.")
}

func testSocketPeers(t *testing.T, f *fixture, p *proxy) {
	binary, e := os.ReadFile("/acceptance.test")
	must(t, e)
	path := filepath.Join(f.root, "peer")
	write(t, path, binary)
	must(t, os.Chmod(path, 0755))
	for _, tc := range []struct {
		name, user string
		groups     []string
		want       int
	}{{"SupplementaryGroup", "10001:10002", []string{"20001"}, 0}, {"NoSocketGroup", "10001:10002", nil, 31}, {"NonmatchingUID", "10003:10002", []string{"20001"}, 32}} {
		t.Run(tc.name, func(t *testing.T) {
			c, e := f.direct.ContainerCreate(f.ctx, &container.Config{Image: f.baseImage, User: tc.user, Entrypoint: []string{path}, Env: []string{"ACCEPTANCE_PEER_PROBE=1", "PROBE_SOCKET=" + p.socket}, Labels: map[string]string{runLabel: f.run}}, &container.HostConfig{GroupAdd: tc.groups, CapDrop: []string{"ALL"}, Mounts: []mount.Mount{{Type: mount.TypeBind, Source: f.root, Target: f.root, ReadOnly: true}}}, nil, nil, "")
			must(t, e)
			must(t, f.direct.ContainerStart(f.ctx, c.ID, container.StartOptions{}))
			wait, errs := f.direct.ContainerWait(f.ctx, c.ID, container.WaitConditionNotRunning)
			select {
			case e := <-errs:
				must(t, e)
			case result := <-wait:
				if int(result.StatusCode) != tc.want {
					logs, _ := f.direct.ContainerLogs(f.ctx, c.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
					if logs != nil {
						b, _ := io.ReadAll(logs)
						_ = logs.Close()
						t.Log(string(b))
					}
					t.Fatalf("peer result=%d want=%d", result.StatusCode, tc.want)
				}
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			}
		})
	}
}

// The baseline's supplementary socket group is removed only in this isolated
// startup-failure control. No capability is added and baseline is not changed.
func testStartupChownFailure(t *testing.T, f *fixture, p *proxy) {
	base := p.inspect(t)
	raw, e := os.ReadFile(filepath.Join(f.root, "config-baseline.yaml"))
	must(t, e)
	controlDir := filepath.Join(f.root, "listener", "failed-chown")
	must(t, os.Mkdir(controlDir, 0777))
	must(t, os.Chmod(controlDir, 0777))
	socket := filepath.Join(controlDir, "menagerie.sock")
	config := filepath.Join(f.root, "config-failed-chown.yaml")
	rendered := []byte(strings.ReplaceAll(string(raw), p.socket, socket))
	write(t, config, rendered)
	host := base.HostConfig
	host.GroupAdd = nil
	for i, m := range host.Mounts {
		if m.Target == "/etc/sockguard/acceptance.yaml" {
			host.Mounts[i].Source = config
		}
	}
	t.Logf("STARTUP_CONTROL variant=no-socket-group rendered=%s baseline=%s capabilities=%v", digest(rendered), digest(raw), host.CapAdd)
	c, e := f.direct.ContainerCreate(f.ctx, base.Config, host, nil, nil, "")
	must(t, e)
	must(t, f.direct.ContainerStart(f.ctx, c.ID, container.StartOptions{}))
	wait, errs := f.direct.ContainerWait(f.ctx, c.ID, container.WaitConditionNotRunning)
	select {
	case e := <-errs:
		must(t, e)
	case result := <-wait:
		if result.StatusCode != 1 {
			t.Fatalf("startup chown failure exit=%d want1", result.StatusCode)
		}
	case <-f.ctx.Done():
		t.Fatal(f.ctx.Err())
	}
	logs, e := f.direct.ContainerLogs(f.ctx, c.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	must(t, e)
	defer logs.Close()
	var output bytes.Buffer
	_, e = stdcopy.StdCopy(&output, &output, logs)
	must(t, e)
	if !strings.Contains(strings.ToLower(output.String()), "chown") || !strings.Contains(strings.ToLower(output.String()), "operation not permitted") {
		t.Fatalf("wrong startup failure: %s", &output)
	}
	if _, e = os.Stat(socket); !os.IsNotExist(e) {
		t.Fatalf("failed chown left socket: %v", e)
	}
	t.Logf("STARTUP_CHOWN_FAILED_CLOSED exit=1 socket_removed=true output=%s", &output)
}

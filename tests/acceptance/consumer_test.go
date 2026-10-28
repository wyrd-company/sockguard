//go:build sockguardacceptance

// relationships:
//
//	references: [testdata/profile-input.json, ../../docs/fork-endpoints.md]
package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"

	"github.com/wyrd-company/devcontainer-builder/pkg/builder"
	dockerhost "github.com/wyrd-company/devcontainer-builder/pkg/host/docker"
	"github.com/wyrd-company/devcontainer-builder/pkg/host/dockercompose"
	"github.com/wyrd-company/devcontainer-builder/pkg/spec"
)

func loadSpec(t *testing.T, w, json string) *spec.DevContainer {
	t.Helper()
	write(t, filepath.Join(w, ".devcontainer", "devcontainer.json"), []byte(json))
	dc, e := spec.LoadFromWorkspace(w)
	must(t, e)
	return dc
}
func testDockerConsumer(t *testing.T, f *fixture, p *proxy) {
	w := f.workspace("build")
	socket := filepath.Join(f.root, "workspace-sockets", "build")
	dc := loadSpec(t, w, fmt.Sprintf(`{"build":{"dockerfile":"Dockerfile"},"workspaceFolder":"/workspace","containerEnv":{"EXAMPLE_MODE":"ready"},"mounts":["type=bind,source=%s,target=/socket"],"onCreateCommand":["sh","-c","printf '%%s' \"$EXAMPLE_MODE\" > /workspace/env-marker"],"userEnvProbe":"none"}`, socket))
	write(t, filepath.Join(w, ".devcontainer", "Dockerfile"), []byte("FROM "+f.baseImage+"\nRUN printf build-marker > /build-marker\n"))
	headerless, buildCalls := p.client(t, "", "")
	b := builder.New()
	imageRef := "acceptance-consumer:" + f.run
	build := func(clientHeaderless bool) error {
		if !clientHeaderless {
			t.Fatal("build must exercise headerless /grpc and /session")
		}
		_, e := b.Build(f.ctx, builder.Options{Spec: dc, Workspace: w, Docker: headerless, Tags: []string{imageRef}, Labels: map[string]string{runLabel: f.run}, Load: true, NoCache: true, SkipFeatures: true, OmitSyntaxDirective: true, Progress: "plain", Stdout: os.Stdout, Stderr: os.Stderr, WorkDir: filepath.Join(w, "build-work")})
		return e
	}
	t.Run("BuildHeaderless", func(t *testing.T) {
		must(t, build(true))
		f.recordImage(imageRef)
		seen := map[string]bool{}
		for _, c := range buildCalls.snapshot() {
			if strings.HasSuffix(c.Path, "/grpc") || strings.HasSuffix(c.Path, "/session") {
				if c.Header {
					t.Fatalf("build tunnel unexpectedly got identity header: %+v", c)
				}
				seen[filepath.Base(c.Path)] = true
			}
		}
		if !seen["grpc"] || !seen["session"] {
			t.Fatalf("did not observe both headerless build tunnels: %+v", buildCalls.snapshot())
		}
	})
	if t.Failed() {
		return
	}
	t.Run("MetadataDefaultClientReadOnly", func(t *testing.T) {
		metadataClient, metadataCalls := p.client(t, "", "")
		t.Setenv("DOCKER_HOST", metadataClient.DaemonHost())
		_, e := b.BaseMetadata(f.ctx, &spec.DevContainer{Image: imageRef}, builder.Options{})
		must(t, e)
		calls := metadataCalls.snapshot()
		if len(calls) == 0 {
			t.Fatal("metadata boundary observed zero requests")
		}
		for _, c := range calls {
			if c.Header || c.Method != "GET" && c.Method != "HEAD" || strings.Contains(c.Path, "/exec") || strings.Contains(c.Path, "/start") || strings.Contains(c.Path, "/create") {
				t.Fatalf("metadata default client sent a write or header: %+v", c)
			}
		}
		t.Logf("METADATA_DEFAULT_CLIENT_CALLS=%+v", calls)
	})
	cli, calls := p.client(t, w, workspaceHeader)
	h := dockerhost.New(cli, dockerhost.Options{Stdout: os.Stdout, Stderr: os.Stderr})
	var id string
	t.Run("UpWithRedactedInspectEnvironment", func(t *testing.T) {
		res, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: imageRef, ImageBuilt: true})
		must(t, e)
		id = res.ContainerID
		if !res.CreatedThisCall || !res.StartedThisCall {
			t.Fatal("first up did not create/start")
		}
		marker, e := os.ReadFile(filepath.Join(w, "env-marker"))
		must(t, e)
		if string(marker) != "ready" {
			t.Fatalf("lifecycle environment under default inspect redaction=%q", marker)
		}
		if got := strings.TrimSpace(f.exec(t, cli, id, []string{"cat", "/build-marker"})); got != "build-marker" {
			t.Fatalf("consumer image marker=%q", got)
		}
	})
	if id == "" {
		return
	}
	t.Run("Stop", func(t *testing.T) {
		must(t, h.Stop(f.ctx, w))
		c, e := f.direct.ContainerInspect(f.ctx, id)
		must(t, e)
		if c.State.Running {
			t.Fatal("consumer stop did not stop its workspace")
		}
	})
	t.Run("Rebuild", func(t *testing.T) {
		must(t, h.RemoveByID(f.ctx, id))
		must(t, build(true))
		f.recordImage(imageRef)
		res, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: imageRef, ImageBuilt: true})
		must(t, e)
		if res.ContainerID == id || !res.CreatedThisCall {
			t.Fatal("rebuild did not replace the container")
		}
		must(t, h.Stop(f.ctx, w))
	})
	t.Logf("DCB_DOCKER_CALLS=%+v", calls.snapshot())
	t.Run("LLBBridgeOffDeniesSameBuild", func(t *testing.T) {
		off := f.startProxy(t, "llb-off")
		offClient, offCalls := off.client(t, "", "")
		_, e := b.Build(f.ctx, builder.Options{Spec: dc, Workspace: w, Docker: offClient, Tags: []string{"acceptance-off:" + f.run}, Labels: map[string]string{runLabel: f.run}, Load: true, NoCache: true, SkipFeatures: true, OmitSyntaxDirective: true, Progress: "plain", Stderr: os.Stderr, WorkDir: filepath.Join(w, "off-work")})
		must(t, llbOffBuildDenial(e, offCalls.snapshot()))
		t.Logf("LLB_OFF_CALLS=%+v", offCalls.snapshot())
		t.Logf("LLB_OFF_INTENDED_DENIAL=%v", e)
	})
}

func testDockerIdentityConsumer(t *testing.T, f *fixture, p *proxy) {
	t.Run("PrivilegedDeniedThenLiveGranted", func(t *testing.T) {
		w := f.workspace("grant-consumer")
		dc := loadSpec(t, w, fmt.Sprintf(`{"image":%q,"privileged":true,"userEnvProbe":"none"}`, f.baseImage))
		cli, denialCalls := p.client(t, w, workspaceHeader)
		h := dockerhost.New(cli, dockerhost.Options{})
		_, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: f.baseImage})
		if e == nil {
			t.Fatalf("DCB privileged denial=%v", e)
		}
		assertDeniedCall(t, denialCalls, "/containers/create", "privileged")
		before := p.inspect(t)
		f.policy([]map[string]any{grant(w, map[string]any{"privileged": true})})
		deadline := time.Now().Add(10 * time.Second)
		for {
			res, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: f.baseImage})
			if e == nil {
				t.Logf("DCB_GRANTED_CONTAINER=%s", res.ContainerID)
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(e)
			}
			assertDeniedCall(t, denialCalls, "/containers/create", "privileged")
			time.Sleep(25 * time.Millisecond)
		}
		after := p.inspect(t)
		if before.ID != after.ID || before.State.Pid != after.State.Pid || before.State.StartedAt != after.State.StartedAt {
			t.Fatal("proxy identity changed on live file edit")
		}
		f.policy(nil)
	})
	t.Run("ForgedRunArgsPrimaryLabelDenied", func(t *testing.T) {
		w := f.workspace("forged")
		other := f.workspace("forged-other")
		dc := loadSpec(t, w, fmt.Sprintf(`{"image":%q,"runArgs":["--label",%q]}`, f.baseImage, primaryLabel+"="+other))
		cli, denialCalls := p.client(t, w, workspaceHeader)
		h := dockerhost.New(cli, dockerhost.Options{})
		_, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: f.baseImage})
		if e == nil {
			t.Fatalf("forged actual consumer label was not denied: %v", e)
		}
		assertDeniedCall(t, denialCalls, "/containers/create", "workspace")
	})

	t.Run("SymlinkSourceDenied", func(t *testing.T) {
		w := f.workspace("consumer-link")
		other := f.workspace("consumer-outside")
		link := filepath.Join(w, "escape")
		must(t, os.Symlink(other, link))
		dc := loadSpec(t, w, fmt.Sprintf(`{"image":%q,"mounts":[%q]}`, f.baseImage, "type=bind,source="+link+",target=/extra"))
		cli, calls := p.client(t, w, workspaceHeader)
		h := dockerhost.New(cli, dockerhost.Options{})
		_, e := h.Up(f.ctx, dockerhost.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w, Image: f.baseImage})
		if e == nil {
			t.Fatal("DCB symlink source unexpectedly admitted")
		}
		assertDeniedCall(t, calls, "/containers/create", "workspace")
	})
}

func testComposeConsumer(t *testing.T, f *fixture, p *proxy) {
	type populatedProject struct {
		name, workspace string
		host            *dockercompose.Host
		single          *dockerhost.Host
		initial, latest *dockercompose.UpResult
		calls           *recorder
	}
	var projects []populatedProject
	for _, name := range []string{"compose-a", "compose-b"} {
		w := f.workspace(name)
		socket := filepath.Join(f.root, "workspace-sockets", name)
		dc := loadSpec(t, w, `{"dockerComposeFile":"compose.yaml","service":"primary","workspaceFolder":"/workspace","userEnvProbe":"none","overrideCommand":false}`)
		compose := func(revision string) {
			write(t, filepath.Join(w, ".devcontainer", "settings.txt"), []byte(revision))
			write(t, filepath.Join(w, ".devcontainer", "compose.yaml"), []byte(fmt.Sprintf(`services:
  primary:
    image: %s
    command: [sleep, "3600"]
    volumes: [%q, %q]
  sidecar:
    image: %s
    command: [sleep, "3600"]
    environment: {EXAMPLE_REVISION: %q}
    volumes: [data:/data]
    configs: [{source: settings, target: /settings.txt}, {source: generated, target: /generated.txt}]
networks:
  default: {driver: bridge}
volumes:
  data: {}
configs:
  settings: {file: ./settings.txt}
  generated: {content: %q}
`, f.baseImage, w+":/workspace", socket+":/socket", f.baseImage, revision, "inline-"+revision)))
		}
		compose("first")
		cli, calls := p.client(t, w, workspaceHeader)
		staging := filepath.Join(f.root, "compose-staging", name)
		h := dockercompose.New(cli, dockercompose.Options{Stdout: os.Stdout, Stderr: os.Stderr, UserDataFolder: staging})
		var first, second *dockercompose.UpResult
		var ledger string
		t.Run(name+"_Up", func(t *testing.T) {
			var e error
			first, e = h.Up(f.ctx, dockercompose.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w})
			must(t, e)
			_, e = composeServiceIDs(first.PrimaryContainerID, first.ContainerIDs)
			must(t, e)
			var sidecarMounts []container.MountPoint
			for service, id := range first.ContainerIDs {
				c, e := f.direct.ContainerInspect(f.ctx, id)
				must(t, e)
				if c.Config.Labels[runLabel] != f.run || c.Config.Labels["com.sockguard.owner"] != "menagerie" {
					t.Fatalf("resource provenance/ownership missing: %s %+v", service, c.Config.Labels)
				}
				if service == "primary" && c.Config.Labels[primaryLabel] != w {
					t.Fatal("primary fixture does not carry its own workspace label")
				}
				if service == "sidecar" {
					sidecarMounts = c.Mounts
				}
				if service == "sidecar" && c.Config.Labels[primaryLabel] != "" {
					t.Fatal("consumer sidecar unexpectedly has primary label")
				}
			}
			// Read only this run/workspace's actual materialization record. Link its
			// name/root labels to the inline config's inspected read-only bind.
			records, e := f.direct.VolumeList(f.ctx, volume.ListOptions{Filters: filters.NewArgs(
				filters.Arg("label", runLabel+"="+f.run), filters.Arg("label", primaryLabel+"="+w), filters.Arg("label", composeObjectRootLabel),
			)})
			must(t, e)
			ledger, e = mountedConfigLedger(records.Volumes, sidecarMounts, f.run, w, staging, "menagerie")
			must(t, e)
			t.Logf("COMPOSE_MOUNTED_LEDGER workspace=%s name=%s mounts=%+v", w, ledger, sidecarMounts)
		})
		if first == nil {
			continue
		}
		t.Run(name+"_ChangedSidecarUp", func(t *testing.T) {
			compose("second")
			var e error
			upStart := len(calls.snapshot())
			second, e = h.Up(f.ctx, dockercompose.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w})
			upCalls := calls.snapshot()
			upEnd := len(upCalls)
			must(t, e)
			_, e = composeServiceIDs(second.PrimaryContainerID, second.ContainerIDs)
			must(t, e)
			must(t, ledgerRetirementDuringUp(upCalls, upStart, upEnd, ledger))
			_, inspectErr := f.direct.VolumeInspect(f.ctx, ledger)
			must(t, retiredLedgerAbsent(inspectErr))
			t.Logf("COMPOSE_SECOND_UP_LEDGER_DELETE workspace=%s ledger=%s range=[%d,%d) calls=%+v", w, ledger, upStart, upEnd, upCalls[upStart:upEnd])
			if second.PrimaryContainerID != first.PrimaryContainerID {
				t.Fatal("unchanged primary was replaced")
			}
			if second.ContainerIDs["sidecar"] == first.ContainerIDs["sidecar"] {
				t.Fatal("changed sidecar was not recreated")
			}
			if got := strings.TrimSpace(f.exec(t, cli, second.PrimaryContainerID, []string{"sh", "-c", "printf compose-exec"})); got != "compose-exec" {
				t.Fatal("real allow_any_command did not execute Compose primary command")
			}
		})
		t.Run(name+"_MissingWorkspaceLookup", func(t *testing.T) {
			other := f.workspace(name + "-absent")
			_, e := dockerhost.New(cli, dockerhost.Options{}).Inspect(f.ctx, other)
			if e != dockerhost.ErrContainerNotFound {
				t.Fatalf("missing workspace lookup crossed owner partition: %v", e)
			}
		})
		if second != nil {
			projects = append(projects, populatedProject{name: name, workspace: w, host: h, single: dockerhost.New(cli, dockerhost.Options{}), initial: first, latest: second, calls: calls})
		}
		t.Run(name+"_EndpointInventory", func(t *testing.T) {
			observed := calls.snapshot()
			for _, want := range []struct {
				method, path string
				status       int
			}{{"GET", "/networks", 200}, {"POST", "/networks/create", 201}, {"GET", "/volumes", 200}, {"POST", "/volumes/create", 201}} {
				found := false
				for _, c := range observed {
					if exactAPICall(c, want.method, want.path, want.status) {
						found = true
					}
				}
				if !found {
					t.Fatalf("required admitted endpoint missing: %s %s calls=%+v", want.method, want.path, observed)
				}
			}
			t.Logf("DCB_COMPOSE_CALLS workspace=%s calls=%+v", name, observed)
		})
	}
	t.Run("PopulatedWorkspaceLookupIsolation", func(t *testing.T) {
		if len(projects) != 2 {
			t.Fatalf("two populated workspace projects required, got %d", len(projects))
		}
		for _, project := range projects {
			t.Run(project.name, func(t *testing.T) {
				wantPrimary := []string{project.latest.PrimaryContainerID}
				single, e := project.single.Inspect(f.ctx, project.workspace)
				must(t, e)
				must(t, workspaceLookupIDs(project.workspace, []string{single.ID}, wantPrimary))
				primary, e := project.host.InspectPrimary(f.ctx, project.workspace)
				must(t, e)
				must(t, workspaceLookupIDs(project.workspace, []string{primary.ID}, wantPrimary))
				inspected, e := project.host.Inspect(f.ctx, project.workspace)
				must(t, e)
				var got, want []string
				for _, c := range inspected.Containers {
					got = append(got, c.ID)
				}
				for _, id := range project.latest.ContainerIDs {
					want = append(want, id)
				}
				must(t, workspaceLookupIDs(project.workspace, got, want))
				t.Logf("TWO_POPULATED_LOOKUPS workspace=%s single=%s primary=%s project=%v expected=%v", project.workspace, single.ID, primary.ID, got, want)
			})
		}
	})
	for _, project := range projects {
		t.Run(project.name+"_Stop", func(t *testing.T) {
			must(t, project.host.Stop(f.ctx, project.workspace))
			for _, id := range project.initial.ContainerIDs {
				c, e := f.direct.ContainerInspect(f.ctx, id)
				if dockerclient.IsErrNotFound(e) {
					continue
				}
				must(t, e)
				if c.State.Running {
					t.Fatalf("own initial container still running: %s", id)
				}
			}
			for _, id := range project.latest.ContainerIDs {
				c, e := f.direct.ContainerInspect(f.ctx, id)
				must(t, e)
				if c.State.Running {
					t.Fatalf("own second-up container still running: %s", id)
				}
			}
			t.Logf("DCB_COMPOSE_STOP_CALLS workspace=%s calls=%+v", project.workspace, project.calls.snapshot())
		})
	}
	t.Run("ForgedComposeSidecarLabelDenied", func(t *testing.T) {
		w := f.workspace("compose-forged")
		other := f.workspace("compose-foreign")
		dc := loadSpec(t, w, `{"dockerComposeFile":"compose.yaml","service":"primary","workspaceFolder":"/workspace"}`)
		write(t, filepath.Join(w, ".devcontainer", "compose.yaml"), []byte(fmt.Sprintf(`services:
  primary:
    image: %s
    command: [sleep, "3600"]
    volumes: [%q]
  sidecar:
    image: %s
    labels: {%s: %q}
    command: [sleep, "3600"]
`, f.baseImage, w+":/workspace", f.baseImage, primaryLabel, other)))
		cli, denialCalls := p.client(t, w, workspaceHeader)
		h := dockercompose.New(cli, dockercompose.Options{UserDataFolder: filepath.Join(f.root, "compose-staging", "compose-forged")})
		_, e := h.Up(f.ctx, dockercompose.UpRequest{Spec: dc, SpecPath: dc.Path, LocalWorkspace: w})
		if e == nil {
			t.Fatalf("actual forged Compose sidecar label not denied: %v", e)
		}
		assertDeniedCall(t, denialCalls, "/containers/create", "workspace")
	})
}

func assertDeniedCall(t *testing.T, r *recorder, path, reason string) {
	t.Helper()
	for _, c := range r.snapshot() {
		if c.Status == 403 && strings.HasSuffix(c.Path, path) && strings.Contains(strings.ToLower(c.Reason), strings.ToLower(reason)) {
			return
		}
	}
	t.Fatalf("actual HTTP denial missing intended path/reason: path=%s reason=%s calls=%+v", path, reason, r.snapshot())
}

//go:build sockguardacceptance

// relationships:
//
//	references: [testdata/candidate.yaml, testdata/profile-input.json, ../../docs/fork-endpoints.md]
package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/volume"
	dockerclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"gopkg.in/yaml.v3"
)

const runLabel = "org.example.acceptance.run"
const workspaceHeader = "X-Sockguard-Workspace"
const throwawayHeader = "X-Sockguard-Throwaway-Workspace"
const primaryLabel = "devcontainer.local_folder"
const commandLabel = "menagerie.throwaway.workspace"

func TestMain(m *testing.M) {
	if os.Getenv("ACCEPTANCE_PEER_PROBE") != "" {
		sock := os.Getenv("PROBE_SOCKET")
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}
		c := http.Client{Transport: tr, Timeout: 10 * time.Second}
		r, e := c.Get("http://docker/_ping")
		if e != nil {
			fmt.Println("CONNECT_FAILED")
			os.Exit(31)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		fmt.Printf("STATUS=%d BODY=%s\n", r.StatusCode, b)
		if r.StatusCode == http.StatusOK {
			os.Exit(0)
		}
		if r.StatusCode == http.StatusForbidden {
			os.Exit(32)
		}
		os.Exit(33)
	}
	if os.Getenv("ACCEPTANCE_REQUIRED") != "1" {
		fmt.Fprintln(os.Stderr, "real daemon acceptance requires tests/acceptance/run.sh (no implicit skip)")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type call struct {
	Method, Path string
	Status       int
	Header       bool
	Reason       string
}
type recorder struct {
	base  http.RoundTripper
	label string
	mu    sync.Mutex
	calls []call
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	// Only a provenance label is added. Workspace/definition labels, mounts,
	// security settings and consumer calls are NEVER repaired by the harness.
	if req.Method == http.MethodPost && (strings.HasSuffix(req.URL.Path, "/containers/create") || strings.HasSuffix(req.URL.Path, "/networks/create") || strings.HasSuffix(req.URL.Path, "/volumes/create")) {
		b, e := io.ReadAll(req.Body)
		if e != nil {
			return nil, e
		}
		_ = req.Body.Close()
		var body map[string]any
		if e = json.Unmarshal(b, &body); e != nil {
			return nil, e
		}
		labels, _ := body["Labels"].(map[string]any)
		if labels == nil {
			labels = map[string]any{}
		}
		labels[runLabel] = r.label
		body["Labels"] = labels
		b, e = json.Marshal(body)
		if e != nil {
			return nil, e
		}
		req.Body = io.NopCloser(bytes.NewReader(b))
		req.ContentLength = int64(len(b))
	}
	resp, e := r.base.RoundTrip(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	reason := ""
	if resp != nil && status >= 400 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		reason = string(body)
	}
	r.mu.Lock()
	r.calls = append(r.calls, call{Method: req.Method, Path: req.URL.Path, Status: status, Header: req.Header.Get(workspaceHeader) != "" || req.Header.Get(throwawayHeader) != "", Reason: reason})
	r.mu.Unlock()
	return resp, e
}
func (r *recorder) snapshot() []call {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]call(nil), r.calls...)
}

type fixture struct {
	t                                               *testing.T
	ctx                                             context.Context
	direct                                          *dockerclient.Client
	root, run, source, forkImage, baseImage, canary string
	imageIDs                                        []string
	canaryStarted                                   string
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func write(t *testing.T, path string, b []byte) {
	t.Helper()
	must(t, os.MkdirAll(filepath.Dir(path), 0755))
	must(t, os.WriteFile(path, b, 0644))
}
func command(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b
	e := cmd.Run()
	t.Logf("command %s: %s", strings.Join(args, " "), b.String())
	must(t, e)
	return strings.TrimSpace(b.String())
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	t.Cleanup(cancel)
	if os.Getenv("BUILDKIT_HOST") != "" {
		t.Fatal("separate BuildKit is not the daemon variant under test")
	}
	d, e := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	must(t, e)
	root, e := os.MkdirTemp("/acceptance", "run-")
	must(t, e)
	must(t, os.Chmod(root, 0755))
	b := make([]byte, 8)
	_, e = rand.Read(b)
	must(t, e)
	f := &fixture{t: t, ctx: ctx, direct: d, root: root, run: hex.EncodeToString(b), source: "/src"}
	// Register cleanup before the first resource mutation, including setup failures.
	t.Cleanup(f.cleanup)
	for _, p := range []string{"workspaces", "workspace-sockets", "compose-staging", "exceptions", "listener", "docker-config"} {
		must(t, os.MkdirAll(filepath.Join(root, p), 0777))
		must(t, os.Chmod(filepath.Join(root, p), 0777))
	}
	must(t, os.MkdirAll("/acceptance/docker-config", 0755))
	v, e := d.ServerVersion(ctx)
	must(t, e)
	info, e := d.Info(ctx)
	must(t, e)
	t.Logf("RUNTIME version=%s api=%s driver=%s status=%v root=%s source=%s tree=%s store_input=%s daemon_image=%s", v.Version, v.APIVersion, info.Driver, info.DriverStatus, info.DockerRootDir, os.Getenv("ACCEPTANCE_SOURCE_HEAD"), os.Getenv("ACCEPTANCE_SOURCE_TREE"), os.Getenv("ACCEPTANCE_STORE"), os.Getenv("ACCEPTANCE_DAEMON_IMAGE"))
	t.Logf("RUNTIME_COMPONENTS=%+v", v.Components)
	f.forkImage = "acceptance-proxy:" + f.run
	f.baseImage = "acceptance-base:" + f.run
	// Exact authored fork Dockerfile; source commit and image ID are both logged.
	command(t, f.ctx, "docker", "build", "--no-cache", "--label", runLabel+"="+f.run, "--build-arg", "COMMIT="+os.Getenv("ACCEPTANCE_SOURCE_HEAD"), "--tag", f.forkImage, f.source)
	command(t, f.ctx, "docker", "buildx", "inspect", "default")
	f.recordImage(f.forkImage)
	dir := filepath.Join(root, "base")
	write(t, filepath.Join(dir, "Dockerfile"), []byte("FROM alpine:3.22\nLABEL "+runLabel+"="+f.run+"\n"))
	command(t, f.ctx, "docker", "build", "--no-cache", "--tag", f.baseImage, dir)
	f.recordImage(f.baseImage)
	// This canary predates the suite workload and is deliberately outside the
	// workload selector. It is owned explicitly and retired only after proof.
	c, e := d.ContainerCreate(ctx, &container.Config{Image: f.baseImage, Cmd: []string{"sleep", "3600"}, Labels: map[string]string{runLabel: f.run, "org.example.acceptance.canary": f.run}}, nil, nil, nil, "")
	must(t, e)
	f.canary = c.ID
	must(t, d.ContainerStart(ctx, c.ID, container.StartOptions{}))
	ci, e := d.ContainerInspect(ctx, c.ID)
	must(t, e)
	f.canaryStarted = ci.State.StartedAt
	t.Logf("CANARY_BEFORE id=%s started=%s", c.ID, f.canaryStarted)
	f.policy(nil)
	return f
}
func (f *fixture) recordImage(ref string) {
	i, e := f.direct.ImageInspect(f.ctx, ref)
	must(f.t, e)
	if i.Config.Labels[runLabel] != f.run {
		f.t.Fatalf("image missing run provenance: %s", ref)
	}
	f.imageIDs = append(f.imageIDs, i.ID)
	f.t.Logf("IMAGE ref=%s id=%s labels=%v", ref, i.ID, i.Config.Labels)
}
func (f *fixture) cleanup() {
	t := f.t
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	// All mutation targets come from the run selector or creation receipts.
	cs, e := f.direct.ContainerList(ctx, container.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil {
		t.Error(e)
	}
	for _, c := range cs {
		if c.ID == f.canary {
			continue
		}
		if e = f.direct.ContainerRemove(ctx, c.ID, container.RemoveOptions{Force: true, RemoveVolumes: true}); e != nil && !dockerclient.IsErrNotFound(e) {
			t.Error(e)
		}
	}
	ns, e := f.direct.NetworkList(ctx, network.ListOptions{Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil {
		t.Error(e)
	}
	for _, n := range ns {
		if e = f.direct.NetworkRemove(ctx, n.ID); e != nil && !dockerclient.IsErrNotFound(e) {
			t.Error(e)
		}
	}
	vs, e := f.direct.VolumeList(ctx, volume.ListOptions{Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil {
		t.Error(e)
	}
	for _, v := range vs.Volumes {
		if e = f.direct.VolumeRemove(ctx, v.Name, true); e != nil && !dockerclient.IsErrNotFound(e) {
			t.Error(e)
		}
	}
	cs, e = f.direct.ContainerList(ctx, container.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil || len(cs) > 1 || (len(cs) == 1 && cs[0].ID != f.canary) {
		t.Errorf("container residue=%v err=%v", cs, e)
	}
	if f.canary != "" {
		c, e := f.direct.ContainerInspect(ctx, f.canary)
		if e != nil || c.State == nil || !c.State.Running || c.State.StartedAt != f.canaryStarted {
			t.Errorf("pre-existing canary changed: id=%s err=%v", f.canary, e)
		} else {
			t.Logf("CANARY_AFTER id=%s running=%v started=%s", c.ID, c.State.Running, c.State.StartedAt)
		}
		if e = f.direct.ContainerRemove(ctx, f.canary, container.RemoveOptions{Force: true}); e != nil {
			t.Error(e)
		}
	}
	// Build failures may publish an image before returning an error. Select
	// every owned labelled output, including one not yet in a success receipt.
	ownedImages, e := f.direct.ImageList(ctx, image.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil {
		t.Error(e)
	}
	for _, owned := range ownedImages {
		if _, e = f.direct.ImageRemove(ctx, owned.ID, image.RemoveOptions{Force: true}); e != nil && !dockerclient.IsErrNotFound(e) {
			t.Error(e)
		}
	}

	cs, e = f.direct.ContainerList(ctx, container.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil || len(cs) != 0 {
		t.Errorf("CleanupResidue containers=%d err=%v", len(cs), e)
	}
	ns, e = f.direct.NetworkList(ctx, network.ListOptions{Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil || len(ns) != 0 {
		t.Errorf("CleanupResidue networks=%d err=%v", len(ns), e)
	}
	vs, e = f.direct.VolumeList(ctx, volume.ListOptions{Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil || len(vs.Volumes) != 0 {
		t.Errorf("CleanupResidue volumes=%d err=%v", len(vs.Volumes), e)
	}
	images, e := f.direct.ImageList(ctx, image.ListOptions{All: true, Filters: filters.NewArgs(filters.Arg("label", runLabel+"="+f.run))})
	if e != nil || len(images) != 0 {
		t.Errorf("CleanupResidue images=%d err=%v", len(images), e)
	}
	t.Logf("CLEANUP_COMPLETE run=%s remaining_containers=%d remaining_networks=%d remaining_volumes=%d explicit_images=%d", f.run, len(cs), len(ns), len(vs.Volumes), len(f.imageIDs))
	// Runtime evidence remains in the owned volume until the outer runner copies it.
	_ = f.direct.Close()
}
func (f *fixture) workspace(name string) string {
	f.t.Helper()
	w := filepath.Join(f.root, "workspaces", name)
	for _, r := range []string{"workspaces", "workspace-sockets", "compose-staging"} {
		must(f.t, os.MkdirAll(filepath.Join(f.root, r, name), 0755))
	}
	return w
}
func (f *fixture) policy(entries []map[string]any) {
	if entries == nil {
		entries = []map[string]any{}
	}
	b, e := json.Marshal(map[string]any{"version": 1, "exceptions": entries})
	must(f.t, e)
	path := filepath.Join(f.root, "exceptions", "workspace-exceptions.json")
	write(f.t, path+".new", b)
	must(f.t, os.Rename(path+".new", path))
	f.t.Logf("POLICY sha256=%s entries=%d", digest(b), len(entries))
}
func grant(w string, g map[string]any) map[string]any {
	return map[string]any{"workspace": w, "grants": g, "approval": map[string]any{"by": map[string]string{"issuer": "https://id.example.test", "subject": "operator-1"}, "at": "2026-01-02T03:04:05Z"}}
}

type proxy struct {
	f                   *fixture
	id, socket, variant string
	recorder            *recorder
}

func (f *fixture) startProxy(t *testing.T, variant string) *proxy {
	t.Helper()
	raw, e := os.ReadFile("/src/tests/acceptance/testdata/candidate.yaml")
	must(t, e)
	meta, e := os.ReadFile("/src/tests/acceptance/testdata/profile-input.json")
	must(t, e)
	var input struct {
		CandidateSHA  string            `json:"candidate_sha256"`
		ReadmeSHA     string            `json:"readme_sha256"`
		Substitutions map[string]string `json:"substitutions"`
	}
	must(t, json.Unmarshal(meta, &input))
	if digest(raw) != input.CandidateSHA {
		t.Fatal("raw candidate hash differs from reviewed input")
	}
	readme, e := os.ReadFile("/src/tests/acceptance/testdata/profile.md")
	must(t, e)
	if digest(readme) != input.ReadmeSHA {
		t.Fatal("profile README hash differs")
	}
	// Apply only the declared literal substitutions, in one pass (no cascades).
	var pairs []string
	var keys []string
	for key := range input.Substitutions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, old := range keys {
		replacement := input.Substitutions[old]
		replacement = strings.NewReplacer("${RUN_ROOT}", f.root, "${CLIENT_UID}", "10001", "${SOCKET_GID}", "20001", "${VARIANT}", variant).Replace(replacement)
		pairs = append(pairs, old, replacement)
	}
	rendered := strings.NewReplacer(pairs...).Replace(string(raw))
	var cfg map[string]any
	must(t, yaml.Unmarshal([]byte(rendered), &cfg))
	listener := filepath.Join(f.root, "listener", variant)
	must(t, os.MkdirAll(listener, 0777))
	must(t, os.Chmod(listener, 0777))
	// A per-proxy socket pathname is a test-path substitution, not policy.
	mappedBaseline := rendered
	write(t, filepath.Join(f.root, "mapped-"+variant+".yaml"), []byte(mappedBaseline))
	switch variant {
	case "baseline", "baseline-observe":
	case "restart-route", "restart-route-volume":
		needle := "        - match: { method: POST, path: \"/containers/*/stop\" }"
		if !strings.Contains(rendered, needle) {
			t.Fatal("restart variant insertion anchor missing")
		}
		rendered = strings.Replace(rendered, needle, "        - match: { method: POST, path: \"/containers/*/restart\" }\n          action: allow\n"+needle, 1)
	case "strict-root":
		rendered = strings.Replace(rendered, "allow_root_user: true", "allow_root_user: false", 1)
	case "llb-off":
		rendered = strings.Replace(rendered, "allow_uninspected_passthrough: true", "allow_uninspected_passthrough: false", 1)
	default:
		t.Fatalf("undeclared profile variant %s", variant)
	}
	configPath := filepath.Join(f.root, "config-"+variant+".yaml")
	write(t, configPath, []byte(rendered))
	t.Logf("PROFILE variant=%s raw=%s mapping=%s mapped_baseline=%s rendered=%s substitutions=%v", variant, digest(raw), digest(meta), digest([]byte(mappedBaseline)), digest([]byte(rendered)), pairs)
	binds := []mount.Mount{{Type: mount.TypeBind, Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}, {Type: mount.TypeBind, Source: configPath, Target: "/etc/sockguard/acceptance.yaml", ReadOnly: true}}
	for _, r := range []string{"workspaces", "workspace-sockets", "compose-staging", "exceptions"} {
		p := filepath.Join(f.root, r)
		binds = append(binds, mount.Mount{Type: mount.TypeBind, Source: p, Target: p, ReadOnly: true})
	}
	binds = append(binds, mount.Mount{Type: mount.TypeBind, Source: filepath.Join(f.root, "listener"), Target: filepath.Join(f.root, "listener")})
	proxyCmd := []string{"serve", "--config", "/etc/sockguard/acceptance.yaml"}
	if variant == "baseline-observe" {
		proxyCmd = append(proxyCmd, "--log-level", "debug")
		t.Log("OBSERVABILITY_OVERRIDE log-level=debug only; policy unchanged")
	}
	c, e := f.direct.ContainerCreate(f.ctx, &container.Config{Image: f.forkImage, User: "0:0", Cmd: proxyCmd, Labels: map[string]string{runLabel: f.run}}, &container.HostConfig{Mounts: binds, ReadonlyRootfs: true, NetworkMode: "none", CapDrop: []string{"ALL"}, CapAdd: []string{"DAC_READ_SEARCH"}, GroupAdd: []string{"20001"}, SecurityOpt: []string{"no-new-privileges:true"}, Tmpfs: map[string]string{"/tmp": "rw,noexec,nosuid,size=64m"}}, nil, nil, "")
	must(t, e)
	must(t, f.direct.ContainerStart(f.ctx, c.ID, container.StartOptions{}))
	p := &proxy{f: f, id: c.ID, socket: filepath.Join(listener, "menagerie.sock"), variant: variant}
	deadline := time.Now().Add(30 * time.Second)
	for {
		_, err := os.Stat(p.socket)
		if err == nil {
			break
		}
		state, e := f.direct.ContainerInspect(f.ctx, c.ID)
		must(t, e)
		if state.State != nil && !state.State.Running {
			logs, _ := f.direct.ContainerLogs(f.ctx, c.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
			if logs != nil {
				b, _ := io.ReadAll(logs)
				_ = logs.Close()
				t.Log(string(b))
			}
			t.Fatalf("proxy startup failed, exit=%d; exact DAC_READ_SEARCH-only capability set retained", state.State.ExitCode)
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not create socket")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("PROXY id=%s pid=%d variant=%s", c.ID, p.inspect(t).State.Pid, variant)
	t.Cleanup(func() {
		logs, e := f.direct.ContainerLogs(context.Background(), c.ID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
		if e == nil {
			b, _ := io.ReadAll(logs)
			_ = logs.Close()
			write(t, filepath.Join(f.root, "proxy-"+variant+".log"), b)
		}
	})
	return p
}
func (p *proxy) inspect(t *testing.T) container.InspectResponse {
	c, e := p.f.direct.ContainerInspect(p.f.ctx, p.id)
	must(t, e)
	return c
}
func (p *proxy) client(t *testing.T, w, header string) (*dockerclient.Client, *recorder) {
	t.Helper()
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
	}}
	r := &recorder{base: tr, label: p.f.run}
	// Observe hijacked /grpc, /session and exec as well as ordinary requests.
	// This relay changes only the non-security provenance label. HTTP headers
	// come from the actual caller-built SDK client, including headerless builds.
	sock := filepath.Join(p.f.root, "listener", fmt.Sprintf("client-%d.sock", time.Now().UnixNano()))
	ln, e := net.Listen("unix", sock)
	must(t, e)
	rp := &httputil.ReverseProxy{Director: func(req *http.Request) { req.URL.Scheme = "http"; req.URL.Host = "docker" }, Transport: r}
	srv := &http.Server{Handler: rp, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if e := srv.Serve(ln); e != nil && e != http.ErrServerClosed {
			t.Logf("owned relay: %v", e)
		}
	}()
	headers := map[string]string{}
	if header != "" {
		headers[header] = w
	}
	c, e := dockerclient.NewClientWithOpts(dockerclient.WithHost("unix://"+sock), dockerclient.WithAPIVersionNegotiation(), dockerclient.WithHTTPHeaders(headers))
	must(t, e)
	t.Cleanup(func() { _ = c.Close(); _ = srv.Close(); tr.CloseIdleConnections(); _ = os.Remove(sock) })
	return c, r
}
func (p *proxy) request(t *testing.T, method, path, w, header string, body any) (int, []byte) {
	t.Helper()
	var b []byte
	var e error
	switch v := body.(type) {
	case []byte:
		b = v
	case nil:
	default:
		b, e = json.Marshal(v)
		must(t, e)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", p.socket)
	}}
	defer tr.CloseIdleConnections()
	req, e := http.NewRequestWithContext(p.f.ctx, method, "http://docker/v1.47"+path, bytes.NewReader(b))
	must(t, e)
	if header != "" {
		req.Header.Set(header, w)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := tr.RoundTrip(req)
	must(t, e)
	defer resp.Body.Close()
	b, e = io.ReadAll(resp.Body)
	must(t, e)
	t.Logf("HTTP variant=%s method=%s path=%s status=%d reason=%s", p.variant, method, path, resp.StatusCode, b)
	return resp.StatusCode, b
}
func expect(t *testing.T, got, want int, b []byte) {
	t.Helper()
	if got != want {
		t.Fatalf("status=%d want=%d body=%s", got, want, b)
	}
}
func denied(t *testing.T, status int, b []byte, reason string) {
	t.Helper()
	expect(t, status, 403, b)
	if !strings.Contains(strings.ToLower(string(b)), strings.ToLower(reason)) {
		t.Fatalf("denial missing intended reason %q: %s", reason, b)
	}
}
func (f *fixture) create(t *testing.T, p *proxy, w, header string, labels map[string]string, host map[string]any, argv ...[]string) (string, int, []byte) {
	t.Helper()
	if labels == nil {
		labels = map[string]string{}
	}
	labels[runLabel] = f.run
	cmd := []string{"sleep", "3600"}
	if len(argv) > 0 {
		cmd = argv[0]
	}
	s, b := p.request(t, "POST", "/containers/create", w, header, map[string]any{"Image": f.baseImage, "Cmd": cmd, "Labels": labels, "HostConfig": host})
	var out struct{ ID string }
	if s == 201 {
		must(t, json.Unmarshal(b, &out))
		if out.ID == "" {
			t.Fatal("admitted create has no ID")
		}
	}
	return out.ID, s, b
}
func (f *fixture) exec(t *testing.T, c *dockerclient.Client, id string, argv []string) string {
	t.Helper()
	e, e1 := c.ContainerExecCreate(f.ctx, id, container.ExecOptions{Cmd: argv, AttachStdout: true, AttachStderr: true})
	must(t, e1)
	a, e1 := c.ContainerExecAttach(f.ctx, e.ID, container.ExecAttachOptions{})
	must(t, e1)
	defer a.Close()
	var out, errOut bytes.Buffer
	_, e1 = stdcopy.StdCopy(&out, &errOut, a.Reader)
	must(t, e1)
	status, e1 := c.ContainerExecInspect(f.ctx, e.ID)
	must(t, e1)
	if status.ExitCode != 0 {
		t.Fatalf("exec exit=%d out=%s err=%s", status.ExitCode, &out, &errOut)
	}
	return out.String()
}

func TestAcceptance(t *testing.T) {
	f := newFixture(t)
	p := f.startProxy(t, "baseline")
	t.Run("DeploymentMountsAndCapabilities", func(t *testing.T) {
		c := p.inspect(t)
		if c.Config.User != "0:0" || !c.HostConfig.ReadonlyRootfs || c.HostConfig.NetworkMode != "none" {
			t.Fatalf("deployment flags drift: %+v", c.HostConfig)
		}
		if len(c.HostConfig.CapAdd) != 1 || strings.TrimPrefix(c.HostConfig.CapAdd[0], "CAP_") != "DAC_READ_SEARCH" {
			t.Fatalf("capability drift: %v", c.HostConfig.CapAdd)
		}
		if len(c.HostConfig.CapDrop) != 1 || strings.TrimPrefix(c.HostConfig.CapDrop[0], "CAP_") != "ALL" {
			t.Fatalf("capability drop drift: %v", c.HostConfig.CapDrop)
		}
		noNewPrivileges := false
		for _, option := range c.HostConfig.SecurityOpt {
			if strings.TrimSuffix(option, ":true") == "no-new-privileges" {
				noNewPrivileges = true
			}
		}
		if !noNewPrivileges {
			t.Fatal("no-new-privileges missing")
		}
		if len(c.HostConfig.GroupAdd) != 1 || c.HostConfig.GroupAdd[0] != "20001" {
			t.Fatal("socket supplementary group missing")
		}
		if _, ok := c.HostConfig.Tmpfs["/tmp"]; !ok {
			t.Fatal("archive tmpfs absent")
		}
		for _, root := range []string{"workspaces", "workspace-sockets", "compose-staging", "exceptions"} {
			path := filepath.Join(f.root, root)
			found := false
			for _, m := range c.Mounts {
				if m.Source == path && m.Destination == path && !m.RW {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing real read-only same-path mount %s", path)
			}
		}
		st, e := os.Stat(p.socket)
		must(t, e)
		if st.Mode().Perm() != 0660 {
			t.Fatalf("socket mode=%o", st.Mode().Perm())
		}
		// Runner uid10001 primary gid10002 connects using supplementary gid20001.
		s, b := p.request(t, "GET", "/_ping", "", "", nil)
		expect(t, s, 200, b)
	})
	t.Run("WorkspaceGrantReloadAndIdentity", func(t *testing.T) { testGrants(t, f, p) })
	t.Run("BindSwapAtStartAndRestart", func(t *testing.T) { testBindSwap(t, f, p) })
	t.Run("LocalVolumeDeviceReresolution", func(t *testing.T) { testVolumeSwap(t, f, p) })
	t.Run("ArchiveAttachWait", func(t *testing.T) { testArchive(t, f, p) })
	t.Run("ExecSettingsAndTarget", func(t *testing.T) { testExec(t, f, p) })
	t.Run("ConsumerDockerLifecycle", func(t *testing.T) { testDockerConsumer(t, f, p) })
	t.Run("ConsumerIdentityControls", func(t *testing.T) { testDockerIdentityConsumer(t, f, p) })
	t.Run("ConsumerComposeLifecycle", func(t *testing.T) { testComposeConsumer(t, f, p) })
	t.Run("StartupChownFailure", func(t *testing.T) { testStartupChownFailure(t, f, p) })
	t.Run("SocketPeerFilesystemAccess", func(t *testing.T) { testSocketPeers(t, f, p) })
}

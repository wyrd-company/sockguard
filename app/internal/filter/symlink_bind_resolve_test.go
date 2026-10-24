package filter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// symlinkBindFixture is a temp tree:
//
//	<root>/ws/                     the allowlisted workspace root
//	<root>/ws/real/file            ordinary file
//	<root>/ws/out -> <root>/outside           absolute link out
//	<root>/ws/mid -> <root>/outside           used as an intermediate component
//	<root>/ws/rel -> ../outside               relative link out with ".."
//	<root>/ws/relreal -> real/../../outside   ".." after a real component
//	<root>/ws/in -> real                      relative link that stays inside
//	<root>/ws/inabs -> <root>/ws/real         absolute link that stays inside
//	<root>/ws/dangling -> <root>/ws/nope      target does not exist
//	<root>/ws/danglingout -> <root>/nope      target does not exist, outside
//	<root>/ws/loopa -> loopb, loopb -> loopa  loop
//	<root>/outside/secret
//	<root>/wslink -> ws                       an allowlist entry that is a link
type symlinkBindFixture struct {
	root    string
	ws      string
	outside string
}

func newSymlinkBindFixture(t *testing.T) symlinkBindFixture {
	t.Helper()
	// The temp dir may itself sit under a symlink; resolve it so expected
	// values are in resolved form.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := symlinkBindFixture{root: root, ws: filepath.Join(root, "ws"), outside: filepath.Join(root, "outside")}
	for _, dir := range []string{filepath.Join(f.ws, "real"), f.outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(f.ws, "real", "file"), filepath.Join(f.outside, "secret")} {
		if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	links := map[string]string{
		"ws/out":         f.outside,
		"ws/mid":         f.outside,
		"ws/rel":         "../outside",
		"ws/relreal":     "real/../../outside",
		"ws/in":          "real",
		"ws/inabs":       filepath.Join(f.ws, "real"),
		"ws/dangling":    filepath.Join(f.ws, "nope"),
		"ws/danglingout": filepath.Join(root, "nope"),
		"ws/loopa":       "loopb",
		"ws/loopb":       "loopa",
		"wslink":         "ws",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func TestResolveBindSource(t *testing.T) {
	f := newSymlinkBindFixture(t)
	tests := []struct {
		name    string
		source  string
		want    string
		wantErr error
	}{
		{name: "ordinary directory is unchanged", source: f.ws + "/real", want: f.ws + "/real"},
		{name: "ordinary file is unchanged", source: f.ws + "/real/file", want: f.ws + "/real/file"},
		{name: "absolute link out", source: f.ws + "/out", want: f.outside},
		{name: "intermediate link out", source: f.ws + "/mid/secret", want: f.outside + "/secret"},
		{name: "relative link out with dot-dot", source: f.ws + "/rel", want: f.outside},
		{name: "dot-dot after a real component in a link", source: f.ws + "/relreal/secret", want: f.outside + "/secret"},
		{name: "relative link inside", source: f.ws + "/in/file", want: f.ws + "/real/file"},
		{name: "absolute link inside", source: f.ws + "/inabs", want: f.ws + "/real"},
		{name: "missing tail is appended", source: f.ws + "/real/new/deeper", want: f.ws + "/real/new/deeper"},
		{name: "missing tail after a link", source: f.ws + "/in/new", want: f.ws + "/real/new"},
		{name: "missing tail after a link out", source: f.ws + "/out/new", want: f.outside + "/new"},
		{name: "missing at the root", source: f.root + "/absent/x", want: f.root + "/absent/x"},
		{name: "dangling link", source: f.ws + "/dangling", wantErr: errBindSourceDangling},
		{name: "dangling link with a tail", source: f.ws + "/dangling/x", wantErr: errBindSourceDangling},
		{name: "dangling link out", source: f.ws + "/danglingout", wantErr: errBindSourceDangling},
		{name: "loop", source: f.ws + "/loopa", wantErr: errBindSourceLoop},
		{name: "non-directory in the middle", source: f.ws + "/real/file/x", wantErr: errBindSourceUnresolvable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveBindSource(tt.source)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("resolveBindSource(%q) = %q, %v; want error %v", tt.source, got, err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("resolveBindSource(%q) = %q, %v; want %q", tt.source, got, err, tt.want)
			}
		})
	}
}

func TestResolveBindSourcePermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	f := newSymlinkBindFixture(t)
	locked := filepath.Join(f.ws, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	if _, err := resolveBindSource(locked + "/x"); !errors.Is(err, errBindSourcePermission) {
		t.Fatalf("resolveBindSource() error = %v, want %v", err, errBindSourcePermission)
	}
}

// TestResolveBindSourceHopLimit pins the kernel's 40-symlink limit: a chain of
// 40 links resolves and a chain of 41 is a loop.
func TestResolveBindSourceHopLimit(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "end"), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := "end"
	for i := 1; i <= maxBindSymlinkHops+1; i++ {
		name := "hop" + strconv.Itoa(i)
		if err := os.Symlink(prev, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		prev = name
	}
	if got, err := resolveBindSource(filepath.Join(dir, "hop40")); err != nil || got != filepath.Join(dir, "end") {
		t.Fatalf("40 hops: resolveBindSource() = %q, %v; want %q", got, err, filepath.Join(dir, "end"))
	}
	if _, err := resolveBindSource(filepath.Join(dir, "hop41")); !errors.Is(err, errBindSourceLoop) {
		t.Fatalf("41 hops: resolveBindSource() error = %v, want %v", err, errBindSourceLoop)
	}
}

// TestResolveBindSourceMatchesEvalSymlinks compares the walk with
// filepath.EvalSymlinks on every fixture path that exists. The walk differs
// from it only for a missing path, which EvalSymlinks refuses.
func TestResolveBindSourceMatchesEvalSymlinks(t *testing.T) {
	f := newSymlinkBindFixture(t)
	var corpus []string
	err := filepath.WalkDir(f.root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		corpus = append(corpus, p)
		for _, tail := range []string{"/secret", "/file", "/.", "/../ws/real"} {
			corpus = append(corpus, p+tail)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	compared := 0
	for _, p := range corpus {
		clean := filepath.Clean(p)
		want, wantErr := filepath.EvalSymlinks(clean)
		if wantErr != nil {
			continue
		}
		compared++
		got, err := resolveBindSource(clean)
		if err != nil || got != want {
			t.Errorf("resolveBindSource(%q) = %q, %v; EvalSymlinks = %q", clean, got, err, want)
		}
	}
	if compared < 20 {
		t.Fatalf("compared only %d paths; the fixture did not build", compared)
	}
}

func TestDenySymlinkedBindSourceReason(t *testing.T) {
	f := newSymlinkBindFixture(t)
	tests := []struct {
		name    string
		source  string
		allowed []string
		want    string
	}{
		{name: "ordinary path", source: f.ws + "/real", allowed: []string{f.ws}},
		{name: "missing path", source: f.ws + "/new", allowed: []string{f.ws}},
		{name: "link inside", source: f.ws + "/in", allowed: []string{f.ws}},
		{name: "link out", source: f.ws + "/out", allowed: []string{f.ws},
			want: `t denied: bind mount source "` + f.ws + `/out" resolves to "` + f.outside + `", which is not allowlisted`},
		{name: "link out into another allowlist entry", source: f.ws + "/out", allowed: []string{f.ws, f.outside}},
		{name: "allowlist entry that is a link", source: f.root + "/wslink/real", allowed: []string{f.root + "/wslink"}},
		{name: "link out under an allowlist entry that is a link", source: f.root + "/wslink/out", allowed: []string{f.root + "/wslink"},
			want: `t denied: bind mount source "` + f.root + `/wslink/out" resolves to "` + f.outside + `", which is not allowlisted`},
		{name: "dangling link", source: f.ws + "/dangling", allowed: []string{f.ws},
			want: `t denied: bind mount source "` + f.ws + `/dangling" cannot be resolved: dangling symlink at "` + f.ws + `/nope"`},
		{name: "loop", source: f.ws + "/loopa", allowed: []string{f.ws},
			want: `t denied: bind mount source "` + f.ws + `/loopa" cannot be resolved: symlink loop at "` + f.ws + `/loopa"`},
		{name: "allowlist holding the root skips resolution", source: f.ws + "/dangling", allowed: []string{"/"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := denySymlinkedBindSourceReason("t", "bind mount source", tt.source, tt.allowed); got != tt.want {
				t.Fatalf("denySymlinkedBindSourceReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

// symlinkBindInspect runs one inspector over a POST body and returns the deny
// reason the middleware would see.
func symlinkBindInspect(t *testing.T, inspect func(*http.Request, string) (string, error), urlPath, body string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, urlPath, strings.NewReader(body))
	reason, err := inspect(req, NormalizePath(req.URL.Path))
	return inspectorDenyReason(t, reason, err)
}

// TestSymlinkBindSourcesPerSurface drives every create surface the resolver is
// wired into with a source that links out of the allowlist, and the same
// surface with a source that stays inside. The inside case keeps each wiring
// honest: it fails if the check denies everything.
func TestSymlinkBindSourcesPerSurface(t *testing.T) {
	f := newSymlinkBindFixture(t)
	allowed := []string{f.ws}
	out, in := f.ws+"/out", f.ws+"/in"

	docker := newContainerCreatePolicy(ContainerCreateOptions{AllowedBindMounts: allowed})
	libpod := newLibpodContainerCreatePolicy(LibpodContainerCreateOptions{AllowedBindMounts: allowed})
	volume := newVolumePolicy(VolumeOptions{AllowDriverOpts: true, AllowedBindMounts: allowed})
	dockerInspect := func(r *http.Request, p string) (string, error) { return docker.inspect(nil, r, p) }
	libpodInspect := func(r *http.Request, p string) (string, error) { return libpod.inspect(nil, r, p) }
	volumeInspect := func(r *http.Request, p string) (string, error) { return volume.inspect(nil, r, p) }
	libpodVolumeInspect := func(r *http.Request, p string) (string, error) { return volume.inspectLibpod(nil, r, p) }

	surfaces := []struct {
		name    string
		inspect func(*http.Request, string) (string, error)
		urlPath string
		body    func(source string) string
		want    string // deny reason for the link out; "%s" is the source
	}{
		{
			name: "container create Binds", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string { return `{"Image":"a","HostConfig":{"Binds":["` + s + `:/x"]}}` },
			want: `container create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "container create Mounts bind", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string {
				return `{"Image":"a","HostConfig":{"Mounts":[{"Type":"bind","Source":"` + s + `","Target":"/x"}]}}`
			},
			want: `container create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "container create Volumes key", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string { return `{"Image":"a","Volumes":{"` + s + `:/x":{}}}` },
			want: `container create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "container create Binds overlay upperdir", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string {
				return `{"Image":"a","HostConfig":{"Binds":["vol:/x:O,upperdir=` + s + `,workdir=` + f.ws + `/real"]}}`
			},
			want: `container create denied: overlay directory "%s" resolves to`,
		},
		{
			name: "container create Mounts local volume bind device", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string {
				return `{"Image":"a","HostConfig":{"Mounts":[{"Type":"volume","Source":"v","Target":"/x","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"` + s + `"}}}}]}}`
			},
			want: `container create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "container create Mounts local volume overlay lowerdir", inspect: dockerInspect, urlPath: "/containers/create",
			body: func(s string) string {
				return `{"Image":"a","HostConfig":{"Mounts":[{"Type":"volume","Source":"v","Target":"/x","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"overlay","device":"` + f.ws + `/real","o":"lowerdir=` + s + `"}}}}]}}`
			},
			want: `container create denied: local volume lowerdir path "%s" resolves to`,
		},
		{
			name: "volume create bind device", inspect: volumeInspect, urlPath: "/volumes/create",
			body: func(s string) string {
				return `{"Name":"v","Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"` + s + `"}}`
			},
			want: `volume create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "volume create overlay lowerdir", inspect: volumeInspect, urlPath: "/volumes/create",
			body: func(s string) string {
				return `{"Name":"v","Driver":"local","DriverOpts":{"type":"overlay","device":"` + f.ws + `/real","o":"lowerdir=` + s + `"}}`
			},
			want: `volume create denied: local volume lowerdir path "%s" resolves to`,
		},
		{
			name: "libpod volume create bind device", inspect: libpodVolumeInspect, urlPath: "/libpod/volumes/create",
			body: func(s string) string {
				return `{"Name":"v","Driver":"local","Options":{"type":"none","o":"bind","device":"` + s + `"}}`
			},
			want: `libpod volume create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "libpod create mounts bind", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string {
				return `{"systemd":"false","image":"a","mounts":[{"type":"bind","source":"` + s + `","destination":"/x"}]}`
			},
			want: `libpod container create denied: bind mount source "%s" resolves to`,
		},
		{
			name: "libpod create rootfs", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string { return `{"systemd":"false","rootfs":"` + s + `"}` },
			want: `libpod container create denied: rootfs path "%s" resolves to`,
		},
		{
			name: "libpod create overlay volume source", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string {
				return `{"systemd":"false","image":"a","overlay_volumes":[{"source":"` + s + `","destination":"/x"}]}`
			},
			want: `libpod container create denied: overlay volume source "%s" resolves to`,
		},
		{
			name: "libpod create overlay volume upperdir", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string {
				return `{"systemd":"false","image":"a","overlay_volumes":[{"source":"` + f.ws + `/real","destination":"/x","options":["O","upperdir=` + s + `","workdir=` + f.ws + `/real"]}]}`
			},
			want: `libpod container create denied: overlay directory "%s" resolves to`,
		},
		{
			name: "libpod create named volume upperdir", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string {
				return `{"systemd":"false","image":"a","volumes":[{"Name":"v","Dest":"/x","Options":["O","upperdir=` + s + `","workdir=` + f.ws + `/real"]}]}`
			},
			want: `libpod container create denied: overlay directory "%s" resolves to`,
		},
		{
			name: "libpod create init_path", inspect: libpodInspect, urlPath: "/libpod/containers/create",
			body: func(s string) string { return `{"systemd":"false","image":"a","init":true,"init_path":"` + s + `"}` },
			want: `libpod container create denied: init_path "%s" resolves to`,
		},
	}
	for _, s := range surfaces {
		t.Run(s.name+"/link out", func(t *testing.T) {
			want := strings.Replace(s.want, "%s", out, 1)
			if got := symlinkBindInspect(t, s.inspect, s.urlPath, s.body(out)); !strings.HasPrefix(got, want) {
				t.Fatalf("deny reason = %q, want prefix %q", got, want)
			}
		})
		t.Run(s.name+"/link inside", func(t *testing.T) {
			if got := symlinkBindInspect(t, s.inspect, s.urlPath, s.body(in)); got != "" {
				t.Fatalf("deny reason = %q, want allowed", got)
			}
		})
	}
}

// TestSymlinkBindSourcesServiceStaysLexical pins the ruling that service create
// keeps its lexical check: a swarm task's source resolves on its node.
func TestSymlinkBindSourcesServiceStaysLexical(t *testing.T) {
	f := newSymlinkBindFixture(t)
	policy := newServicePolicy(ServiceOptions{AllowOfficial: true, AllowedBindMounts: []string{f.ws}})
	inspect := func(r *http.Request, p string) (string, error) { return policy.inspect(nil, r, p) }
	bodies := map[string]string{
		"bind mount": `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"bind","Source":"` + f.ws + `/out","Target":"/x"}]}}}`,
		"local volume bind device": `{"TaskTemplate":{"ContainerSpec":{"Image":"nginx:latest","Mounts":[{"Type":"volume","Source":"v","Target":"/x",` +
			`"VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"` + f.ws + `/out"}}}}]}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			if got := symlinkBindInspect(t, inspect, "/services/create", body); got != "" {
				t.Fatalf("deny reason = %q, want allowed (lexical check only)", got)
			}
		})
	}
}

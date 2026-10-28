// relationships:
//
// references: [../../../docs/content/docs/symlink-bind-sources]
package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func setStartVolume(t *testing.T, f *forkStartRecheckFixture, driver string, options map[string]string) {
	t.Helper()
	body, err := json.Marshal(ForkStartRecheckVolume{Driver: driver, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	f.daemon.setVolumes(map[string]string{"/volumes/data": string(body)})
	f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{{Type: "volume", Name: "data", Source: filepath.Join(f.outside, "mountpoint")}}, nil, nil))
}

func TestForkStartRecheckLocalVolumeDevice(t *testing.T) {
	for _, route := range forkStartRecheckRoutes {
		t.Run(route.path, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			device := filepath.Join(f.ws, "proj")
			setStartVolume(t, f, "local", map[string]string{"type": "none", "o": "bind", "device": device, "private": "must-not-appear"})
			p := f.policy([]string{f.ws}, nil)
			assertForwarded(t, send(t, p, http.MethodPost, route.path, ""))
			if got := f.daemon.inspects(); len(got) != 2 || got[1] != "GET /volumes/data" {
				t.Fatalf("volume lookup missing: %q", got)
			}
			f.swap("proj", f.outside)
			got := send(t, p, http.MethodPost, route.path, "")
			assertDenied(t, got, "container_start_bind_source_denied", route.subject+` denied: bind mount source "`+device+`" resolves to "`+f.outside+`", which is not allowlisted`)
			if strings.Contains(got.reason, "must-not-appear") {
				t.Fatal("driver option leaked")
			}
		})
	}
}

func TestForkStartRecheckVolumeClassifierAndNoNarrowing(t *testing.T) {
	for _, tc := range []struct {
		name, driver string
		opts         map[string]string
		deny         bool
	}{
		{"plugin", "example-driver", map[string]string{"o": "bind", "device": "DEVICE"}, false},
		{"local-no-bind", "local", map[string]string{"type": "nfs", "device": "DEVICE", "o": "addr=bind.example.org"}, false},
		{"local-default", "local", nil, false},
		{"type-none", "local", map[string]string{"type": "none", "device": "DEVICE"}, true},
		{"type-bind", "local", map[string]string{"type": "bind", "device": "DEVICE"}, true},
		{"rbind", "LOCAL", map[string]string{"TYPE": "nfs", "O": "ro,RBIND", "Device": "DEVICE"}, true},
		{"device-in-o", "local", map[string]string{"o": "bind,device=DEVICE"}, true},
		{"outside-as-written", "local", map[string]string{"type": "none", "device": "OUTSIDE"}, false},
		{"relative-as-written", "local", map[string]string{"o": "bind", "device": "relative/path"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			outside := f.outside
			if tc.name == "outside-as-written" {
				outside = filepath.Join(f.outside, "device")
				if err := os.Symlink(filepath.Join(f.outside, "sub"), outside); err != nil {
					t.Fatal(err)
				}
			}
			for k, v := range tc.opts {
				tc.opts[k] = strings.ReplaceAll(strings.ReplaceAll(v, "DEVICE", filepath.Join(f.ws, "proj")), "OUTSIDE", outside)
			}
			setStartVolume(t, f, tc.driver, tc.opts)
			f.swap("proj", f.outside)
			got := send(t, f.policy([]string{f.ws}, nil), http.MethodPost, "/containers/c1/start", "")
			if tc.deny {
				if got.status != 403 || got.reasonCode != "container_start_bind_source_denied" {
					t.Fatalf("bind classifier not enforced: %+v", got)
				}
			} else {
				assertForwarded(t, got)
			}
		})
	}
}

func TestForkStartRecheckVolumeNoLookupsWithoutConstraint(t *testing.T) {
	for _, pair := range []struct{ compat, libpod []string }{{nil, nil}, {[]string{"/"}, nil}, {[]string{"/"}, []string{"/restricted"}}, {[]string{"/restricted"}, []string{"/"}}} {
		f := newForkStartRecheckFixture(t)
		setStartVolume(t, f, "local", map[string]string{"o": "bind", "device": f.outside})
		assertForwarded(t, send(t, f.policy(pair.compat, pair.libpod), http.MethodPost, "/containers/c1/start", ""))
		if len(f.daemon.inspects()) != 0 {
			t.Fatalf("unconstrained request made lookups: %q", f.daemon.inspects())
		}
	}
}

func TestForkStartRecheckVolumeFailureIsSafe(t *testing.T) {
	for _, name := range []string{"transport", "404", "201", "500", "decode", "decode-options", "redirect", "null", "missing-driver", "size", "read", "nil-inspector", "missing-name"} {
		t.Run(name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			p := f.policy([]string{f.ws}, nil)
			container := ForkStartRecheckContainer{Mounts: []ForkStartRecheckMount{{Type: "volume", Name: "data"}}}
			p.ForkStartRecheck.InspectContainer = func(context.Context, string) (ForkStartRecheckContainer, error) { return container, nil }
			p.ForkStartRecheck.InspectVolume = NewForkStartRecheckVolumeInspectorWithRoundTripper(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				if name == "redirect" && r.URL.Path == "/volumes/other" {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"Driver":"local"}`)), Header: make(http.Header)}, nil
				}
				if r.Method != "GET" || r.URL.Path != "/volumes/data" {
					t.Fatalf("lookup target %s %s", r.Method, r.URL.Path)
				}
				if name == "transport" {
					return nil, errors.New("must-not-appear")
				}
				status, body := 200, `{"Driver":"local","Options":{"private":"must-not-appear"}}`
				switch name {
				case "404":
					status = 404
				case "201":
					status = 201
				case "500":
					status = 500
				case "decode":
					body = `{"Options":{"private":"must-not-appear"},"Driver":`
				case "decode-options":
					body = `{"Driver":"local","Options":{"private":42}}`
				case "redirect":
					status = 303
				case "null":
					body = "null"
				case "missing-driver":
					body = `{"Options":{"private":"must-not-appear"}}`
				case "size":
					body += strings.Repeat(" ", 8<<20)
				}
				reader := io.NopCloser(strings.NewReader(body))
				if name == "read" {
					reader = io.NopCloser(io.MultiReader(strings.NewReader(body), failedVolumeReader{}))
				}
				headers := make(http.Header)
				if name == "redirect" {
					headers.Set("Location", "/volumes/other")
				}
				return &http.Response{StatusCode: status, Body: reader, Header: headers}, nil
			}))
			if name == "nil-inspector" {
				p.ForkStartRecheck.InspectVolume = nil
			}
			if name == "missing-name" {
				container.Mounts[0].Name = ""
			}
			var logs bytes.Buffer
			got := sendLogged(t, slog.New(slog.NewTextHandler(&logs, nil)), p, http.MethodPost, "/containers/c1/start", "")
			wantName := container.Mounts[0].Name
			assertDenied(t, got, "container_start_volume_inspect_failed", `container start denied: volume "`+wantName+`" could not be inspected to re-check its bind devices`)
			if strings.Contains(got.reason+logs.String(), "must-not-appear") {
				t.Fatal("driver option leaked in denial or logs")
			}
		})
	}
}

type failedVolumeReader struct{}

func (failedVolumeReader) Read([]byte) (int, error) { return 0, errors.New("must-not-appear") }

func TestForkStartRecheckVolumeDeviceSpellings(t *testing.T) {
	for _, tc := range []string{"as-written", "cleaned", "created", "dangling", "missing-inside"} {
		t.Run(tc, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			raw := filepath.Join(f.ws, "proj")
			switch tc {
			case "as-written":
				f.swap("up", filepath.Join(f.outside, "sub"))
				raw = f.ws + "/up/../proj"
			case "cleaned":
				for _, dir := range []string{filepath.Join(f.ws, "parent", "inner"), filepath.Join(f.ws, "parent", "proj")} {
					if err := os.MkdirAll(dir, 0o755); err != nil {
						t.Fatal(err)
					}
				}
				f.swap("up", filepath.Join(f.ws, "parent", "inner"))
				f.swap("proj", f.outside)
				raw = f.ws + "/up/../proj"
			case "created":
				raw = f.ws + "/new/../proj"
			case "dangling":
				if err := os.Symlink(filepath.Join(f.outside, "missing"), raw+"/link"); err != nil {
					t.Fatal(err)
				}
				raw += "/link"
			case "missing-inside":
				raw += "/new/child"
			}
			setStartVolume(t, f, "local", map[string]string{"o": "bind", "device": raw})
			allowed := []string{f.ws}
			if tc == "created" {
				allowed = []string{filepath.Join(f.ws, "proj")}
			}
			got := send(t, f.policy(allowed, nil), http.MethodPost, "/containers/c1/start", "")
			if tc == "missing-inside" {
				assertForwarded(t, got)
			} else if got.status != 403 || got.reasonCode != "container_start_bind_source_denied" {
				t.Fatalf("device %s not checked: %+v", tc, got)
			}
		})
	}
}

func TestForkStartRecheckVolumeInspectContextAndEscaping(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(t.Context(), contextKey{}, "context-marker")
	calls := 0
	inspect := NewForkStartRecheckVolumeInspectorWithRoundTripper(roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Context().Value(contextKey{}) != "context-marker" || r.URL.EscapedPath() != "/volumes/data%2Fchild%3Fquery" {
			t.Fatalf("inspect context or escaped target lost: %v %s", r.Context(), r.URL.EscapedPath())
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"Driver":"local","Options":null}`)), Header: make(http.Header)}, nil
	}))
	if _, err := inspect(ctx, "data/child?query"); err != nil || calls != 1 {
		t.Fatalf("inspect failed: calls=%d err=%v", calls, err)
	}
	if _, err := inspect(nil, "data"); err == nil || calls != 1 { //nolint:staticcheck // nil context intentionally exercises request construction failure.
		t.Fatalf("nil context reached transport: calls=%d err=%v", calls, err)
	}
}

func TestForkStartRecheckVolumeChecksEveryMountAndDevice(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(200, inspectBody(t, []ForkStartRecheckMount{{Type: "volume", Name: "first"}, {Type: "volume", Name: "second"}}, nil, nil))
	f.daemon.setVolumes(map[string]string{
		"/volumes/first":  `{"Driver":"local","Options":null}`,
		"/volumes/second": string(mustJSON(t, ForkStartRecheckVolume{Driver: "local", Options: map[string]string{"o": "bind", "device": filepath.Join(f.ws, "up", "inner"), "Device": filepath.Join(f.ws, "proj")}})),
	})
	assertForwarded(t, send(t, f.policy([]string{f.ws}, nil), http.MethodPost, "/containers/c1/start", ""))
	f.daemon.clearRequests()
	f.swap("up/inner", f.outside)
	got := send(t, f.policy([]string{f.ws}, nil), http.MethodPost, "/containers/c1/start", "")
	if got.status != 403 || got.reasonCode != "container_start_bind_source_denied" {
		t.Fatalf("second volume/device was skipped: %+v", got)
	}
	if want := []string{"GET /containers/c1/json", "GET /volumes/first", "GET /volumes/second"}; !slices.Equal(f.daemon.inspects(), want) {
		t.Fatalf("volume lookups %q want %q", f.daemon.inspects(), want)
	}
}

func TestForkStartRecheckVolumeParticipatesInExceptionMatch(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	p := f.policy()
	p.ContainerCreate.AllowedBindMounts = []string{f.ws, f.outside}
	set := func(sources []string, device string) {
		setStartVolume(t, f.forkStartRecheckFixture, "local", map[string]string{"o": "bind", "device": device})
		body := ForkStartRecheckContainer{Config: ForkStartRecheckConfig{Labels: map[string]string{WorkspaceLocalFolderLabel: f.alpha}}, Mounts: []ForkStartRecheckMount{{Type: "volume", Name: "data"}}}
		for _, source := range sources {
			body.Mounts = append(body.Mounts, bindMount(source))
		}
		f.daemon.set(200, inspectBodyOf(t, body))
	}
	extra := filepath.Join(f.extra, "data")
	set([]string{f.alpha, extra}, f.alpha)
	assertForwarded(t, sendWorkspace(t, p, "/containers/c1/start", devcontainerHeader(f.alpha)))
	// The device itself passes the base scope, but fails bind agreement.
	// It must revoke the extras that the other inspected sources need.
	set([]string{f.alpha, extra}, f.outside)
	assertDenied(t, sendWorkspace(t, p, "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace", `container start denied: bind mount source "`+extra+`" is outside the request's workspace`)
	// A volume device inside W is not the required bind-type workspace mount.
	set([]string{extra}, f.alpha)
	assertDenied(t, sendWorkspace(t, p, "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace", `container start denied: bind mount source "`+extra+`" is outside the request's workspace`)
}

func TestForkStartRecheckVolumeWorkspaceRejectsRelativeDevice(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	setStartVolume(t, f.forkStartRecheckFixture, "local", map[string]string{"o": "bind", "device": "relative/path"})
	p := f.policy()
	p.LibpodContainerCreate.AllowedBindMounts = []string{"/"}
	assertDenied(t, sendWorkspace(t, p, "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace", `container start denied: bind mount source "relative/path" is not an absolute path`)
}

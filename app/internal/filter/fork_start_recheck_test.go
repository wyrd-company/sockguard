package filter

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// TestForkStartRecheckSwapAfterCreateIsDenied creates a container through the
// create check, then replaces its bind source with a symlink out of the
// allowlist. Every start and restart spelling is denied with the start
// reason and never reaches the daemon; the unchanged source and the restored
// source both start.
func TestForkStartRecheckSwapAfterCreateIsDenied(t *testing.T) {
	for _, route := range forkStartRecheckRoutes {
		t.Run(route.path, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			proj := filepath.Join(f.ws, "proj")
			policy := f.policy([]string{f.ws}, []string{f.ws})
			f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{bindMount(proj)}, []string{proj + ":/work"}, nil))

			assertForwarded(t, send(t, policy, http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Binds":["`+proj+`:/work"]}}`))
			assertForwarded(t, send(t, policy, http.MethodPost, route.path, ""))

			f.swap("proj", f.outside)
			assertDenied(t, send(t, policy, http.MethodPost, route.path, ""), "container_start_bind_source_denied",
				route.subject+` denied: bind mount source "`+proj+`" resolves to "`+f.outside+`", which is not allowlisted`)

			f.restore("proj")
			assertForwarded(t, send(t, policy, http.MethodPost, route.path, ""))
			if got := len(f.daemon.inspects()); got != 3 {
				t.Errorf("daemon saw %d inspects, want 3: %q", got, f.daemon.inspects())
			}
		})
	}
}

// TestForkStartRecheckReadsEveryBindSourceField proves each inspect field is
// read: a source that only one field carries is resolved, and a swap under it
// is denied.
func TestForkStartRecheckReadsEveryBindSourceField(t *testing.T) {
	tests := []struct {
		name       string
		body       func(f *forkStartRecheckFixture) string
		wantReason func(f *forkStartRecheckFixture) string
	}{
		{
			name: "mount point source",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, nil, nil)
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + filepath.Join(f.ws, "proj") + `" resolves to "` + f.outside + `", which is not allowlisted`
			},
		},
		{
			// The mount point holds the cleaned ws/proj, which is unchanged.
			// The spec as written walks through the swapped ws/up.
			name: "HostConfig.Binds spelled with ..",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, []string{f.ws + "/up/../proj:/work:rw"}, nil)
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + f.ws + `/up/../proj" resolves to "` + filepath.Join(f.outside, "proj") + `", which is not allowlisted`
			},
		},
		{
			name: "HostConfig.Mounts bind spelled with ..",
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, nil, []ForkStartRecheckMount{bindMount(f.ws + "/up/../proj")})
			},
			wantReason: func(f *forkStartRecheckFixture) string {
				return `container start denied: bind mount source "` + f.ws + `/up/../proj" resolves to "` + filepath.Join(f.outside, "proj") + `", which is not allowlisted`
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			policy := f.policy([]string{f.ws}, nil)
			f.daemon.set(http.StatusOK, tt.body(f))
			assertForwarded(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""))

			// Both bodies resolve through ws/proj or ws/up; swapping both
			// out of the allowlist leaves the field under test as the only
			// one that can carry the denial.
			if strings.Contains(tt.name, "..") {
				f.swap("up", filepath.Join(f.outside, "sub"))
			} else {
				f.swap("proj", f.outside)
			}
			assertDenied(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""), "container_start_bind_source_denied", tt.wantReason(f))
		})
	}
}

// TestForkStartRecheckInspectFailureIsDenied fails the inspect in every way
// the inspector can see and asserts the start is denied with the inspect
// reason, distinct from the escape reason, and never reaches the daemon.
func TestForkStartRecheckInspectFailureIsDenied(t *testing.T) {
	const reason = `container start denied: container "c1" could not be inspected to re-check its bind sources`
	tests := []struct {
		name   string
		status int
		body   string
		policy func(f *forkStartRecheckFixture) PolicyConfig
	}{
		{name: "daemon error", status: http.StatusInternalServerError, body: `{"message":"boom"}`},
		{name: "not found", status: http.StatusNotFound, body: `{"message":"no such container"}`},
		{name: "no content", status: http.StatusNoContent, body: ``},
		{name: "unparsable body", status: http.StatusOK, body: `{"Mounts":`},
		{name: "wrong body shape", status: http.StatusOK, body: `{"Mounts":{"Type":"bind"}}`},
		{name: "body over the response limit", status: http.StatusOK, body: `{"x":"` + strings.Repeat("a", MaxResponseBodyBytes) + `"}`},
		{
			name: "transport error",
			policy: func(f *forkStartRecheckFixture) PolicyConfig {
				p := f.policy([]string{f.ws}, nil)
				p.ForkStartRecheck.InspectContainer = NewForkStartRecheckInspectorWithRoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
					return nil, net.ErrClosed
				}))
				return p
			},
		},
		{
			name: "no inspector configured",
			policy: func(f *forkStartRecheckFixture) PolicyConfig {
				p := f.policy([]string{f.ws}, nil)
				p.ForkStartRecheck.InspectContainer = nil
				return p
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			policy := f.policy([]string{f.ws}, nil)
			if tt.policy != nil {
				policy = tt.policy(f)
			} else {
				f.daemon.set(tt.status, tt.body)
			}
			assertDenied(t, send(t, policy, http.MethodPost, "/containers/c1/start", ""), "container_start_inspect_failed", reason)
		})
	}
}

// TestForkStartRecheckLogsTheInspectCause pins that the cause of an inspect
// failure, which the deny reason leaves out, reaches the log.
func TestForkStartRecheckLogsTheInspectCause(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(http.StatusInternalServerError, `{}`)
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	got := sendLogged(t, logger, f.policy([]string{f.ws}, nil), http.MethodPost, "/containers/c1/start", "")
	assertDenied(t, got, "container_start_inspect_failed", `container start denied: container "c1" could not be inspected to re-check its bind sources`)
	for _, want := range []string{"level=WARN", "container start re-check: inspect failed", "upstream returned 500 Internal Server Error"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q does not hold %q", logs.String(), want)
		}
	}
}

// TestForkStartRecheckNarrowsNothingCreateAllowed covers the starts that must
// pass as before: no allowlist, an allowlist with "/", a source no allowlist
// admits as written, a container with no bind, and non-bind entries.
func TestForkStartRecheckNarrowsNothingCreateAllowed(t *testing.T) {
	tests := []struct {
		name        string
		compat      func(f *forkStartRecheckFixture) []string
		libpod      func(f *forkStartRecheckFixture) []string
		body        func(f *forkStartRecheckFixture) string
		wantInspect bool
	}{
		{
			// The default policy denies every bind at create. Nothing to
			// re-check, so no inspect: a failing daemon cannot deny the start.
			name: "no allowlist",
			body: func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			name:   "compat allowlist holds /",
			compat: func(*forkStartRecheckFixture) []string { return []string{"/"} },
			libpod: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body:   func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			name:   "libpod allowlist holds /",
			compat: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			libpod: func(*forkStartRecheckFixture) []string { return []string{"/"} },
			body:   func(*forkStartRecheckFixture) string { return `not json` },
		},
		{
			// Created under another policy; the start passes as it did.
			name:   "source outside every allowlist as written",
			compat: func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			body: func(f *forkStartRecheckFixture) string {
				return inspectBody(t, []ForkStartRecheckMount{bindMount(filepath.Join(f.ws, "proj"))}, []string{filepath.Join(f.ws, "proj") + ":/w"}, nil)
			},
			wantInspect: true,
		},
		{
			name:        "no bind",
			compat:      func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body:        func(*forkStartRecheckFixture) string { return `{"HostConfig":{"Binds":null},"Mounts":[]}` },
			wantInspect: true,
		},
		{
			name:   "named volume and volume mount",
			compat: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			body: func(f *forkStartRecheckFixture) string {
				// The volume entries name the swapped ws/proj, so only their
				// type keeps them out of the re-check.
				proj := filepath.Join(f.ws, "proj")
				return inspectBody(t, []ForkStartRecheckMount{{Type: "volume", Source: proj, Name: "data"}}, []string{"data:/data"}, []ForkStartRecheckMount{{Type: "volume", Source: proj, Name: "data"}})
			},
			wantInspect: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			var compat, libpod []string
			if tt.compat != nil {
				compat = tt.compat(f)
			}
			if tt.libpod != nil {
				libpod = tt.libpod(f)
			}
			f.swap("proj", f.outside)
			f.daemon.set(http.StatusOK, tt.body(f))
			f.daemon.setVolumes(map[string]string{"/volumes/data": `{"Driver":"local","Options":null}`})
			for _, route := range forkStartRecheckRoutes {
				assertForwarded(t, send(t, f.policy(compat, libpod), http.MethodPost, route.path, ""))
			}
			if got := len(f.daemon.inspects()) > 0; got != tt.wantInspect {
				t.Errorf("daemon inspected = %v, want %v: %q", got, tt.wantInspect, f.daemon.inspects())
			}
		})
	}
}

// TestForkStartRecheckAllowlists checks which allowlist holds a source: each
// one that admits it as written is tried, and one that also admits the
// resolved form is enough. The compat and libpod allowlists apply to both
// route families, since the daemon mounts the same source whichever route
// created the container.
func TestForkStartRecheckAllowlists(t *testing.T) {
	tests := []struct {
		name   string
		compat func(f *forkStartRecheckFixture) []string
		libpod func(f *forkStartRecheckFixture) []string
		// source is the bind source under ws; empty means "proj".
		source     string
		target     func(f *forkStartRecheckFixture) string
		path       string
		wantDenied bool
	}{
		{
			name:       "libpod allowlist holds a compat start",
			libpod:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/containers/c1/start",
			wantDenied: true,
		},
		{
			name:       "compat allowlist holds a libpod start",
			compat:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/libpod/containers/c1/start",
			wantDenied: true,
		},
		{
			// ws/up/inner -> ws/proj: outside the narrow compat entry,
			// inside the libpod one.
			name:   "one admitting allowlist is enough",
			compat: func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			libpod: func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			source: "up/inner",
			target: func(f *forkStartRecheckFixture) string { return filepath.Join(f.ws, "proj") },
			path:   "/containers/c1/start",
		},
		{
			name:       "every admitting allowlist fails",
			compat:     func(f *forkStartRecheckFixture) []string { return []string{filepath.Join(f.ws, "up")} },
			libpod:     func(f *forkStartRecheckFixture) []string { return []string{f.ws} },
			source:     "up/inner",
			target:     func(f *forkStartRecheckFixture) string { return f.outside },
			path:       "/containers/c1/start",
			wantDenied: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckFixture(t)
			var compat, libpod []string
			if tt.compat != nil {
				compat = tt.compat(f)
			}
			if tt.libpod != nil {
				libpod = tt.libpod(f)
			}
			name := tt.source
			if name == "" {
				name = "proj"
			}
			proj := filepath.Join(f.ws, name)
			f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{bindMount(proj)}, nil, nil))
			assertForwarded(t, send(t, f.policy(compat, libpod), http.MethodPost, tt.path, ""))
			f.swap(name, tt.target(f))
			got := send(t, f.policy(compat, libpod), http.MethodPost, tt.path, "")
			if !tt.wantDenied {
				assertForwarded(t, got)
				return
			}
			subject := "container start"
			if strings.HasPrefix(tt.path, "/libpod/") {
				subject = "libpod container start"
			}
			resolved := tt.target(f)
			assertDenied(t, got, "container_start_bind_source_denied",
				subject+` denied: bind mount source "`+proj+`" resolves to "`+resolved+`", which is not allowlisted`)
		})
	}
}

// TestForkStartRecheckOtherRoutesUnchanged sends the container routes beside
// start and restart, and near-miss spellings, and asserts none is inspected.
func TestForkStartRecheckOtherRoutesUnchanged(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(http.StatusInternalServerError, `{}`)
	policy := f.policy([]string{f.ws}, []string{f.ws})
	for _, req := range []struct{ method, path string }{
		{http.MethodPost, "/containers/c1/stop"},
		{http.MethodPost, "/containers/c1/kill"},
		{http.MethodPost, "/containers/c1/pause"},
		{http.MethodPost, "/containers/c1/unpause"},
		{http.MethodPost, "/containers/c1/wait"},
		{http.MethodPost, "/containers/c1/rename"},
		{http.MethodPost, "/containers/c1/start/x"},
		{http.MethodPost, "/containers/start"},
		{http.MethodPost, "/containers/restart"},
		{http.MethodPost, "/libpod/containers/start"},
		{http.MethodPost, "/libpod/containers/c1/stop"},
		{http.MethodPost, "/libpod/pods/c1/start"},
		{http.MethodGet, "/containers/c1/start"},
		{http.MethodGet, "/containers/c1/json"},
	} {
		assertForwarded(t, send(t, policy, req.method, req.path, ""))
	}
	if got := f.daemon.inspects(); len(got) != 0 {
		t.Errorf("daemon saw %q, want no inspect", got)
	}
}

// TestForkStartRecheckInspectsTheNamedContainer pins the identifier the
// inspect uses: everything between the prefix and the action, path-escaped.
func TestForkStartRecheckInspectsTheNamedContainer(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	policy := f.policy([]string{f.ws}, nil)
	for _, route := range []struct{ path, want string }{
		{"/v1.45/containers/c1/start", "GET /containers/c1/json"},
		{"/containers/a/b/restart", "GET /containers/a%2Fb/json"},
		{"/libpod/containers/web-1/start", "GET /containers/web-1/json"},
	} {
		before := len(f.daemon.inspects())
		send(t, policy, http.MethodPost, route.path, "")
		got := f.daemon.inspects()[before:]
		if len(got) != 1 || got[0] != route.want {
			t.Errorf("%s: daemon saw %q, want [%q]", route.path, got, route.want)
		}
	}
}

// TestForkStartRecheckIsTheOnlyStartInspector pins that no other POST
// inspector matches a start or restart path. The middleware runs only the
// highest-severity bucket of matching inspectors, so a second match could
// shadow the re-check or be shadowed by it.
func TestForkStartRecheckIsTheOnlyStartInspector(t *testing.T) {
	policy := compileRuntimePolicy(nil, PolicyConfig{}, newMutationEngine(MutationOptions{}))
	for _, route := range forkStartRecheckRoutes {
		var matched []string
		for _, p := range policy.inspectPoliciesByMethod[http.MethodPost] {
			if p.matches(NormalizePath(route.path)) {
				matched = append(matched, p.errorLogMessage)
			}
		}
		if len(matched) != 1 || matched[0] != "failed to re-check container start bind sources" {
			t.Errorf("%s: matching inspectors %q, want only the start re-check", route.path, matched)
		}
	}
}

// TestForkStartRecheckTarget pins the path parser on inputs the middleware's
// path normalization never hands it, such as an empty identifier.
func TestForkStartRecheckTarget(t *testing.T) {
	for _, tt := range []struct {
		path, id, subject string
		ok                bool
	}{
		{path: "/containers/c1/start", id: "c1", subject: "container start", ok: true},
		{path: "/libpod/containers/c1/restart", id: "c1", subject: "libpod container restart", ok: true},
		{path: "/containers//start"},
		{path: "/containers//restart"},
		{path: "/libpod/containers//start"},
	} {
		id, subject, ok := forkStartRecheckTarget(tt.path)
		if id != tt.id || subject != tt.subject || ok != tt.ok {
			t.Errorf("forkStartRecheckTarget(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.path, id, subject, ok, tt.id, tt.subject, tt.ok)
		}
	}
}

// TestForkStartRecheckInspectsOnlyPost calls the inspector directly with a
// method the middleware's per-method dispatch never hands it.
func TestForkStartRecheckInspectsOnlyPost(t *testing.T) {
	f := newForkStartRecheckFixture(t)
	f.daemon.set(http.StatusInternalServerError, `{}`)
	policy := newForkStartRecheckPolicy(f.policy([]string{f.ws}, nil))
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		if reason, err := policy.inspect(nil, httptest.NewRequest(method, "/containers/c1/start", nil), "/containers/c1/start"); reason != "" || err != nil {
			t.Errorf("%s: inspect = (%q, %v), want no denial", method, reason, err)
		}
	}
	if got := f.daemon.inspects(); len(got) != 0 {
		t.Errorf("daemon saw %q, want no inspect", got)
	}
}

// TestForkStartRecheckNormalizesAllowlistEntries checks that entries are
// cleaned the way the create check cleans them: an entry with a trailing
// slash or a ".." still holds the sources under it, and a relative one holds
// nothing.
func TestForkStartRecheckNormalizesAllowlistEntries(t *testing.T) {
	for _, entries := range [][]string{{"WS/"}, {"WS/./"}, {"WS/up/.."}} {
		f := newForkStartRecheckFixture(t)
		allowed := make([]string, 0, len(entries)+1)
		for _, entry := range entries {
			allowed = append(allowed, strings.Replace(entry, "WS", f.ws, 1))
		}
		allowed = append(allowed, "relative/path")
		proj := filepath.Join(f.ws, "proj")
		f.daemon.set(http.StatusOK, inspectBody(t, []ForkStartRecheckMount{bindMount(proj)}, nil, nil))
		f.swap("proj", f.outside)
		assertDenied(t, send(t, f.policy(allowed, nil), http.MethodPost, "/containers/c1/start", ""), "container_start_bind_source_denied",
			`container start denied: bind mount source "`+proj+`" resolves to "`+f.outside+`", which is not allowlisted`)
	}
}

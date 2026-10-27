package filter

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestForkStartRecheckWorkspaceHeaderIsRequired covers the header rules on
// every start and restart spelling: none, both, a repeated header and an
// invalid value are each denied before the daemon is asked, and the reason
// never quotes the value.
func TestForkStartRecheckWorkspaceHeaderIsRequired(t *testing.T) {
	tests := []struct {
		name       string
		header     func(f *forkStartRecheckWorkspaceFixture) http.Header
		reasonCode string
		reason     string
		inspects   bool
	}{
		{
			name:       "no header",
			header:     func(*forkStartRecheckWorkspaceFixture) http.Header { return nil },
			reasonCode: "container_start_workspace_missing",
			reason:     " denied: the request names no workspace (set X-Sockguard-Workspace or X-Sockguard-Throwaway-Workspace)",
		},
		{
			name: "both headers",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header {
				return http.Header{"X-Sockguard-Workspace": {f.alpha}, "X-Sockguard-Throwaway-Workspace": {f.alpha}}
			},
			reasonCode: "container_start_workspace_ambiguous",
			reason:     " denied: the request names more than one workspace",
		},
		{
			name: "devcontainer header twice",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header {
				return http.Header{"X-Sockguard-Workspace": {f.alpha, f.beta}}
			},
			reasonCode: "container_start_workspace_ambiguous",
			reason:     " denied: the request names more than one workspace",
		},
		{
			name: "throwaway header twice",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header {
				return http.Header{"X-Sockguard-Throwaway-Workspace": {f.alpha, f.alpha}}
			},
			reasonCode: "container_start_workspace_ambiguous",
			reason:     " denied: the request names more than one workspace",
		},
		{
			name:       "empty value",
			header:     func(*forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader("") },
			reasonCode: "container_start_workspace_invalid",
			reason:     " denied: the workspace header does not name a valid workspace",
		},
		{
			name:       "not a workspace",
			header:     func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.outside) },
			reasonCode: "container_start_workspace_invalid",
			reason:     " denied: the workspace header does not name a valid workspace",
			inspects:   true,
		},
		{
			name:       "throwaway header that is not a workspace",
			header:     func(f *forkStartRecheckWorkspaceFixture) http.Header { return throwawayHeader(f.alpha + "/proj") },
			reasonCode: "container_start_workspace_invalid",
			reason:     " denied: the workspace header does not name a valid workspace",
			inspects:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, route := range forkStartRecheckRoutes {
				f := newForkStartRecheckWorkspaceFixture(t)
				f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(f.alpha, "proj")}))
				header := tt.header(f)
				got := sendWorkspace(t, f.policy(), route.path, header)
				assertDenied(t, got, tt.reasonCode, route.subject+tt.reason)
				for _, values := range header {
					for _, value := range values {
						if value != "" && strings.Contains(got.reason, value) {
							t.Errorf("%s: reason %q quotes the header value %q", route.path, got.reason, value)
						}
					}
				}
				if inspected := len(f.daemon.inspects()) > 0; inspected != tt.inspects {
					t.Errorf("%s: daemon inspected = %v, want %v", route.path, inspected, tt.inspects)
				}
			}
		})
	}
}

// TestForkStartRecheckWorkspaceLabelsMustMatch checks the identity labels: each
// must be absent or equal the header's workspace, under either header.
func TestForkStartRecheckWorkspaceLabelsMustMatch(t *testing.T) {
	tests := []struct {
		name     string
		header   func(f *forkStartRecheckWorkspaceFixture) http.Header
		labels   func(f *forkStartRecheckWorkspaceFixture) []string
		mismatch string
	}{
		{name: "no label", header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) }},
		{
			name:   "devcontainer label equal",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"devcontainer.local_folder=" + f.alpha}
			},
		},
		{
			name:   "throwaway label equal under the throwaway header",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return throwawayHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"menagerie.throwaway.workspace=" + f.alpha}
			},
		},
		{
			name:   "devcontainer label of another workspace",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"devcontainer.local_folder=" + f.beta}
			},
			mismatch: "devcontainer.local_folder",
		},
		{
			name:   "devcontainer label of another workspace under the throwaway header",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return throwawayHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"devcontainer.local_folder=" + f.beta}
			},
			mismatch: "devcontainer.local_folder",
		},
		{
			name:   "throwaway label of another workspace",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"menagerie.throwaway.workspace=" + f.beta}
			},
			mismatch: "menagerie.throwaway.workspace",
		},
		{
			name:   "empty label value",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) },
			labels: func(*forkStartRecheckWorkspaceFixture) []string {
				return []string{"devcontainer.local_folder="}
			},
			mismatch: "devcontainer.local_folder",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckWorkspaceFixture(t)
			var labels []string
			if tt.labels != nil {
				labels = tt.labels(f)
			}
			f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(f.alpha, "proj")}, labels...))
			got := sendWorkspace(t, f.policy(), "/containers/c1/start", tt.header(f))
			if tt.mismatch == "" {
				assertForwarded(t, got)
				return
			}
			assertDenied(t, got, "container_start_workspace_label_mismatch",
				`container start denied: container label "`+tt.mismatch+`" does not match the request's workspace`)
			if strings.Contains(got.reason, f.alpha) || strings.Contains(got.reason, f.beta) {
				t.Errorf("reason %q quotes a workspace path", got.reason)
			}
		})
	}
}

// TestForkStartRecheckWorkspaceScopesBindSources is the cross-workspace swap:
// alpha's source replaced after create with a symlink into beta stays inside
// the base allowlist, and only the workspace scope denies it. A source in
// beta as written, and a ".." spelling that creates a directory in beta, are
// denied too.
func TestForkStartRecheckWorkspaceScopesBindSources(t *testing.T) {
	t.Run("swap into another workspace", func(t *testing.T) {
		for _, route := range forkStartRecheckRoutes {
			f := newForkStartRecheckWorkspaceFixture(t)
			proj := filepath.Join(f.alpha, "proj")
			f.daemon.set(http.StatusOK, containerIn(t, []string{proj}, "devcontainer.local_folder="+f.alpha))
			assertForwarded(t, sendWorkspace(t, f.policy(), route.path, devcontainerHeader(f.alpha)))

			if err := os.Rename(proj, proj+".orig"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(f.beta, "proj"), proj); err != nil {
				t.Fatal(err)
			}
			// The allowlist alone admits the swap.
			base := f.policy()
			base.ForkStartRecheck.Workspace = nil
			assertForwarded(t, send(t, base, http.MethodPost, route.path, ""))

			assertDenied(t, sendWorkspace(t, f.policy(), route.path, devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
				route.subject+` denied: bind mount source "`+proj+`" resolves to "`+filepath.Join(f.beta, "proj")+`", which is outside the request's workspace`)
		}
	})
	t.Run("source in another workspace as written", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		source := filepath.Join(f.beta, "proj")
		f.daemon.set(http.StatusOK, containerIn(t, []string{source}))
		assertDenied(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
			`container start denied: bind mount source "`+source+`" is outside the request's workspace`)
	})
	t.Run("the root itself", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		f.daemon.set(http.StatusOK, containerIn(t, []string{f.ws}))
		assertDenied(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
			`container start denied: bind mount source "`+f.ws+`" is outside the request's workspace`)
	})
	t.Run("dot-dot spelling that creates a directory in another workspace", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		raw := f.beta + "/new/../../alpha/proj"
		body := ForkStartRecheckContainer{
			Mounts:     []ForkStartRecheckMount{bindMount(filepath.Join(f.alpha, "proj"))},
			HostConfig: ForkStartRecheckHostConfig{Binds: []string{raw + ":/work"}},
		}
		f.daemon.set(http.StatusOK, inspectBodyOf(t, body))
		assertDenied(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
			`container start denied: bind mount source "`+raw+`" creates directory "`+filepath.Join(f.beta, "new")+`", which is outside the request's workspace`)
	})
	t.Run("missing folder inside the workspace", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(f.alpha, "new", "dir")}))
		assertForwarded(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)))
	})
	t.Run("unresolvable source under an extra bind source", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		// Under the extra bind source, which the base allowlist does not
		// hold, so only the workspace scope resolves it.
		link := filepath.Join(f.extra, "data", "dangling")
		if err := os.Symlink(filepath.Join(f.outside, "nope"), link); err != nil {
			t.Fatal(err)
		}
		f.daemon.set(http.StatusOK, containerIn(t, []string{link}))
		assertDenied(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
			`container start denied: bind mount source "`+link+`" cannot be resolved: dangling symlink at "`+filepath.Join(f.outside, "nope")+`"`)
	})
}

// TestForkStartRecheckWorkspaceExceptionsOnlyForADevcontainer checks the
// extra bind source, which the base allowlist does not hold: a devcontainer
// may bind it, a throwaway header may not, and neither may a container with a
// throwaway label under the devcontainer header, even if the scope function
// returns it. A swap after create under it is denied.
func TestForkStartRecheckWorkspaceExceptionsOnlyForADevcontainer(t *testing.T) {
	tests := []struct {
		name         string
		header       func(f *forkStartRecheckWorkspaceFixture) http.Header
		labels       func(f *forkStartRecheckWorkspaceFixture) []string
		alwaysExtras bool
		denied       bool
	}{
		{name: "devcontainer header", header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) }},
		{name: "throwaway header", header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return throwawayHeader(f.alpha) }, denied: true},
		{
			name:         "throwaway header with a scope that returns the extra",
			header:       func(f *forkStartRecheckWorkspaceFixture) http.Header { return throwawayHeader(f.alpha) },
			alwaysExtras: true,
			denied:       true,
		},
		{
			name:   "throwaway label under the devcontainer header",
			header: func(f *forkStartRecheckWorkspaceFixture) http.Header { return devcontainerHeader(f.alpha) },
			labels: func(f *forkStartRecheckWorkspaceFixture) []string {
				return []string{"menagerie.throwaway.workspace=" + f.alpha}
			},
			alwaysExtras: true,
			denied:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newForkStartRecheckWorkspaceFixture(t)
			policy := f.policy()
			if tt.alwaysExtras {
				policy.ForkStartRecheck.Workspace = func(w ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error) {
					w.Throwaway = false
					return f.scope(w)
				}
			}
			source := filepath.Join(f.extra, "data", "sub")
			var labels []string
			if tt.labels != nil {
				labels = tt.labels(f)
			}
			f.daemon.set(http.StatusOK, containerIn(t, []string{source}, labels...))
			got := sendWorkspace(t, policy, "/containers/c1/start", tt.header(f))
			if tt.denied {
				assertDenied(t, got, "container_start_bind_source_outside_workspace",
					`container start denied: bind mount source "`+source+`" is outside the request's workspace`)
				return
			}
			assertForwarded(t, got)

			// The base re-check does not hold the extra bind source; the
			// workspace scope does. The extra entry itself is resolved, as
			// allowlist entries are, so the swap is below it.
			f.swapPath(source, f.outside)
			assertDenied(t, sendWorkspace(t, policy, "/containers/c1/start", tt.header(f)), "container_start_bind_source_outside_workspace",
				`container start denied: bind mount source "`+source+`" resolves to "`+f.outside+`", which is outside the request's workspace`)
		})
	}
}

// TestForkStartRecheckWorkspaceDeniesSourcesNoAllowlistHolds checks that a
// workspace policy, unlike the plain re-check, denies a source outside the
// roots that neither the base allowlist nor an extra bind source holds.
func TestForkStartRecheckWorkspaceDeniesSourcesNoAllowlistHolds(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	source := filepath.Join(f.outside, "sub")
	f.daemon.set(http.StatusOK, containerIn(t, []string{source}))
	assertDenied(t, sendWorkspace(t, f.policy(), "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
		`container start denied: bind mount source "`+source+`" is outside the request's workspace`)
}

// TestForkStartRecheckWorkspaceProfileWithoutAllowlist checks that the scope
// applies when no allowlist needs the re-check.
func TestForkStartRecheckWorkspaceProfileWithoutAllowlist(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	policy := f.forkStartRecheckFixture.policy([]string{"/"}, nil)
	policy.ForkStartRecheck.Workspace = f.scope
	source := filepath.Join(f.beta, "proj")
	f.daemon.set(http.StatusOK, containerIn(t, []string{source}))
	assertDenied(t, sendWorkspace(t, policy, "/containers/c1/start", devcontainerHeader(f.alpha)), "container_start_bind_source_outside_workspace",
		`container start denied: bind mount source "`+source+`" is outside the request's workspace`)
	assertDenied(t, sendWorkspace(t, policy, "/containers/c1/start", nil), "container_start_workspace_missing",
		"container start denied: the request names no workspace (set X-Sockguard-Workspace or X-Sockguard-Throwaway-Workspace)")
}

// TestForkStartRecheckNoWorkspaceProfileIgnoresHeaders checks that a policy
// without the workspace scope starts without a header and ignores one.
func TestForkStartRecheckNoWorkspaceProfileIgnoresHeaders(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	policy := f.forkStartRecheckFixture.policy([]string{f.ws}, nil)
	f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(f.beta, "proj")}, "devcontainer.local_folder="+f.beta))
	for _, header := range []http.Header{nil, devcontainerHeader(f.alpha), {"X-Sockguard-Workspace": {f.alpha}, "X-Sockguard-Throwaway-Workspace": {f.beta}}} {
		assertForwarded(t, sendWorkspace(t, policy, "/containers/c1/start", header))
	}
}

// TestForkStartRecheckWorkspaceAllowedPaths covers the paths a workspace
// source may use besides its own folder: a base allowlist entry that is a
// symlink, an extra bind source under a per-workspace root, and the parents
// of a base entry that does not exist yet, which the daemon creates.
func TestForkStartRecheckWorkspaceAllowedPaths(t *testing.T) {
	t.Run("base entry that is a symlink", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		link := filepath.Join(filepath.Dir(f.ws), "cache-link")
		if err := os.Symlink(filepath.Join(f.extra, "data"), link); err != nil {
			t.Fatal(err)
		}
		policy := f.forkStartRecheckFixture.policy([]string{f.ws, link}, nil)
		policy.ForkStartRecheck.Workspace = func(w ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error) {
			scope, err := f.scope(w)
			scope.ExtraBindSources = nil
			return scope, err
		}
		f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(link, "sub")}))
		assertForwarded(t, sendWorkspace(t, policy, "/containers/c1/start", devcontainerHeader(f.alpha)))
	})
	t.Run("extra bind source under a root", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		shared := filepath.Join(f.beta, "proj")
		policy := f.policy()
		policy.ForkStartRecheck.Workspace = func(w ForkStartRecheckWorkspace) (ForkStartRecheckWorkspaceScope, error) {
			scope, err := f.scope(w)
			scope.ExtraBindSources = append(scope.ExtraBindSources, shared)
			return scope, err
		}
		f.daemon.set(http.StatusOK, containerIn(t, []string{shared}))
		assertForwarded(t, sendWorkspace(t, policy, "/containers/c1/start", devcontainerHeader(f.alpha)))
	})
	t.Run("parents of a base entry that does not exist yet", func(t *testing.T) {
		f := newForkStartRecheckWorkspaceFixture(t)
		entry := filepath.Join(filepath.Dir(f.ws), "later", "entry")
		policy := f.forkStartRecheckFixture.policy([]string{f.ws, entry}, nil)
		policy.ForkStartRecheck.Workspace = f.scope
		f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(entry, "data")}))
		assertForwarded(t, sendWorkspace(t, policy, "/containers/c1/start", devcontainerHeader(f.alpha)))
	})
}

// TestForkStartRecheckWorkspaceBaseHoldsBothAllowlists checks that a source
// outside the roots may use either create allowlist under the workspace scope.
func TestForkStartRecheckWorkspaceBaseHoldsBothAllowlists(t *testing.T) {
	f := newForkStartRecheckWorkspaceFixture(t)
	policy := f.forkStartRecheckFixture.policy([]string{f.ws}, []string{f.ws, f.outside})
	policy.ForkStartRecheck.Workspace = f.scope
	f.daemon.set(http.StatusOK, containerIn(t, []string{filepath.Join(f.outside, "sub")}))
	assertForwarded(t, sendWorkspace(t, policy, "/containers/c1/start", devcontainerHeader(f.alpha)))
}

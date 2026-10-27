// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// newScopeHarness is newWSHarness with a second per-workspace root,
// <base>/sockets, holding a folder per workspace. Both roots and the
// outside folder are in the base allowlist.
func newScopeHarness(t *testing.T, entries func(f workspaceExceptionsFixture) []map[string]any) (*wsHarness, string) {
	t.Helper()
	f := newWorkspaceExceptionsFixture(t)
	sockets := filepath.Join(f.base, "sockets")
	for _, ws := range []string{"alpha", "beta", "gamma"} {
		if err := os.MkdirAll(filepath.Join(sockets, ws), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if entries != nil {
		writeAtomic(t, f.file, mustJSON(t, workspaceDoc(entries(f)...)))
	}
	store, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{
		Path: f.file, WorkspaceRoot: f.root, PerWorkspaceRoots: []string{f.root, sockets}, MaxBytes: 1 << 20, Logger: testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return &wsHarness{t: t, f: f, store: store, logs: &bytes.Buffer{}}, sockets
}

func (h *wsHarness) scopeOptions(sockets string, edit func(*ContainerCreateOptions)) ContainerCreateOptions {
	return h.options(func(o *ContainerCreateOptions) {
		o.AllowedBindMounts = []string{h.f.root, sockets, h.f.outside, h.f.staging}
		if edit != nil {
			edit(o)
		}
	})
}

func scopedRequest(labels map[string]string, binds ...string) wsCreate {
	return wsCreate{labels: labels, hostConfig: map[string]any{"Binds": binds}}
}

func TestWorkspaceScopeBindsStayInTheirOwnFolders(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	opts := h.scopeOptions(sockets, nil)
	alpha := map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}
	ownSocket := filepath.Join(sockets, "alpha")

	h.admit(opts, scopedRequest(alpha, h.f.alpha+":/w", ownSocket+":/run/sockets", h.f.outside+":/data"))
	h.admit(opts, scopedRequest(alpha, ownSocket+"/new/dir:/run/x"))
	for name, bind := range map[string]string{
		"another workspace folder":            h.f.beta + ":/other",
		"another socket folder":               filepath.Join(sockets, "beta") + ":/run/other",
		"a root itself":                       h.f.root + ":/all",
		"the socket root itself":              sockets + ":/all",
		"dot-dot from its own folder":         h.f.alpha + "/../beta:/other",
		"dot-dot after a created directory":   ownSocket + "/missing/../../beta:/other",
		"a symlink in its folder to another":  h.f.alpha + "/to-beta:/other",
		"a not-yet-existing sibling's folder": filepath.Join(sockets, "delta") + ":/other",
	} {
		t.Run(name, func(t *testing.T) {
			h := h.with(t)
			if name == "a symlink in its folder to another" {
				if err := os.Symlink(h.f.beta, filepath.Join(h.f.alpha, "to-beta")); err != nil {
					t.Fatal(err)
				}
			}
			h.deny(opts, scopedRequest(alpha, h.f.alpha+":/w", bind), "outside this workspace's folder")
			// Control: without apply_workspace_exceptions the base policy
			// admits the same request.
			h.admit(h.scopeOptions(sockets, func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = false }), scopedRequest(alpha, h.f.alpha+":/w", bind))
		})
	}
}

func TestWorkspaceScopeCoversEveryHostPathField(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	opts := h.scopeOptions(sockets, nil)
	alpha := map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}
	other := filepath.Join(sockets, "beta")
	for name, req := range map[string]wsCreate{
		"Mounts bind": {labels: alpha, hostConfig: map[string]any{"Mounts": []map[string]any{{"Type": "bind", "Source": other, "Target": "/x"}}}},
		"Volumes key": {labels: alpha, top: map[string]any{"Volumes": map[string]any{other + ":/x": map[string]any{}}}},
		"local volume bind device": {labels: alpha, hostConfig: map[string]any{"Mounts": []map[string]any{{"Type": "volume", "Source": "v", "Target": "/x", "VolumeOptions": map[string]any{
			"DriverConfig": map[string]any{"Name": "local", "Options": map[string]string{"type": "none", "o": "bind", "device": other}},
		}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			h := h.with(t)
			h.deny(opts, req, "outside this workspace's folder")
		})
	}
}

func TestWorkspaceScopeExtraBindSources(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	shared := filepath.Join(sockets, "beta", "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared}}))))
	h.store.Reload()
	opts := h.scopeOptions(sockets, nil)
	h.admit(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/w", shared+":/shared"))
	// The grant is alpha's: gamma may not use it.
	h.deny(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.gamma}, h.f.gamma+":/w", shared+":/shared"), "outside this workspace's folder")
	// Extra bind sources are an exception, so a throwaway identity for alpha
	// gets none: neither under a root nor elsewhere.
	throwaway := map[string]string{WorkspaceThrowawayLabel: h.f.alpha}
	h.deny(opts, scopedRequest(throwaway, shared+":/shared"), "outside this workspace's folder")
	extra := filepath.Join(h.f.base, "extra")
	if err := os.MkdirAll(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared, extra}}))))
	h.store.Reload()
	h.admit(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/w", extra+":/extra"))
	h.deny(opts, scopedRequest(throwaway, extra+":/extra"), "is not allowlisted")
}

// A workspace folder under a per-workspace root that is a symlink, into
// another workspace's folder say, refuses the request: the bind checks would
// otherwise follow it.
func TestWorkspaceScopeFolderMustBeCanonical(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	alphaSockets := filepath.Join(sockets, "alpha")
	if err := os.Remove(alphaSockets); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(sockets, "beta"), alphaSockets); err != nil {
		t.Fatal(err)
	}
	opts := h.scopeOptions(sockets, nil)
	for _, labels := range []map[string]string{{WorkspaceLocalFolderLabel: h.f.alpha}, {WorkspaceThrowawayLabel: h.f.alpha}} {
		h.deny(opts, scopedRequest(labels, alphaSockets+"/x:/run/x"), "not a canonical directory")
		h.deny(opts, scopedRequest(labels, h.f.outside+":/data"), "not a canonical directory")
	}
	// A folder that does not exist yet is fine: gamma has a socket folder,
	// a new workspace may not.
	if err := os.MkdirAll(filepath.Join(h.f.root, "delta"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.admit(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: filepath.Join(h.f.root, "delta")}, filepath.Join(sockets, "delta")+":/run/s"))
}

func TestWorkspaceStoreForkStartRecheckScope(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	shared := filepath.Join(h.f.outside, "shared")
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared}}))))
	h.store.Reload()
	scope, err := h.store.ForkStartRecheckWorkspace(ForkStartRecheckWorkspace{Path: h.f.alpha})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(scope.Roots, []string{h.f.root, sockets}) || !slices.Equal(scope.Folders, []string{h.f.alpha, filepath.Join(sockets, "alpha")}) || !slices.Equal(scope.ExtraBindSources, []string{shared}) {
		t.Fatalf("scope %+v", scope)
	}
	// Another workspace's entry does not lend its extras.
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(
		workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared}}),
		workspaceEntryDoc(h.f.beta, nil),
	)))
	h.store.Reload()
	if scope, err := h.store.ForkStartRecheckWorkspace(ForkStartRecheckWorkspace{Path: h.f.beta}); err != nil || len(scope.ExtraBindSources) != 0 {
		t.Fatalf("beta scope %+v %v: want no extra bind sources", scope, err)
	}
	if scope, err := h.store.ForkStartRecheckWorkspace(ForkStartRecheckWorkspace{Path: h.f.alpha, Throwaway: true}); err != nil || len(scope.ExtraBindSources) != 0 {
		t.Fatalf("throwaway scope %+v %v: want no extra bind sources", scope, err)
	}
	for _, bad := range []string{"", h.f.alpha + "/", h.f.outside, filepath.Join(h.f.root, "missing")} {
		if _, err := h.store.ForkStartRecheckWorkspace(ForkStartRecheckWorkspace{Path: bad}); err == nil {
			t.Fatalf("workspace %q must be refused", bad)
		}
	}
	// The scope function plugs into the start re-check policy's options.
	var _ ForkStartRecheckWorkspaceFunc = h.store.ForkStartRecheckWorkspace
}

// The throwaway label scopes binds like devcontainer.local_folder and never
// grants an exception, even for a workspace with grants.
func TestWorkspaceScopeThrowawayLabel(t *testing.T) {
	h, sockets := newScopeHarness(t, privilegedGrant)
	opts := h.scopeOptions(sockets, nil)
	throwaway := map[string]string{WorkspaceThrowawayLabel: h.f.alpha}
	h.admit(opts, scopedRequest(throwaway, h.f.alpha+":/w", filepath.Join(sockets, "alpha")+":/run/s"))
	h.deny(opts, scopedRequest(throwaway, h.f.alpha+":/w", h.f.beta+":/other"), "outside this workspace's folder")
	priv := scopedRequest(throwaway, h.f.alpha+":/w")
	priv.hostConfig["Privileged"] = true
	h.deny(opts, priv, "privileged containers are not allowed")
	// Control: the devcontainer label gets the grant.
	devc := scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/w")
	devc.hostConfig["Privileged"] = true
	h.admit(opts, devc)
	for name, value := range map[string]string{
		"relative":       "root/alpha",
		"not clean":      h.f.root + "/x/../alpha",
		"nested":         h.f.alpha + "/sub",
		"outside root":   h.f.outside,
		"missing folder": filepath.Join(h.f.root, "delta"),
	} {
		t.Run(name, func(t *testing.T) {
			h := h.with(t)
			for _, header := range []string{WorkspaceHeader, WorkspaceThrowawayHeader} {
				req := scopedRequest(nil, h.f.outside+":/data")
				req.headers = map[string][]string{header: {value}}
				if reason := h.deny(opts, req, "the workspace header does not name a valid workspace"); strings.Contains(reason, value) {
					t.Fatalf("reason quotes the header: %q", reason)
				}
			}
		})
	}
}

// The throwaway header never grants, even with an entry for W that grants
// privileged, and even when the container carries the devcontainer label.
func TestWorkspaceThrowawayHeaderNeverGrants(t *testing.T) {
	h, sockets := newScopeHarness(t, privilegedGrant)
	opts := h.scopeOptions(sockets, nil)
	for _, labels := range []map[string]string{nil, {WorkspaceLocalFolderLabel: h.f.alpha}, {WorkspaceThrowawayLabel: h.f.alpha}} {
		req := scopedRequest(labels, h.f.alpha+":/w")
		req.hostConfig["Privileged"] = true
		req.headers = map[string][]string{WorkspaceThrowawayHeader: {h.f.alpha}}
		h.deny(opts, req, "privileged containers are not allowed")
		delete(req.hostConfig, "Privileged")
		h.admit(opts, req)
	}
}

// devcontainer.local_folder and menagerie.throwaway.workspace must be absent
// or equal the header's workspace.
func TestWorkspaceLabelsAgreeWithHeader(t *testing.T) {
	h, sockets := newScopeHarness(t, privilegedGrant)
	opts := h.scopeOptions(sockets, nil)
	withHeader := func(labels map[string]string) wsCreate {
		req := scopedRequest(labels, h.f.alpha+":/w")
		req.headers = map[string][]string{WorkspaceHeader: {h.f.alpha}}
		return req
	}
	for _, label := range []string{WorkspaceLocalFolderLabel, WorkspaceThrowawayLabel} {
		for name, value := range map[string]string{"another workspace": h.f.beta, "trailing slash": h.f.alpha + "/", "empty": ""} {
			t.Run(label+" "+name, func(t *testing.T) {
				h := h.with(t)
				reason := h.deny(opts, withHeader(map[string]string{label: value}), "workspace label "+label+" disagrees with the request's workspace")
				if value != "" && strings.Contains(reason, value) {
					t.Fatalf("reason quotes a value: %q", reason)
				}
			})
		}
	}
	h.admit(opts, withHeader(nil))
	h.admit(opts, withHeader(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}))
	h.admit(opts, withHeader(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha, WorkspaceThrowawayLabel: h.f.alpha}))
	// The grant follows the header: a privileged create for alpha with no
	// label is matched.
	priv := withHeader(nil)
	priv.hostConfig["Privileged"] = true
	h.admit(opts, priv)
}

func TestWorkspaceBothHeadersDenied(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	opts := h.scopeOptions(sockets, nil)
	for name, headers := range map[string]map[string][]string{
		"both headers":       {WorkspaceHeader: {h.f.alpha}, WorkspaceThrowawayHeader: {h.f.alpha}},
		"repeated header":    {WorkspaceHeader: {h.f.alpha, h.f.alpha}},
		"repeated throwaway": {WorkspaceThrowawayHeader: {h.f.alpha, h.f.beta}},
	} {
		t.Run(name, func(t *testing.T) {
			h := h.with(t)
			req := scopedRequest(nil, h.f.outside+":/data")
			req.headers = headers
			if reason := h.deny(opts, req, "the request names more than one workspace"); strings.Contains(reason, h.f.alpha) {
				t.Fatalf("deny reason must not echo the header: %q", reason)
			}
		})
	}
	empty := scopedRequest(nil, h.f.outside+":/data")
	empty.headers = map[string][]string{WorkspaceHeader: {""}}
	h.deny(opts, empty, "the workspace header does not name a valid workspace")
}

// A create without a workspace header is denied in the profile, whatever it
// binds and whatever labels it carries, an empty body included.
func TestWorkspaceHeaderlessCreateDenied(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	opts := h.scopeOptions(sockets, nil)
	for name, req := range map[string]wsCreate{
		"binds under a root":   scopedRequest(nil, h.f.alpha+":/w"),
		"binds outside roots":  scopedRequest(nil, h.f.outside+":/data"),
		"no binds":             {},
		"label only":           scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/w"),
		"throwaway label only": scopedRequest(map[string]string{WorkspaceThrowawayLabel: h.f.alpha}, h.f.alpha+":/w"),
	} {
		t.Run(name, func(t *testing.T) {
			h := h.with(t)
			req.headers = map[string][]string{}
			h.deny(opts, req, "the request names no workspace")
		})
	}
	for name, body := range map[string]string{"empty body": "", "malformed body": "{"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/containers/create", strings.NewReader(body))
			reason, err := newContainerCreatePolicy(opts).inspectWithWorkspaceExceptions(testLogger(), r, "/containers/create")
			if err != nil || !strings.Contains(reason, "the request names no workspace") {
				t.Fatalf("reason %q err %v", reason, err)
			}
		})
	}
	// With a header, binds outside every per-workspace root still follow the
	// base policy.
	req := scopedRequest(nil, h.f.outside+":/data", h.f.staging+":/staging")
	req.headers = map[string][]string{WorkspaceHeader: {h.f.gamma}}
	h.admit(opts, req)
}

func TestWorkspaceScopeProfileWithoutApplyUnchanged(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	off := h.scopeOptions(sockets, func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = false })
	headerless := scopedRequest(nil, h.f.alpha+":/w")
	headerless.headers = map[string][]string{}
	h.admit(off, headerless)
	// require_no_restart_policy alone sends the request through the wrapper
	// too; it must not scope binds either.
	restartOnly := h.scopeOptions(sockets, func(o *ContainerCreateOptions) {
		o.ApplyWorkspaceExceptions, o.RequireNoRestartPolicy = false, true
	})
	h.admit(restartOnly, scopedRequest(nil, h.f.alpha+":/w", h.f.beta+":/b"))
	for _, req := range []wsCreate{
		scopedRequest(nil, h.f.alpha+":/w", h.f.beta+":/b"),
		scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha, WorkspaceThrowawayLabel: h.f.beta}, h.f.beta+":/b"),
		scopedRequest(map[string]string{WorkspaceThrowawayLabel: "not-a-path"}, h.f.root+":/all"),
	} {
		h.admit(off, req)
	}
}

// An allowlist entry is judged by where it resolves: a symlink into another
// workspace's folder does not carry that folder past scoping.
func TestWorkspaceScopeSymlinkedAllowlistEntry(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	link := filepath.Join(h.f.base, "beta-link")
	if err := os.Symlink(h.f.beta, link); err != nil {
		t.Fatal(err)
	}
	opts := h.scopeOptions(sockets, func(o *ContainerCreateOptions) { o.AllowedBindMounts = append(o.AllowedBindMounts, link) })
	alpha := map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}
	h.deny(opts, scopedRequest(alpha, link+"/x:/x"), "outside this workspace's folder")
	h.admit(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.beta}, link+"/x:/x"))
}

func TestWorkspaceScopedAllowlist(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := func(rel string) string { return filepath.Join(base, rel) }
	roots := []string{p("ws"), p("sockets")}
	// base itself contains both roots and "/" contains everything: neither
	// can be narrowed by prefix, so both are dropped.
	allowed := []string{p("ws"), p("sockets"), p("cache"), p("ws/alpha/sub"), p("ws/beta"), base, "/"}
	got := workspaceScopedAllowlist(allowed, roots, "alpha", []string{p("sockets/beta/shared")})
	want := []string{p("ws/alpha"), p("sockets/alpha"), p("cache"), p("ws/alpha/sub"), p("sockets/beta/shared")}
	if !slices.Equal(got, want) {
		t.Fatalf("scoped allowlist\n got %v\nwant %v", got, want)
	}
	if got := workspaceScopedAllowlist(allowed, roots, "", nil); !slices.Equal(got, []string{p("cache")}) {
		t.Fatalf("no workspace: %v", got)
	}
}

func TestPerWorkspaceRootsChecked(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	sockets := filepath.Join(f.base, "sockets")
	if err := os.MkdirAll(filepath.Join(sockets, "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.base, "sockets-link")
	if err := os.Symlink(sockets, link); err != nil {
		t.Fatal(err)
	}
	newStore := func(roots []string) error {
		_, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{Path: f.file, WorkspaceRoot: f.root, PerWorkspaceRoots: roots, MaxBytes: 1 << 20, Logger: testLogger()})
		return err
	}
	if err := newStore([]string{f.root, sockets}); err != nil {
		t.Fatalf("valid roots: %v", err)
	}
	for name, roots := range map[string][]string{
		"missing workspace root": {sockets},
		"symlinked root":         {f.root, link},
		"nested root":            {f.root, sockets, filepath.Join(sockets, "inner")},
		"repeated root":          {f.root, f.root},
	} {
		if err := newStore(roots); err == nil {
			t.Fatalf("%s: roots %v must be refused", name, roots)
		}
	}
	store, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{Path: f.file, WorkspaceRoot: f.root, MaxBytes: 1 << 20, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Load().perWorkspaceRoots(); !slices.Equal(got, []string{f.root}) {
		t.Fatalf("default roots %v, want the workspace root", got)
	}
}

// extraBindSources are a grant: scoping honors them only when the exception
// applies (the devcontainer header, an entry for W and a passing match).
func TestWorkspaceScopeExtrasOnlyWhenTheExceptionApplies(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	shared := filepath.Join(sockets, "beta", "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared}}))))
	h.store.Reload()
	opts := h.scopeOptions(sockets, nil)
	alpha := map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}
	// Control: the match passes and the extra is usable.
	h.admit(opts, scopedRequest(alpha, h.f.alpha+":/w", shared+":/shared"))
	// A bind outside W and its extras breaks agreement: no exception, so
	// the extra under a root is out of scope.
	h.deny(opts, scopedRequest(alpha, h.f.alpha+":/w", shared+":/shared", h.f.outside+":/data"), "outside this workspace's folder")
	// No workspace mount: no exception, no extra.
	h.deny(opts, scopedRequest(alpha, shared+":/shared"), "outside this workspace's folder")
}

// The roots come from the configuration: an invalid file removes the grants
// and leaves the scoping in force.
func TestWorkspaceScopeHoldsWithAnInvalidFile(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	writeAtomic(t, h.f.file, []byte(`{"version":1,"exceptions":[],"extra":true}`))
	if h.store.Reload().State() != WorkspaceExceptionsInvalid {
		t.Fatal("fixture: file should be invalid")
	}
	opts := h.scopeOptions(sockets, nil)
	alpha := map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}
	h.admit(opts, scopedRequest(alpha, h.f.alpha+":/w", filepath.Join(sockets, "alpha")+":/run/s"))
	h.deny(opts, scopedRequest(alpha, h.f.alpha+":/w", h.f.beta+":/other"), "outside this workspace's folder")
}

// DenyWorkspaceScopeReason is exported for callers other than create: a
// throwaway identity drops any grant it is passed, and no identity drops
// every per-workspace root.
func TestDenyWorkspaceScopeReasonAPI(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	shared := filepath.Join(sockets, "beta", "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	snap := h.store.Load()
	allowed := []string{h.f.root, sockets}
	req := WorkspaceExceptionRequest{Binds: []string{h.f.alpha + ":/w", shared + ":/shared"}}
	devcontainer := WorkspaceIdentity{Kind: WorkspaceIdentityDevcontainer, Workspace: h.f.alpha}
	throwaway := WorkspaceIdentity{Kind: WorkspaceIdentityThrowaway, Workspace: h.f.alpha}
	if reason := DenyWorkspaceScopeReason(snap, devcontainer, req, allowed, []string{shared}); reason != "" {
		t.Fatalf("devcontainer with the grant: %q", reason)
	}
	if reason := DenyWorkspaceScopeReason(snap, devcontainer, req, allowed, nil); reason == "" {
		t.Fatal("devcontainer without the grant must be denied")
	}
	if reason := DenyWorkspaceScopeReason(snap, throwaway, req, allowed, []string{shared}); reason == "" {
		t.Fatal("a throwaway identity must not use a grant it is passed")
	}
	own := WorkspaceExceptionRequest{Binds: []string{h.f.alpha + ":/w"}}
	if reason := DenyWorkspaceScopeReason(snap, WorkspaceIdentity{Kind: WorkspaceIdentityNone}, own, allowed, nil); !strings.Contains(reason, "needs a workspace") {
		t.Fatalf("no identity: %q", reason)
	}
}

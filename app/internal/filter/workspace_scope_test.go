// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"bytes"
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
	// A throwaway request is scoped by alpha's extras too, but they do not
	// widen its allowlist: an extra outside the base allowlist stays denied.
	throwaway := map[string]string{WorkspaceThrowawayLabel: h.f.alpha}
	h.admit(opts, scopedRequest(throwaway, shared+":/shared"))
	extra := filepath.Join(h.f.base, "extra")
	if err := os.MkdirAll(extra, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, h.f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(h.f.alpha, map[string]any{"extraBindSources": []string{shared, extra}}))))
	h.store.Reload()
	h.admit(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha}, h.f.alpha+":/w", extra+":/extra"))
	h.deny(opts, scopedRequest(throwaway, extra+":/extra"), "is not allowlisted")
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
			h.deny(opts, scopedRequest(map[string]string{WorkspaceThrowawayLabel: value}, h.f.outside+":/data"), "label "+WorkspaceThrowawayLabel)
		})
	}
}

func TestWorkspaceScopeBothLabelsDenied(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	reason := h.deny(h.scopeOptions(sockets, nil), scopedRequest(map[string]string{
		WorkspaceLocalFolderLabel: h.f.alpha, WorkspaceThrowawayLabel: h.f.alpha,
	}, h.f.outside+":/data"), "cannot both be set")
	if strings.Contains(reason, h.f.alpha) {
		t.Fatalf("deny reason must not echo the label values: %q", reason)
	}
}

func TestWorkspaceScopeNoLabel(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	opts := h.scopeOptions(sockets, nil)
	h.deny(opts, scopedRequest(nil, h.f.alpha+":/w"), "needs a workspace label")
	h.deny(opts, scopedRequest(nil, filepath.Join(sockets, "alpha")+":/run/s"), "needs a workspace label")
	// A label that is not a workspace key gives no identity.
	h.deny(opts, scopedRequest(map[string]string{WorkspaceLocalFolderLabel: h.f.alpha + "/"}, h.f.alpha+":/w"), "needs a workspace label")
	// Binds outside every per-workspace root still follow the base policy.
	h.admit(opts, scopedRequest(nil, h.f.outside+":/data", h.f.staging+":/staging"))
	h.admit(opts, wsCreate{hostConfig: map[string]any{"Binds": []string{"named:/data"}}})
}

func TestWorkspaceScopeProfileWithoutApplyUnchanged(t *testing.T) {
	h, sockets := newScopeHarness(t, nil)
	off := h.scopeOptions(sockets, func(o *ContainerCreateOptions) { o.ApplyWorkspaceExceptions = false })
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

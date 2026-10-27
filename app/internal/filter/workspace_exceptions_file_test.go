// relationships:
//
//	references: [../../../docs/content/docs/workspace-exceptions]
package filter

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// workspaceExceptionsFixture is a temp tree:
//
//	<base>/root/alpha/       workspace with an entry
//	<base>/root/beta/        workspace with an entry
//	<base>/root/gamma/       workspace without an entry
//	<base>/outside/          a sibling of the root, in the base allowlist
//	<base>/staging/          a Compose staging folder, in the base allowlist
type workspaceExceptionsFixture struct {
	base    string
	root    string
	alpha   string
	beta    string
	gamma   string
	outside string
	staging string
	file    string
}

func newWorkspaceExceptionsFixture(t *testing.T) workspaceExceptionsFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := workspaceExceptionsFixture{
		base:    base,
		root:    filepath.Join(base, "root"),
		outside: filepath.Join(base, "outside"),
		staging: filepath.Join(base, "staging"),
		file:    filepath.Join(base, "policy", "workspace-exceptions.json"),
	}
	f.alpha = filepath.Join(f.root, "alpha")
	f.beta = filepath.Join(f.root, "beta")
	f.gamma = filepath.Join(f.root, "gamma")
	for _, dir := range []string{f.alpha, f.beta, f.gamma, f.outside, f.staging, filepath.Dir(f.file)} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// entry returns a valid entry object for workspace with the given grants.
func workspaceEntryDoc(workspace string, grants map[string]any) map[string]any {
	if grants == nil {
		grants = map[string]any{}
	}
	return map[string]any{
		"workspace": workspace,
		"grants":    grants,
		"approval": map[string]any{
			"by": map[string]any{"issuer": "https://id.example.org", "subject": "user-0001", "name": "Manager One"},
			"at": "2026-01-02T03:04:05Z",
		},
	}
}

func workspaceDoc(entries ...map[string]any) map[string]any {
	list := make([]any, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	return map[string]any{"version": 1, "exceptions": list}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeAtomic writes body by the replace protocol: a temp file in the same
// folder, renamed over the target.
func writeAtomic(t *testing.T, target string, body []byte) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(target), ".tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		t.Fatal(err)
	}
}

func newTestWorkspaceStore(t *testing.T, f workspaceExceptionsFixture, observe func(string)) *WorkspaceExceptionStore {
	t.Helper()
	store, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{
		Path: f.file, WorkspaceRoot: f.root, MaxBytes: 1 << 20, Logger: testLogger(), ObserveLoad: observe,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestWorkspaceExceptionsParseValidDocument(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	body := mustJSON(t, workspaceDoc(
		workspaceEntryDoc(f.alpha, map[string]any{
			"privileged": true, "capAdd": []string{"cap_sys_ptrace", "ALL"}, "namespaces": []string{"pid", "ipc", "network", "userns", "cgroupns"},
			"devices": []string{"/dev/fuse"}, "deviceCgroupRules": []string{"c 10:229 rwm"}, "gpus": true,
			"extraBindSources": []string{f.outside}, "securityOpt": []string{"seccomp=unconfined", "apparmor=unconfined", "apparmor=sample-profile", "label=disable", "systempaths=unconfined"},
			"runtimes": []string{"sample-runc"}, "sysctls": []string{"net.ipv4.ip_forward"}, "restartPolicy": []string{"unless-stopped", "always", "on-failure"},
		}),
		workspaceEntryDoc(f.beta, nil),
	))
	entries, err := parseWorkspaceExceptions(body, f.root)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	g := entries[f.alpha].grants
	if !g.privileged || !g.allCapabilities || !slices.Equal(g.capabilities, []string{"SYS_PTRACE"}) || !g.hostPID || !g.hostIPC ||
		!g.hostNetwork || !g.hostUserNS || !g.hostCgroupNS || !g.gpus || !g.seccompUnconfined || !g.appArmorUnconfined ||
		!g.selinuxDisable || !g.systemPathsUnconfined || !slices.Equal(g.appArmorProfiles, []string{"sample-profile"}) ||
		!slices.Equal(g.deviceCgroupRules, []string{"c 10:229 rwm"}) || len(g.restartPolicies) != 3 {
		t.Fatalf("grants not decoded: %+v", g)
	}
	if beta := entries[f.beta].grants; beta.privileged || len(beta.extraBindSources) != 0 {
		t.Fatalf("missing grant fields must mean not granted: %+v", beta)
	}
	future := workspaceEntryDoc(f.gamma, nil)
	future["approval"].(map[string]any)["at"] = "2999-12-31T23:59:59Z"
	if _, err := parseWorkspaceExceptions(mustJSON(t, workspaceDoc(future)), f.root); err != nil {
		t.Fatalf("approval.at is not compared with the clock: %v", err)
	}
	if a := entries[f.alpha].approval; a.Issuer != "https://id.example.org" || a.Subject != "user-0001" || a.At != "2026-01-02T03:04:05Z" {
		t.Fatalf("approval not decoded: %+v", a)
	}
}

// Each row changes one thing in a valid document; every one makes the whole
// file invalid.
func TestWorkspaceExceptionsParseRejectsInvalidDocuments(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	valid := func() map[string]any {
		return workspaceDoc(workspaceEntryDoc(f.alpha, map[string]any{"privileged": true}))
	}
	entry := func(doc map[string]any) map[string]any { return doc["exceptions"].([]any)[0].(map[string]any) }
	grants := func(doc map[string]any) map[string]any { return entry(doc)["grants"].(map[string]any) }
	approval := func(doc map[string]any) map[string]any { return entry(doc)["approval"].(map[string]any) }
	if _, err := parseWorkspaceExceptions(mustJSON(t, valid()), f.root); err != nil {
		t.Fatalf("control must parse: %v", err)
	}
	mutated := func(edit func(map[string]any)) []byte {
		doc := valid()
		edit(doc)
		return mustJSON(t, doc)
	}
	validText := string(mustJSON(t, valid()))
	for _, tc := range []struct {
		name string
		body []byte
		want string
	}{
		{"version 2", mutated(func(d map[string]any) { d["version"] = 2 }), "version 2"},
		{"version missing", mutated(func(d map[string]any) { delete(d, "version") }), `missing required key "version"`},
		{"exceptions missing", mutated(func(d map[string]any) { delete(d, "exceptions") }), `missing required key "exceptions"`},
		{"unknown top-level key", mutated(func(d map[string]any) { d["extra"] = true }), `unknown key "extra"`},
		{"unknown entry key", mutated(func(d map[string]any) { entry(d)["comment"] = "x" }), `unknown key "comment"`},
		{"unknown grant key", mutated(func(d map[string]any) { grants(d)["uts"] = true }), `unknown key "uts"`},
		{"case-variant grant key", mutated(func(d map[string]any) { delete(grants(d), "privileged"); grants(d)["Privileged"] = true }), `unknown key "Privileged"`},
		{"unknown approval key", mutated(func(d map[string]any) { approval(d)["expires"] = "x" }), `unknown key "expires"`},
		{"unknown approval.by key", mutated(func(d map[string]any) { approval(d)["by"].(map[string]any)["email"] = "x" }), `unknown key "email"`},
		{"duplicate key", []byte(strings.Replace(validText, `"privileged":true`, `"privileged":false,"privileged":true`, 1)), "duplicate"},
		{"case-variant duplicate key", []byte(strings.Replace(validText, `"version":1`, `"version":1,"Version":1`, 1)), "Version"},
		{"trailing data", []byte(validText + ` {}`), "document"},
		{"top level array", []byte(`[` + validText + `]`), "document must be an object"},
		{"wrong type", mutated(func(d map[string]any) { grants(d)["privileged"] = "yes" }), "wrong type"},
		{"null grant", mutated(func(d map[string]any) { grants(d)["capAdd"] = nil }), "must not be null"},
		{"null list element", mutated(func(d map[string]any) { grants(d)["capAdd"] = []any{nil} }), "must not be null"},
		{"null grants", mutated(func(d map[string]any) { entry(d)["grants"] = nil }), "not null"},
		{"invalid UTF-8", []byte("{\"version\":1,\"exceptions\":[],\"x\":\"\xff\"}"), "UTF-8"},
		{"approval missing", mutated(func(d map[string]any) { delete(entry(d), "approval") }), `missing required key "approval"`},
		{"approval.by.issuer missing", mutated(func(d map[string]any) { delete(approval(d)["by"].(map[string]any), "issuer") }), `missing required key "issuer"`},
		{"approval.by.subject empty", mutated(func(d map[string]any) { approval(d)["by"].(map[string]any)["subject"] = "" }), "must not be empty"},
		{"approval.at not UTC", mutated(func(d map[string]any) { approval(d)["at"] = "2026-01-02T03:04:05+01:00" }), "not an RFC 3339 UTC timestamp"},
		{"approval.at not RFC 3339", mutated(func(d map[string]any) { approval(d)["at"] = "2026-01-02 03:04:05" }), "not an RFC 3339 UTC timestamp"},
		{"approval.note too long", mutated(func(d map[string]any) { approval(d)["note"] = strings.Repeat("é", 501) }), "longer than 500"},
		{"workspace relative", mutated(func(d map[string]any) { entry(d)["workspace"] = "root/alpha" }), "not an absolute, clean path"},
		{"workspace trailing slash", mutated(func(d map[string]any) { entry(d)["workspace"] = f.alpha + "/" }), "not an absolute, clean path"},
		{"workspace not clean", mutated(func(d map[string]any) { entry(d)["workspace"] = f.root + "/x/../alpha" }), "not an absolute, clean path"},
		{"workspace nested", mutated(func(d map[string]any) { entry(d)["workspace"] = f.alpha + "/sub" }), "not a direct child"},
		{"workspace outside root", mutated(func(d map[string]any) { entry(d)["workspace"] = f.outside }), "not a direct child"},
		{"workspace is the root", mutated(func(d map[string]any) { entry(d)["workspace"] = f.root }), "not a direct child"},
		{"duplicate workspace", mutated(func(d map[string]any) {
			d["exceptions"] = append(d["exceptions"].([]any), workspaceEntryDoc(f.alpha, nil))
		}), "appears more than once"},
		{"extraBindSources /", mutated(func(d map[string]any) { grants(d)["extraBindSources"] = []string{"/"} }), `"/" cannot be granted`},
		{"extraBindSources relative", mutated(func(d map[string]any) { grants(d)["extraBindSources"] = []string{"srv"} }), "not an absolute, clean path"},
		{"devices /", mutated(func(d map[string]any) { grants(d)["devices"] = []string{"/"} }), `"/" cannot be granted`},
		{"namespace uts", mutated(func(d map[string]any) { grants(d)["namespaces"] = []string{"uts"} }), "not a grantable namespace"},
		{"capability not a name", mutated(func(d map[string]any) { grants(d)["capAdd"] = []string{"SYS ADMIN"} }), "not a capability name"},
		{"device cgroup rule malformed", mutated(func(d map[string]any) { grants(d)["deviceCgroupRules"] = []string{"x 1:2 q"} }), "not a device cgroup rule"},
		{"securityOpt seccomp profile", mutated(func(d map[string]any) { grants(d)["securityOpt"] = []string{"seccomp=/profiles/x.json"} }), "not a grantable security option"},
		{"securityOpt colon form", mutated(func(d map[string]any) { grants(d)["securityOpt"] = []string{"seccomp:unconfined"} }), "not a grantable security option"},
		{"securityOpt no-new-privileges", mutated(func(d map[string]any) { grants(d)["securityOpt"] = []string{"no-new-privileges=false"} }), "not a grantable security option"},
		{"runtime empty", mutated(func(d map[string]any) { grants(d)["runtimes"] = []string{""} }), "not a runtime name"},
		{"sysctl key with value", mutated(func(d map[string]any) { grants(d)["sysctls"] = []string{"net.ipv4.ip_forward=1"} }), "not a sysctl key"},
		{"restartPolicy no", mutated(func(d map[string]any) { grants(d)["restartPolicy"] = []string{"no"} }), "not a grantable restart policy"},
		{"restartPolicy unknown", mutated(func(d map[string]any) { grants(d)["restartPolicy"] = []string{"sometimes"} }), "not a grantable restart policy"},
		{"restartPolicy case variant", mutated(func(d map[string]any) { grants(d)["restartPolicy"] = []string{"Always"} }), "not a grantable restart policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWorkspaceExceptions(tc.body, f.root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v; want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestWorkspaceExceptionStoreStates(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	var loads []string
	store := newTestWorkspaceStore(t, f, func(r string) { loads = append(loads, r) })
	if got := store.Load().State(); got != WorkspaceExceptionsMissing {
		t.Fatalf("no file: state %q, want missing", got)
	}
	writeAtomic(t, f.file, mustJSON(t, workspaceDoc(workspaceEntryDoc(f.alpha, nil))))
	if snap := store.Reload(); snap.State() != WorkspaceExceptionsLoaded || snap.Len() != 1 {
		t.Fatalf("valid file: state %q len %d", snap.State(), snap.Len())
	}
	writeAtomic(t, f.file, []byte(`{"version":1}`))
	snap := store.Reload()
	if snap.State() != WorkspaceExceptionsInvalid || snap.Err() == nil || snap.Len() != 0 {
		t.Fatalf("invalid file must drop every entry (no last good): state %q len %d err %v", snap.State(), snap.Len(), snap.Err())
	}
	if err := os.Remove(f.file); err != nil {
		t.Fatal(err)
	}
	if got := store.Reload().State(); got != WorkspaceExceptionsMissing {
		t.Fatalf("removed file: state %q, want missing", got)
	}
	if want := []string{"missing", "ok", "invalid", "missing"}; !slices.Equal(loads, want) {
		t.Fatalf("load outcomes %v, want %v", loads, want)
	}
}

// A missing file is logged when it goes missing, not on every reload; an
// invalid file logs an error with its cause on every load.
func TestWorkspaceExceptionStoreLogs(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	var logs bytes.Buffer
	store, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{
		Path: f.file, WorkspaceRoot: f.root, MaxBytes: 1 << 20, Logger: slog.New(slog.NewTextHandler(&logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	store.Reload()
	store.Reload()
	if got := strings.Count(logs.String(), "workspace exceptions file not found"); got != 1 {
		t.Fatalf("missing file logged %d times over three loads, want 1:\n%s", got, logs.String())
	}
	writeAtomic(t, f.file, []byte(`{"version":1,"exceptions":[],"extra":1}`))
	store.Reload()
	store.Reload()
	if got := strings.Count(logs.String(), "level=ERROR msg=\"workspace exceptions file invalid"); got != 2 || !strings.Contains(logs.String(), `unknown key \"extra\"`) {
		t.Fatalf("invalid file: %d error lines, want 2 naming the cause:\n%s", got, logs.String())
	}
}

func TestWorkspaceExceptionStoreRejectsOversizedFile(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	body := mustJSON(t, workspaceDoc(workspaceEntryDoc(f.alpha, nil)))
	writeAtomic(t, f.file, body)
	store, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{Path: f.file, WorkspaceRoot: f.root, MaxBytes: int64(len(body) - 1), Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	if snap := store.Load(); snap.State() != WorkspaceExceptionsInvalid {
		t.Fatalf("oversized file: state %q, want invalid", snap.State())
	}
}

func TestWorkspaceExceptionStoreRequiresCanonicalRoot(t *testing.T) {
	f := newWorkspaceExceptionsFixture(t)
	link := filepath.Join(f.base, "rootlink")
	if err := os.Symlink(f.root, link); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{link, f.root + "/", "/", filepath.Join(f.base, "absent"), "relative/root"} {
		if _, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{Path: f.file, WorkspaceRoot: root, MaxBytes: 1 << 20}); err == nil {
			t.Fatalf("root %q must be refused", root)
		}
	}
	if _, err := NewWorkspaceExceptionStore(WorkspaceExceptionStoreOptions{Path: "relative.json", WorkspaceRoot: f.root, MaxBytes: 1 << 20}); err == nil {
		t.Fatal("a relative file path must be refused")
	}
}

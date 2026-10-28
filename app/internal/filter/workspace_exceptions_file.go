package filter

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/codeswhat/sockguard/app/internal/boundedio"
)

// Fork-owned (wyrd-company/sockguard): the workspace exceptions file.
//
// The file gives one workspace folder gates on Docker-compat
// POST /containers/create that the base policy keeps closed. The operator
// writes it; the proxy only reads it. docs/content/docs/workspace-exceptions.mdx
// is the contract and docs/workspace-exceptions.schema.json its JSON Schema.
// The proxy is the authority: it validates the file here and does not read the
// schema.

// WorkspaceExceptionsFileVersion is the only accepted value of "version".
const WorkspaceExceptionsFileVersion = 1

// WorkspaceLocalFolderLabel is the container label a create request names its
// workspace folder with. devcontainer-builder writes it from LocalWorkspace.
const WorkspaceLocalFolderLabel = "devcontainer.local_folder"

// maxWorkspaceApprovalNoteRunes bounds approval.note.
const maxWorkspaceApprovalNoteRunes = 500

// workspaceExceptionNamespaces maps each grantable namespace name to the
// HostConfig field whose "host" value it admits. "uts" is absent: host UTS is
// always denied.
var workspaceExceptionNamespaces = []string{"pid", "ipc", "network", "userns", "cgroupns"}

// workspaceExceptionRestartPolicies is the closed set of restartPolicy grant
// entries. "no" and "" need no grant.
var workspaceExceptionRestartPolicies = []string{"always", "unless-stopped", "on-failure"}

var (
	workspaceCapabilityName = regexp.MustCompile(`^[A-Z0-9_]+$`)
	workspaceSysctlKey      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
	workspaceAppArmorName   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]*$`)
)

// workspaceGrants is one entry's grants in normalized form. A zero field is
// "not granted".
type workspaceGrants struct {
	privileged            bool
	allCapabilities       bool
	capabilities          []string
	hostPID               bool
	hostIPC               bool
	hostNetwork           bool
	hostUserNS            bool
	hostCgroupNS          bool
	devices               []string
	deviceCgroupRules     []string
	gpus                  bool
	extraBindSources      []string
	seccompUnconfined     bool
	appArmorUnconfined    bool
	appArmorProfiles      []string
	selinuxDisable        bool
	systemPathsUnconfined bool
	runtimes              []string
	sysctls               []string
	restartPolicies       []string
}

// WorkspaceApproval is an entry's approval provenance, logged on every
// applied exception. The proxy checks its shape only.
type WorkspaceApproval struct {
	Issuer  string
	Subject string
	Name    string
	At      string
	Note    string
}

type workspaceExceptionEntry struct {
	workspace string
	grants    workspaceGrants
	approval  WorkspaceApproval
}

// WorkspaceExceptionsState is the load state of a snapshot.
type WorkspaceExceptionsState string

const (
	// WorkspaceExceptionsLoaded: the file was read and is valid.
	WorkspaceExceptionsLoaded WorkspaceExceptionsState = "loaded"
	// WorkspaceExceptionsMissing: the file does not exist. No exceptions.
	WorkspaceExceptionsMissing WorkspaceExceptionsState = "missing"
	// WorkspaceExceptionsInvalid: the file could not be read or is invalid.
	// No exceptions until a valid file arrives.
	WorkspaceExceptionsInvalid WorkspaceExceptionsState = "invalid"
)

// WorkspaceExceptionSnapshot is one immutable load of the file. A create
// request takes one snapshot at admission and uses it for matching and for
// its grants.
type WorkspaceExceptionSnapshot struct {
	state WorkspaceExceptionsState
	root  string
	// roots are the per-workspace roots: binds under one are scoped to the
	// request's workspace folder. They do not depend on the file, so every
	// snapshot, missing or invalid too, carries them.
	roots   []string
	err     error
	entries map[string]*workspaceExceptionEntry
}

// State reports how the snapshot was loaded.
func (s *WorkspaceExceptionSnapshot) State() WorkspaceExceptionsState {
	if s == nil {
		return WorkspaceExceptionsMissing
	}
	return s.state
}

// Err is the load failure of an invalid snapshot, nil otherwise.
func (s *WorkspaceExceptionSnapshot) Err() error {
	if s == nil {
		return nil
	}
	return s.err
}

// Len is the number of entries.
func (s *WorkspaceExceptionSnapshot) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// WorkspaceExceptionStore holds the current snapshot of one exceptions file
// and replaces it on Reload. It is safe for concurrent use.
type WorkspaceExceptionStore struct {
	path     string
	root     string
	roots    []string
	maxBytes int64
	logger   *slog.Logger
	observe  func(result string)

	current  atomic.Pointer[WorkspaceExceptionSnapshot]
	reloadMu sync.Mutex
}

// WorkspaceExceptionStoreOptions configures NewWorkspaceExceptionStore.
type WorkspaceExceptionStoreOptions struct {
	// Path is workspace_exceptions.file: an absolute path.
	Path string
	// WorkspaceRoot is workspace_exceptions.workspace_root. It must be
	// absolute and canonical: filepath.EvalSymlinks(root) == root.
	WorkspaceRoot string
	// PerWorkspaceRoots is workspace_exceptions.per_workspace_roots. Empty
	// means [WorkspaceRoot]. Each root must be canonical, WorkspaceRoot must
	// be one of them, and no root may sit inside another.
	PerWorkspaceRoots []string
	// MaxBytes bounds the file size (config.MaxConfigFileBytes).
	MaxBytes int64
	Logger   *slog.Logger
	// ObserveLoad, when set, is called with "ok", "missing" or "invalid"
	// after every load (the reload-outcome metric).
	ObserveLoad func(result string)
}

// NewWorkspaceExceptionStore checks the workspace root and loads the file
// once. A missing or invalid file is not an error here: the store then holds
// a snapshot without exceptions. A workspace root that is not canonical is.
func NewWorkspaceExceptionStore(opts WorkspaceExceptionStoreOptions) (*WorkspaceExceptionStore, error) {
	if !path.IsAbs(opts.Path) {
		return nil, fmt.Errorf("workspace exceptions file %q is not an absolute path", opts.Path)
	}
	roots, err := CheckWorkspaceExceptionRoots(opts.WorkspaceRoot, opts.PerWorkspaceRoots)
	if err != nil {
		return nil, err
	}
	if opts.MaxBytes <= 0 {
		return nil, errors.New("workspace exceptions file size bound must be positive")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &WorkspaceExceptionStore{
		path:     opts.Path,
		root:     opts.WorkspaceRoot,
		roots:    roots,
		maxBytes: opts.MaxBytes,
		logger:   opts.Logger,
		observe:  opts.ObserveLoad,
	}
	s.Reload()
	return s, nil
}

// Path is the watched file path.
func (s *WorkspaceExceptionStore) Path() string { return s.path }

// Load returns the current snapshot. A nil store has no exceptions.
func (s *WorkspaceExceptionStore) Load() *WorkspaceExceptionSnapshot {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Reload reads the file again and swaps in the new snapshot. Loads are
// serialized; a request in flight keeps the snapshot it took.
func (s *WorkspaceExceptionStore) Reload() *WorkspaceExceptionSnapshot {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()

	next := s.read()
	prev := s.current.Swap(next)
	s.report(prev, next)
	return next
}

func (s *WorkspaceExceptionStore) read() *WorkspaceExceptionSnapshot {
	body, err := boundedio.ReadFile(s.path, s.maxBytes)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &WorkspaceExceptionSnapshot{state: WorkspaceExceptionsMissing, root: s.root, roots: s.roots}
		}
		return &WorkspaceExceptionSnapshot{state: WorkspaceExceptionsInvalid, root: s.root, roots: s.roots, err: err}
	}
	entries, err := parseWorkspaceExceptions(body, s.root)
	if err != nil {
		return &WorkspaceExceptionSnapshot{state: WorkspaceExceptionsInvalid, root: s.root, roots: s.roots, err: err}
	}
	return &WorkspaceExceptionSnapshot{state: WorkspaceExceptionsLoaded, root: s.root, roots: s.roots, entries: entries}
}

func (s *WorkspaceExceptionStore) report(prev, next *WorkspaceExceptionSnapshot) {
	switch next.state {
	case WorkspaceExceptionsLoaded:
		s.logger.Info("workspace exceptions loaded", "path", s.path, "entries", len(next.entries))
		s.observeLoad("ok")
	case WorkspaceExceptionsMissing:
		// Normal before the first approval, so it is logged once per
		// transition rather than on every reload.
		if prev == nil || prev.state != WorkspaceExceptionsMissing {
			s.logger.Info("workspace exceptions file not found; no workspace exceptions apply", "path", s.path)
		}
		s.observeLoad("missing")
	default:
		s.logger.Error("workspace exceptions file invalid; no workspace exceptions apply until a valid file is loaded", "path", s.path, "error", next.err)
		s.observeLoad("invalid")
	}
}

func (s *WorkspaceExceptionStore) observeLoad(result string) {
	if s.observe != nil {
		s.observe(result)
	}
}

// parseWorkspaceExceptions decodes and validates the whole document. Any
// failure makes the whole file invalid.
func parseWorkspaceExceptions(body []byte, root string) (map[string]*workspaceExceptionEntry, error) {
	if !utf8.Valid(body) {
		return nil, errors.New("file is not valid UTF-8")
	}
	// Case-variant duplicates ("version" and "Version") and exact
	// duplicates are refused before decoding: encoding/json keeps the last
	// one and folds case.
	if err := RejectDuplicateCaseVariantJSONKeys(body); err != nil {
		return nil, err
	}
	top, err := strictJSONObject(body, "document", workspaceTopFields, workspaceTopFields)
	if err != nil {
		return nil, err
	}
	var version int
	if err := strictJSONValue(top["version"], "version", &version); err != nil {
		return nil, err
	}
	if version != WorkspaceExceptionsFileVersion {
		return nil, fmt.Errorf("version %d is not supported (want %d)", version, WorkspaceExceptionsFileVersion)
	}
	var rawEntries []json.RawMessage
	if err := strictJSONValue(top["exceptions"], "exceptions", &rawEntries); err != nil {
		return nil, err
	}
	entries := make(map[string]*workspaceExceptionEntry, len(rawEntries))
	for i, raw := range rawEntries {
		entry, err := parseWorkspaceExceptionEntry(raw, root, fmt.Sprintf("exceptions[%d]", i))
		if err != nil {
			return nil, err
		}
		if _, dup := entries[entry.workspace]; dup {
			return nil, fmt.Errorf("exceptions[%d].workspace %q appears more than once", i, entry.workspace)
		}
		entries[entry.workspace] = entry
	}
	return entries, nil
}

func parseWorkspaceExceptionEntry(raw json.RawMessage, root, at string) (*workspaceExceptionEntry, error) {
	fields, err := strictJSONObject(raw, at, workspaceEntryFields, workspaceEntryFields)
	if err != nil {
		return nil, err
	}
	entry := &workspaceExceptionEntry{}
	if err := strictJSONValue(fields["workspace"], at+".workspace", &entry.workspace); err != nil {
		return nil, err
	}
	if err := checkWorkspaceKey(entry.workspace, root); err != nil {
		return nil, fmt.Errorf("%s.workspace: %w", at, err)
	}
	if entry.grants, err = parseWorkspaceGrants(fields["grants"], at+".grants"); err != nil {
		return nil, err
	}
	if entry.approval, err = parseWorkspaceApproval(fields["approval"], at+".approval"); err != nil {
		return nil, err
	}
	return entry, nil
}

// checkWorkspaceKey applies the load-time rules for a workspace key: absolute,
// clean, no trailing slash, and a direct child of the workspace root.
func checkWorkspaceKey(workspace, root string) error {
	if !path.IsAbs(workspace) || path.Clean(workspace) != workspace {
		return fmt.Errorf("%q is not an absolute, clean path", workspace)
	}
	if path.Dir(workspace) != root || workspace == root {
		return fmt.Errorf("%q is not a direct child of the workspace root %q", workspace, root)
	}
	return nil
}

// Field names of each object in the file. Required lists are subsets.
var (
	workspaceTopFields              = []string{"version", "exceptions"}
	workspaceEntryFields            = []string{"workspace", "grants", "approval"}
	workspaceApprovalFields         = []string{"by", "at", "note"}
	workspaceApprovalRequiredFields = []string{"by", "at"}
	workspaceApprovalByFields       = []string{"issuer", "subject", "name"}
	workspaceApprovalByRequired     = []string{"issuer", "subject"}
)

// workspaceSecurityOptValues is the closed set of fixed securityOpt grants;
// apparmor=<profile> is the one pattern beside them.
var workspaceSecurityOptValues = []string{"seccomp=unconfined", "apparmor=unconfined", "label=disable", "systempaths=unconfined"}

var workspaceGrantFields = []string{
	"privileged", "capAdd", "namespaces", "devices", "deviceCgroupRules", "gpus",
	"extraBindSources", "securityOpt", "runtimes", "sysctls", "restartPolicy",
}

func parseWorkspaceGrants(raw json.RawMessage, at string) (workspaceGrants, error) {
	var g workspaceGrants
	fields, err := strictJSONObject(raw, at, workspaceGrantFields, nil)
	if err != nil {
		return g, err
	}
	if v, ok := fields["privileged"]; ok {
		if err := strictJSONValue(v, at+".privileged", &g.privileged); err != nil {
			return g, err
		}
	}
	if v, ok := fields["gpus"]; ok {
		if err := strictJSONValue(v, at+".gpus", &g.gpus); err != nil {
			return g, err
		}
	}
	lists := []struct {
		key   string
		apply func(string, string) error
	}{
		{"capAdd", g.addCapability},
		{"namespaces", g.addNamespace},
		{"devices", g.addDevice},
		{"deviceCgroupRules", g.addDeviceCgroupRule},
		{"extraBindSources", g.addExtraBindSource},
		{"securityOpt", g.addSecurityOpt},
		{"runtimes", g.addRuntime},
		{"sysctls", g.addSysctl},
		{"restartPolicy", g.addRestartPolicy},
	}
	for _, list := range lists {
		v, ok := fields[list.key]
		if !ok {
			continue
		}
		var values []string
		if err := strictJSONStringList(v, at+"."+list.key, &values); err != nil {
			return g, err
		}
		for i, value := range values {
			if err := list.apply(value, fmt.Sprintf("%s.%s[%d]", at, list.key, i)); err != nil {
				return g, err
			}
		}
	}
	return g, nil
}

func appendUnique(list []string, value string) []string {
	if slices.Contains(list, value) {
		return list
	}
	return append(list, value)
}

func (g *workspaceGrants) addCapability(value, at string) error {
	capability := normalizeCapability(value)
	if capability == "" || !workspaceCapabilityName.MatchString(capability) {
		return fmt.Errorf("%s: %q is not a capability name", at, value)
	}
	if capability == "ALL" {
		g.allCapabilities = true
		return nil
	}
	g.capabilities = appendUnique(g.capabilities, capability)
	return nil
}

func (g *workspaceGrants) addNamespace(value, at string) error {
	switch value {
	case "pid":
		g.hostPID = true
	case "ipc":
		g.hostIPC = true
	case "network":
		g.hostNetwork = true
	case "userns":
		g.hostUserNS = true
	case "cgroupns":
		g.hostCgroupNS = true
	default:
		return fmt.Errorf("%s: %q is not a grantable namespace (one of %s)", at, value, strings.Join(workspaceExceptionNamespaces, ", "))
	}
	return nil
}

// checkGrantHostPath requires an absolute, clean path other than "/". "/" is
// refused because every allowlist this feeds reads it as "everything".
func checkGrantHostPath(value, at string) error {
	if !path.IsAbs(value) || path.Clean(value) != value {
		return fmt.Errorf("%s: %q is not an absolute, clean path", at, value)
	}
	if value == "/" {
		return fmt.Errorf("%s: \"/\" cannot be granted", at)
	}
	return nil
}

func (g *workspaceGrants) addDevice(value, at string) error {
	if err := checkGrantHostPath(value, at); err != nil {
		return err
	}
	g.devices = appendUnique(g.devices, value)
	return nil
}

func (g *workspaceGrants) addDeviceCgroupRule(value, at string) error {
	canonical, ok := canonicalizeDeviceCgroupRule(value)
	if !ok {
		return fmt.Errorf("%s: %q is not a device cgroup rule", at, value)
	}
	g.deviceCgroupRules = appendUnique(g.deviceCgroupRules, canonical)
	return nil
}

func (g *workspaceGrants) addExtraBindSource(value, at string) error {
	if err := checkGrantHostPath(value, at); err != nil {
		return err
	}
	g.extraBindSources = appendUnique(g.extraBindSources, value)
	return nil
}

func (g *workspaceGrants) addSecurityOpt(value, at string) error {
	switch value {
	case "seccomp=unconfined":
		g.seccompUnconfined = true
	case "apparmor=unconfined":
		g.appArmorUnconfined = true
	case "label=disable":
		g.selinuxDisable = true
	case "systempaths=unconfined":
		g.systemPathsUnconfined = true
	default:
		name, ok := strings.CutPrefix(value, "apparmor=")
		if !ok || !workspaceAppArmorName.MatchString(name) {
			return fmt.Errorf("%s: %q is not a grantable security option (seccomp=unconfined, apparmor=unconfined, apparmor=<profile>, label=disable, systempaths=unconfined)", at, value)
		}
		g.appArmorProfiles = appendUnique(g.appArmorProfiles, name)
	}
	return nil
}

func (g *workspaceGrants) addRuntime(value, at string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("%s: %q is not a runtime name", at, value)
	}
	g.runtimes = appendUnique(g.runtimes, value)
	return nil
}

func (g *workspaceGrants) addSysctl(value, at string) error {
	if !workspaceSysctlKey.MatchString(value) {
		return fmt.Errorf("%s: %q is not a sysctl key", at, value)
	}
	g.sysctls = appendUnique(g.sysctls, value)
	return nil
}

func (g *workspaceGrants) addRestartPolicy(value, at string) error {
	if !slices.Contains(workspaceExceptionRestartPolicies, value) {
		return fmt.Errorf("%s: %q is not a grantable restart policy (one of %s)", at, value, strings.Join(workspaceExceptionRestartPolicies, ", "))
	}
	g.restartPolicies = appendUnique(g.restartPolicies, value)
	return nil
}

func parseWorkspaceApproval(raw json.RawMessage, at string) (WorkspaceApproval, error) {
	var a WorkspaceApproval
	fields, err := strictJSONObject(raw, at, workspaceApprovalFields, workspaceApprovalRequiredFields)
	if err != nil {
		return a, err
	}
	by, err := strictJSONObject(fields["by"], at+".by", workspaceApprovalByFields, workspaceApprovalByRequired)
	if err != nil {
		return a, err
	}
	required := []struct {
		raw  json.RawMessage
		name string
		dst  *string
	}{
		{by["issuer"], at + ".by.issuer", &a.Issuer},
		{by["subject"], at + ".by.subject", &a.Subject},
		{fields["at"], at + ".at", &a.At},
	}
	for _, f := range required {
		if err := strictJSONValue(f.raw, f.name, f.dst); err != nil {
			return a, err
		}
		if *f.dst == "" {
			return a, fmt.Errorf("%s must not be empty", f.name)
		}
	}
	if v, ok := by["name"]; ok {
		if err := strictJSONValue(v, at+".by.name", &a.Name); err != nil {
			return a, err
		}
	}
	if v, ok := fields["note"]; ok {
		if err := strictJSONValue(v, at+".note", &a.Note); err != nil {
			return a, err
		}
		if utf8.RuneCountInString(a.Note) > maxWorkspaceApprovalNoteRunes {
			return a, fmt.Errorf("%s.note is longer than %d characters", at, maxWorkspaceApprovalNoteRunes)
		}
	}
	ts, err := time.Parse(time.RFC3339, a.At)
	if err != nil || !strings.HasSuffix(a.At, "Z") || ts.Location() != time.UTC {
		return a, fmt.Errorf("%s.at %q is not an RFC 3339 UTC timestamp", at, a.At)
	}
	return a, nil
}

// strictJSONObject decodes raw as one JSON object whose keys are byte-equal
// to names in allowed. encoding/json matches struct fields without regard to
// case, so the keys are checked here rather than by struct tags: "Privileged"
// is refused, not read as "privileged".
func strictJSONObject(raw json.RawMessage, at string, allowed, required []string) (map[string]json.RawMessage, error) {
	if isJSONNull(raw) {
		return nil, fmt.Errorf("%s must be an object, not null", at)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%s must be an object: %w", at, err)
	}
	for key := range fields {
		if !slices.Contains(allowed, key) {
			return nil, fmt.Errorf("%s has unknown key %q", at, key)
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("%s is missing required key %q", at, key)
		}
	}
	return fields, nil
}

// strictJSONValue decodes a scalar or array value, refusing null, which
// encoding/json would otherwise leave as the zero value.
func strictJSONValue(raw json.RawMessage, at string, dst any) error {
	if isJSONNull(raw) {
		return fmt.Errorf("%s must not be null", at)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("%s has the wrong type: %w", at, err)
	}
	return nil
}

// strictJSONStringList decodes an array of strings, refusing null elements.
func strictJSONStringList(raw json.RawMessage, at string, dst *[]string) error {
	var elems []json.RawMessage
	if err := strictJSONValue(raw, at, &elems); err != nil {
		return err
	}
	out := make([]string, 0, len(elems))
	for i, elem := range elems {
		var s string
		if err := strictJSONValue(elem, fmt.Sprintf("%s[%d]", at, i), &s); err != nil {
			return err
		}
		out = append(out, s)
	}
	*dst = out
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

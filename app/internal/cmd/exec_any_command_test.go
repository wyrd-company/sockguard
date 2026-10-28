package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// execAnyCommandDaemon is a mock Docker daemon on a unix socket. It records
// every exec create and exec start that reaches it, so a test can tell a
// forwarded request from one the proxy denied. Exec inspect answers from
// stored, which stands in for the metadata Docker keeps for each exec ID.
type execAnyCommandDaemon struct {
	mu      sync.Mutex
	creates []string
	starts  []string
	stored  map[string]string
}

func (d *execAnyCommandDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1.45/") {
		path = strings.TrimPrefix(path, "/v1.45")
	}
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/exec"):
		body, _ := io.ReadAll(r.Body)
		d.creates = append(d.creates, path+" "+string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"Id":"created"}`)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		owner, ok := execAnyCommandOwners[id]
		if !ok {
			http.Error(w, "no such container", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"Id":%q,"Config":{"Labels":{"com.example.owner":%q}}}`, id, owner)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/json"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/exec/"), "/json")
		meta, ok := d.stored[id]
		if !ok {
			http.Error(w, "no such exec", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, meta)
	case r.Method == http.MethodPost && strings.HasPrefix(path, "/exec/") && strings.HasSuffix(path, "/start"):
		d.starts = append(d.starts, path)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "unexpected upstream request", http.StatusNotFound)
	}
}

func (d *execAnyCommandDaemon) counts() (creates, starts int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.creates), len(d.starts)
}

// execInspectJSON renders a GET /exec/{id}/json answer for an exec in
// containerID.
func execInspectJSON(containerID, user string, privileged bool, entrypoint string, args ...string) string {
	if args == nil {
		args = []string{}
	}
	argJSON, _ := json.Marshal(args)
	return fmt.Sprintf(`{"ContainerID":%q,"ProcessConfig":{"entrypoint":%q,"arguments":%s,"privileged":%t,"user":%q}}`, containerID, entrypoint, argJSON, privileged, user)
}

// execAnyCommandStored is the exec metadata every chain test can start.
// Each ID names the case it stands for.
var execAnyCommandStored = map[string]string{
	"plain":      execInspectJSON("workspace", "vscode", false, "/bin/sh", "-c", "make setup"),
	"root-empty": execInspectJSON("workspace", "", false, "/bin/sh"),
	"root-name":  execInspectJSON("workspace", "root", false, "/bin/sh"),
	"root-uid":   execInspectJSON("workspace", "0:0", false, "/bin/sh"),
	"privileged": execInspectJSON("workspace", "vscode", true, "/bin/sh"),
	"foreign":    execInspectJSON("other", "vscode", false, "/bin/sh", "-c", "make setup"),
}

// execAnyCommandOwners holds the owner label of each mock container.
var execAnyCommandOwners = map[string]string{
	"workspace": "owner-a",
	"other":     "owner-b",
}

// newExecAnyCommandChain loads requestBodyYAML (the indented body of
// request_body) through config.LoadBytes, builds the production serve
// handler chain against a mock daemon, and returns both. extraYAML is
// appended at the top level.
func newExecAnyCommandChain(t *testing.T, requestBodyYAML, extraYAML string) (http.Handler, *execAnyCommandDaemon) {
	t.Helper()
	socketPath := shortSocketPath(t, "exec-any")
	_ = os.Remove(socketPath)
	daemon := &execAnyCommandDaemon{stored: execAnyCommandStored}
	startUnixHTTPUpstream(t, socketPath, daemon)

	yaml := fmt.Sprintf(`upstream:
  socket: %s
health:
  enabled: false
log:
  access_log: false
response:
  deny_verbosity: verbose
rules:
  - match: { method: POST, path: "/containers/*/exec" }
    action: allow
  - match: { method: POST, path: "/exec/*/start" }
    action: allow
  - match: { method: "*", path: "/**" }
    action: deny
request_body:
  exec:
%s
%s`, socketPath, requestBodyYAML, extraYAML)
	cfg, err := config.LoadBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadBytes: %v\n%s", err, yaml)
	}
	rules, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	return buildServeHandler(t, cfg, newDiscardLogger(), nil, rules, newServeTestDeps()), daemon
}

func serveExecCreate(handler http.Handler, remoteAddr, body string) *httptest.ResponseRecorder {
	return serveExecCreateIn(handler, remoteAddr, "workspace", body)
}

func serveExecCreateIn(handler http.Handler, remoteAddr, containerID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1.45/containers/"+containerID+"/exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func serveExecStart(handler http.Handler, remoteAddr, id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1.45/exec/"+id+"/start", strings.NewReader(`{"Detach":true}`))
	req.Header.Set("Content-Type", "application/json")
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// assertExecDenied checks a 403 whose body carries wantReason and that the
// daemon saw no new create or start.
func assertExecDenied(t *testing.T, rec *httptest.ResponseRecorder, daemon *execAnyCommandDaemon, beforeCreates, beforeStarts int, wantReason string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), wantReason) {
		t.Fatalf("body = %s, want reason containing %q", rec.Body.String(), wantReason)
	}
	creates, starts := daemon.counts()
	if creates != beforeCreates || starts != beforeStarts {
		t.Fatalf("daemon saw creates=%d starts=%d, want %d/%d (request must not be forwarded)", creates, starts, beforeCreates, beforeStarts)
	}
}

const (
	execAnyCommandOn  = "    allow_any_command: true"
	execAnyCommandOff = "    allow_any_command: false"
	plainExecBody     = `{"User":"vscode","Cmd":["/bin/sh","-c","make setup"]}`
)

// TestExecAnyCommandDefaultOffDeniesEmptyAllowlist pins the default: with
// allow_any_command absent or false and no allowed_commands, exec create and
// exec start stay denied by the argv gate and nothing reaches the daemon.
func TestExecAnyCommandDefaultOffDeniesEmptyAllowlist(t *testing.T) {
	for name, body := range map[string]string{
		"absent":         "    allow_root_user: false",
		"explicit false": execAnyCommandOff,
	} {
		t.Run(name, func(t *testing.T) {
			handler, daemon := newExecAnyCommandChain(t, body, "")
			assertExecDenied(t, serveExecCreate(handler, "", plainExecBody), daemon, 0, 0, "no commands are allowlisted")
			assertExecDenied(t, serveExecStart(handler, "", "plain"), daemon, 0, 0, "no commands are allowlisted")
		})
	}
}

// TestExecAnyCommandAdmitsAnyArgvOnCreate: with the setting on and an empty
// allowlist, exec create with any argv and a non-root user is forwarded.
func TestExecAnyCommandAdmitsAnyArgvOnCreate(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn, "")
	for i, body := range []string{
		plainExecBody,
		`{"User":"1000:1000","Cmd":["git","config","--global","core.editor","vi"]}`,
		`{"User":"vscode","Cmd":"npm ci --ignore-scripts"}`,
	} {
		rec := serveExecCreate(handler, "", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: status = %d, want 201; body: %s", i, rec.Code, rec.Body.String())
		}
		if creates, _ := daemon.counts(); creates != i+1 {
			t.Fatalf("create %d: daemon creates = %d, want %d", i, creates, i+1)
		}
	}
}

// TestExecAnyCommandAdmitsAnyArgvOnStart: with the setting on, exec start
// re-reads the stored exec metadata and forwards a non-root, unprivileged
// exec whatever its argv.
func TestExecAnyCommandAdmitsAnyArgvOnStart(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn, "")
	rec := serveExecStart(handler, "", "plain")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	if _, starts := daemon.counts(); starts != 1 {
		t.Fatalf("daemon starts = %d, want 1", starts)
	}
}

// TestExecAnyCommandStillDeniesRootUser: the setting does not imply
// allow_root_user. Every root form the exec check recognizes is denied on
// create, and a stored root exec is denied at start.
func TestExecAnyCommandStillDeniesRootUser(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn, "")
	for _, user := range []string{"", " ", "0", "00", "0:0", "0:1000", "root", "ROOT", " root ", "root:root"} {
		body := fmt.Sprintf(`{"User":%q,"Cmd":["id"]}`, user)
		assertExecDenied(t, serveExecCreate(handler, "", body), daemon, 0, 0, "root exec user is not allowed")
	}
	// A body with no User field at all runs as the container's user.
	assertExecDenied(t, serveExecCreate(handler, "", `{"Cmd":["id"]}`), daemon, 0, 0, "root exec user is not allowed")
	for _, id := range []string{"root-empty", "root-name", "root-uid"} {
		assertExecDenied(t, serveExecStart(handler, "", id), daemon, 0, 0, "root exec user is not allowed")
	}
}

// TestExecAnyCommandStillDeniesPrivileged: the setting does not imply
// allow_privileged, on create or at start.
func TestExecAnyCommandStillDeniesPrivileged(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn+"\n    allow_root_user: true", "")
	assertExecDenied(t, serveExecCreate(handler, "", `{"User":"vscode","Privileged":true,"Cmd":["id"]}`), daemon, 0, 0, "privileged exec is not allowed")
	assertExecDenied(t, serveExecStart(handler, "", "privileged"), daemon, 0, 0, "privileged exec is not allowed")
}

// TestExecAnyCommandStillAppliesEnvChecks: denied_env_vars,
// allowed_env_vars and allowed_env_values still apply with the setting on.
func TestExecAnyCommandStillAppliesEnvChecks(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn+`
    denied_env_vars: ["LD_PRELOAD"]
    allowed_env_vars: ["LD_PRELOAD", "HOME", "MODE"]
    allowed_env_values: ["MODE=safe"]`, "")
	assertExecDenied(t, serveExecCreate(handler, "", `{"User":"vscode","Cmd":["id"],"Env":["LD_PRELOAD=/x.so"]}`), daemon, 0, 0, "is denylisted")
	assertExecDenied(t, serveExecCreate(handler, "", `{"User":"vscode","Cmd":["id"],"Env":["PATH=/x"]}`), daemon, 0, 0, "is not allowlisted")
	assertExecDenied(t, serveExecCreate(handler, "", `{"User":"vscode","Cmd":["id"],"Env":["MODE=unsafe"]}`), daemon, 0, 0, "disallowed value")
	rec := serveExecCreate(handler, "", `{"User":"vscode","Cmd":["id"],"Env":["HOME=/home/vscode","MODE=safe"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("allowed env: status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

// TestExecAnyCommandDoesNotWidenAllowlist: a non-empty allowed_commands
// still applies when the setting is on. The setting lifts only the gate an
// empty allowlist sets.
func TestExecAnyCommandDoesNotWidenAllowlist(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn+`
    allowed_commands:
      - ["echo", "*"]`, "")
	assertExecDenied(t, serveExecCreate(handler, "", `{"User":"vscode","Cmd":["id"]}`), daemon, 0, 0, "is not allowlisted")
	assertExecDenied(t, serveExecStart(handler, "", "plain"), daemon, 0, 0, "is not allowlisted")
	rec := serveExecCreate(handler, "", `{"User":"vscode","Cmd":["echo","hi"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("allowlisted command: status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

// TestExecAnyCommandIsScopedToItsClientProfile: a profile that sets
// allow_any_command admits exec for its own clients only. The default policy,
// which leaves it off, still denies.
func TestExecAnyCommandIsScopedToItsClientProfile(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, "    allow_root_user: false", `clients:
  source_ip_profiles:
    - profile: workspaces
      cidrs: ["192.0.2.0/24"]
  profiles:
    - name: workspaces
      rules:
        - match: { method: POST, path: "/containers/*/exec" }
          action: allow
        - match: { method: POST, path: "/exec/*/start" }
          action: allow
        - match: { method: "*", path: "/**" }
          action: deny
      request_body:
        exec:
          allow_any_command: true
`)
	const assigned, unassigned = "192.0.2.10:4000", "198.51.100.10:4000"
	if rec := serveExecCreate(handler, assigned, plainExecBody); rec.Code != http.StatusCreated {
		t.Fatalf("assigned create: status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	if rec := serveExecStart(handler, assigned, "plain"); rec.Code != http.StatusOK {
		t.Fatalf("assigned start: status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	assertExecDenied(t, serveExecCreate(handler, unassigned, plainExecBody), daemon, 1, 1, "no commands are allowlisted")
	assertExecDenied(t, serveExecStart(handler, unassigned, "plain"), daemon, 1, 1, "no commands are allowlisted")
	// The profile's own root and privileged checks still apply. A profile
	// policy answers with the minimal deny body, so only the status and the
	// absence of a forward are checked here.
	assertExecDenied(t, serveExecCreate(handler, assigned, `{"User":"root","Cmd":["id"]}`), daemon, 1, 1, "")
	assertExecDenied(t, serveExecStart(handler, assigned, "privileged"), daemon, 1, 1, "")
}

// TestBlindWritesDoNotEnableExecAnyCommand: the global
// insecure_allow_body_blind_writes does not set allow_any_command in config
// or in the runtime exec policy of the default policy or any profile.
func TestBlindWritesDoNotEnableExecAnyCommand(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(`insecure_allow_body_blind_writes: true
clients:
  profiles:
    - name: other
      rules:
        - match: { method: "*", path: "/**" }
          action: deny
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.RequestBody.Exec.AllowAnyCommand {
		t.Fatal("request_body.exec.allow_any_command = true, want false when only insecure_allow_body_blind_writes is set")
	}
	if cfg.Clients.Profiles[0].RequestBody.Exec.AllowAnyCommand {
		t.Fatal("profile request_body.exec.allow_any_command = true, want false")
	}
	for name, rb := range map[string]config.RequestBodyConfig{
		"default": cfg.RequestBody,
		"profile": cfg.Clients.Profiles[0].RequestBody,
	} {
		policy := attachRuntimeInspectors(cfg, nil, rb.ToFilterOptions())
		if policy.Exec.AllowAnyCommand {
			t.Fatalf("%s runtime policy Exec.AllowAnyCommand = true, want false", name)
		}
		if !policy.Exec.AllowBlindWrites {
			t.Fatalf("%s runtime policy Exec.AllowBlindWrites = false, want true (control)", name)
		}
	}
}

// TestExecAnyCommandLeavesBlindWriteSemanticsAlone: with allow_any_command on
// and the global acknowledgment off, the runtime policy acknowledges no blind
// write, and startup validation still refuses every other uninspected
// body-sensitive endpoint while accepting the exec ones.
func TestExecAnyCommandLeavesBlindWriteSemanticsAlone(t *testing.T) {
	cfg := config.Defaults()
	cfg.RequestBody.Exec.AllowAnyCommand = true

	policy := attachRuntimeInspectors(&cfg, nil, cfg.RequestBody.ToFilterOptions())
	if policy.Exec.AllowBlindWrites || policy.Build.AllowBlindWrites || policy.ImageLoad.AllowBlindWrites || policy.ContainerUpdate.AllowBlindWrites {
		t.Fatalf("runtime policy acknowledges blind writes: exec=%t build=%t image_load=%t container_update=%t",
			policy.Exec.AllowBlindWrites, policy.Build.AllowBlindWrites, policy.ImageLoad.AllowBlindWrites, policy.ContainerUpdate.AllowBlindWrites)
	}

	cfg.Rules = []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/swarm/join"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	compiled, err := compileRuleConfigsForTest(cfg.Rules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	err = validateBodyBlindWriteRules(&cfg, compiled)
	if err == nil {
		t.Fatal("validateBodyBlindWriteRules = nil, want /swarm/join refused")
	}
	if !strings.Contains(err.Error(), "/swarm/join") {
		t.Fatalf("error = %v, want it to name /swarm/join", err)
	}
	if strings.Contains(err.Error(), "exec") {
		t.Fatalf("error = %v, want no exec endpoint named", err)
	}
}

// TestExecAnyCommandSatisfiesStartupExecValidation: broad exec allow rules
// load without the global acknowledgment when allow_any_command is on, at
// the top level and in a profile, and are refused when it is off.
func TestExecAnyCommandSatisfiesStartupExecValidation(t *testing.T) {
	execRules := []config.RuleConfig{
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/containers/*/exec"}, Action: "allow"},
		{Match: config.MatchConfig{Method: http.MethodPost, Path: "/exec/*/start"}, Action: "allow"},
		{Match: config.MatchConfig{Method: "*", Path: "/**"}, Action: "deny"},
	}
	compiled, err := compileRuleConfigsForTest(execRules)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	for _, on := range []bool{false, true} {
		cfg := config.Defaults()
		cfg.Rules = execRules
		cfg.RequestBody.Exec.AllowAnyCommand = on
		err := validateBodyBlindWriteRules(&cfg, compiled)
		if on && err != nil {
			t.Fatalf("top level, allow_any_command on: err = %v, want nil", err)
		}
		if !on && (err == nil || !strings.Contains(err.Error(), "/exec/")) {
			t.Fatalf("top level, allow_any_command off: err = %v, want exec refused", err)
		}

		profile := config.RequestBodyConfig{Exec: config.ExecRequestBodyConfig{AllowAnyCommand: on}}
		err = validateBodyBlindWriteRulesForPolicy("workspaces", false, profile, execRules, compiled)
		if on && err != nil {
			t.Fatalf("profile, allow_any_command on: err = %v, want nil", err)
		}
		if !on && (err == nil || !strings.Contains(err.Error(), `client profile "workspaces"`)) {
			t.Fatalf("profile, allow_any_command off: err = %v, want profile exec refused", err)
		}
	}
}

// TestExecAnyCommandKeepsOwnerLabelIsolation: with ownership on, the setting
// admits exec only in containers the client owns. Exec create in, and exec
// start of an exec attached to, another owner's container are denied and not
// forwarded.
func TestExecAnyCommandKeepsOwnerLabelIsolation(t *testing.T) {
	handler, daemon := newExecAnyCommandChain(t, execAnyCommandOn, `ownership:
  owner: owner-a
  label_key: com.example.owner
`)
	if rec := serveExecCreate(handler, "", plainExecBody); rec.Code != http.StatusCreated {
		t.Fatalf("owned create: status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	if rec := serveExecStart(handler, "", "plain"); rec.Code != http.StatusOK {
		t.Fatalf("owned start: status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	assertExecDenied(t, serveExecCreateIn(handler, "", "other", plainExecBody), daemon, 1, 1, "owner")
	assertExecDenied(t, serveExecStart(handler, "", "foreign"), daemon, 1, 1, "owner")
}

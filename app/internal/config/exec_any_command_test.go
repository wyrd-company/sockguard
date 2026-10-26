package config

import "testing"

// TestExecAllowAnyCommandDefaultsOff pins the default: off in Defaults() and
// in a load with no input.
func TestExecAllowAnyCommandDefaultsOff(t *testing.T) {
	if Defaults().RequestBody.Exec.AllowAnyCommand {
		t.Fatal("Defaults().RequestBody.Exec.AllowAnyCommand = true, want false")
	}
	cfg, err := LoadBytes(nil)
	if err != nil {
		t.Fatalf("LoadBytes(nil) = %v", err)
	}
	if cfg.RequestBody.Exec.AllowAnyCommand {
		t.Fatal("LoadBytes(nil).RequestBody.Exec.AllowAnyCommand = true, want false")
	}
}

// TestExecAllowAnyCommandLoadsFromYAML reads the key at the top level and in
// a client profile, and maps it into the filter options.
func TestExecAllowAnyCommandLoadsFromYAML(t *testing.T) {
	cfg, err := LoadBytes([]byte(`request_body:
  exec:
    allow_any_command: true
clients:
  profiles:
    - name: on
      request_body:
        exec:
          allow_any_command: true
    - name: off
      request_body:
        exec:
          allow_root_user: false
`))
	if err != nil {
		t.Fatalf("LoadBytes = %v", err)
	}
	if !cfg.RequestBody.Exec.AllowAnyCommand {
		t.Fatal("top-level allow_any_command = false, want true")
	}
	if !cfg.RequestBody.ToFilterOptions().Exec.AllowAnyCommand {
		t.Fatal("top-level ToFilterOptions().Exec.AllowAnyCommand = false, want true")
	}
	if !cfg.Clients.Profiles[0].RequestBody.ToFilterOptions().Exec.AllowAnyCommand {
		t.Fatal(`profile "on" Exec.AllowAnyCommand = false, want true`)
	}
	if cfg.Clients.Profiles[1].RequestBody.ToFilterOptions().Exec.AllowAnyCommand {
		t.Fatal(`profile "off" Exec.AllowAnyCommand = true, want false`)
	}
}

// TestExecAllowAnyCommandEnvOverride reads the documented env var.
func TestExecAllowAnyCommandEnvOverride(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_EXEC_ALLOW_ANY_COMMAND", "true")
	cfg, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load = %v", err)
	}
	if !cfg.RequestBody.Exec.AllowAnyCommand {
		t.Fatal("allow_any_command = false, want true from SOCKGUARD_REQUEST_BODY_EXEC_ALLOW_ANY_COMMAND")
	}
}

// TestBlindWritesDoNotSetExecAllowAnyCommand: the global acknowledgment does
// not turn the exec setting on.
func TestBlindWritesDoNotSetExecAllowAnyCommand(t *testing.T) {
	cfg, err := LoadBytes([]byte("insecure_allow_body_blind_writes: true\n"))
	if err != nil {
		t.Fatalf("LoadBytes = %v", err)
	}
	if !cfg.InsecureAllowBodyBlindWrites {
		t.Fatal("insecure_allow_body_blind_writes = false, want true (control)")
	}
	if cfg.RequestBody.Exec.AllowAnyCommand || cfg.RequestBody.ToFilterOptions().Exec.AllowAnyCommand {
		t.Fatal("allow_any_command = true, want false when only insecure_allow_body_blind_writes is set")
	}
}

func TestExecArgvGateConfigured(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ExecRequestBodyConfig
		want bool
	}{
		{"empty", ExecRequestBodyConfig{}, false},
		{"root and privileged only", ExecRequestBodyConfig{AllowRootUser: true, AllowPrivileged: true}, false},
		{"allowlist", ExecRequestBodyConfig{AllowedCommands: [][]string{{"id"}}}, true},
		{"any command", ExecRequestBodyConfig{AllowAnyCommand: true}, true},
		{"both", ExecRequestBodyConfig{AllowAnyCommand: true, AllowedCommands: [][]string{{"id"}}}, true},
	} {
		if got := tc.cfg.ArgvGateConfigured(); got != tc.want {
			t.Errorf("%s: ArgvGateConfigured() = %t, want %t", tc.name, got, tc.want)
		}
	}
}

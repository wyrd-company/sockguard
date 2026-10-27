package config

import (
	"strings"
	"testing"
)

func TestWorkspaceExceptionsConfigLoadsFromYAMLAndEnv(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
workspace_exceptions:
  file: /srv/policy/workspace-exceptions.json
  workspace_root: /srv/workspaces
request_body:
  container_create:
    apply_workspace_exceptions: true
    require_no_restart_policy: true
clients:
  profiles:
    - name: sample
      rules:
        - match: { method: GET, path: "/_ping" }
          action: allow
      request_body:
        container_create:
          apply_workspace_exceptions: true
          require_no_restart_policy: true
`))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if cfg.WorkspaceExceptions.File != "/srv/policy/workspace-exceptions.json" || cfg.WorkspaceExceptions.WorkspaceRoot != "/srv/workspaces" {
		t.Fatalf("workspace_exceptions = %+v", cfg.WorkspaceExceptions)
	}
	for name, cc := range map[string]ContainerCreateRequestBodyConfig{
		"request_body":     cfg.RequestBody.ContainerCreate,
		"clients.profiles": cfg.Clients.Profiles[0].RequestBody.ContainerCreate,
	} {
		opts := cc.ToFilterOptions()
		if !cc.ApplyWorkspaceExceptions || !cc.RequireNoRestartPolicy || !opts.ApplyWorkspaceExceptions || !opts.RequireNoRestartPolicy {
			t.Fatalf("%s: container_create fields not loaded or mapped: %+v", name, cc)
		}
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	t.Setenv("SOCKGUARD_WORKSPACE_EXCEPTIONS_FILE", "/srv/env/workspace-exceptions.json")
	t.Setenv("SOCKGUARD_WORKSPACE_EXCEPTIONS_WORKSPACE_ROOT", "/srv/env-workspaces")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_APPLY_WORKSPACE_EXCEPTIONS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_REQUIRE_NO_RESTART_POLICY", "true")
	env, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if env.WorkspaceExceptions.File != "/srv/env/workspace-exceptions.json" || env.WorkspaceExceptions.WorkspaceRoot != "/srv/env-workspaces" ||
		!env.RequestBody.ContainerCreate.ApplyWorkspaceExceptions || !env.RequestBody.ContainerCreate.RequireNoRestartPolicy {
		t.Fatalf("env not honored: %+v %+v", env.WorkspaceExceptions, env.RequestBody.ContainerCreate)
	}
}

func TestWorkspaceExceptionsConfigDefaultsOff(t *testing.T) {
	cfg := Defaults()
	if cfg.WorkspaceExceptions.Enabled() || cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions || cfg.RequestBody.ContainerCreate.RequireNoRestartPolicy {
		t.Fatalf("defaults must leave the feature off: %+v", cfg.WorkspaceExceptions)
	}
}

func TestValidateWorkspaceExceptions(t *testing.T) {
	valid := func(c *Config) {
		c.WorkspaceExceptions = WorkspaceExceptionsConfig{File: "/srv/policy/x.json", WorkspaceRoot: "/srv/workspaces"}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"file relative", func(c *Config) { valid(c); c.WorkspaceExceptions.File = "policy/x.json" }, "workspace_exceptions.file must be an absolute, clean path"},
		{"file not clean", func(c *Config) { valid(c); c.WorkspaceExceptions.File = "/srv/policy/../x.json" }, "workspace_exceptions.file must be an absolute, clean path"},
		{"root missing", func(c *Config) { valid(c); c.WorkspaceExceptions.WorkspaceRoot = "" }, "workspace_exceptions.workspace_root is required when workspace_exceptions.file is set"},
		{"root slash", func(c *Config) { valid(c); c.WorkspaceExceptions.WorkspaceRoot = "/" }, "workspace_exceptions.workspace_root must be an absolute, clean path other than /"},
		{"root trailing slash", func(c *Config) { valid(c); c.WorkspaceExceptions.WorkspaceRoot = "/srv/workspaces/" }, "workspace_exceptions.workspace_root must be an absolute, clean path"},
		{"root without file", func(c *Config) { c.WorkspaceExceptions.WorkspaceRoot = "/srv/workspaces" }, "workspace_exceptions.workspace_root requires workspace_exceptions.file"},
		{"apply without file", func(c *Config) { c.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true }, "request_body.container_create.apply_workspace_exceptions requires workspace_exceptions.file"},
		{"profile apply without file", func(c *Config) {
			c.Clients.Profiles = []ClientProfileConfig{{Name: "sample", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
				RequestBody: RequestBodyConfig{ContainerCreate: ContainerCreateRequestBodyConfig{ApplyWorkspaceExceptions: true}}}}
		}, "clients.profiles[0].request_body.container_create.apply_workspace_exceptions requires workspace_exceptions.file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			tc.mutate(&cfg)
			err := Validate(&cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate = %v; want %q", err, tc.want)
			}
		})
	}
	cfg := Defaults()
	valid(&cfg)
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("valid block: %v", err)
	}
	// require_no_restart_policy needs no file.
	cfg = Defaults()
	cfg.RequestBody.ContainerCreate.RequireNoRestartPolicy = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("require_no_restart_policy alone: %v", err)
	}
}

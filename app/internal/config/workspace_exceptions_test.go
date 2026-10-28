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
  per_workspace_roots: [/srv/workspaces, /srv/workspace-sockets]
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
	if cfg.WorkspaceExceptions.File != "/srv/policy/workspace-exceptions.json" || cfg.WorkspaceExceptions.WorkspaceRoot != "/srv/workspaces" ||
		len(cfg.WorkspaceExceptions.PerWorkspaceRoots) != 2 || cfg.WorkspaceExceptions.PerWorkspaceRoots[1] != "/srv/workspace-sockets" {
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
	t.Setenv("SOCKGUARD_WORKSPACE_EXCEPTIONS_PER_WORKSPACE_ROOTS", "/srv/env-workspaces,/srv/env-sockets")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_APPLY_WORKSPACE_EXCEPTIONS", "true")
	t.Setenv("SOCKGUARD_REQUEST_BODY_CONTAINER_CREATE_REQUIRE_NO_RESTART_POLICY", "true")
	env, err := Load("/nonexistent-so-defaults-and-env-only.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if env.WorkspaceExceptions.File != "/srv/env/workspace-exceptions.json" || env.WorkspaceExceptions.WorkspaceRoot != "/srv/env-workspaces" ||
		!env.RequestBody.ContainerCreate.ApplyWorkspaceExceptions || !env.RequestBody.ContainerCreate.RequireNoRestartPolicy ||
		len(env.WorkspaceExceptions.PerWorkspaceRoots) != 2 || env.WorkspaceExceptions.PerWorkspaceRoots[1] != "/srv/env-sockets" {
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
		{"roots without file", func(c *Config) { c.WorkspaceExceptions.PerWorkspaceRoots = []string{"/srv/workspaces"} }, "workspace_exceptions.per_workspace_roots requires workspace_exceptions.file"},
		{"roots without workspace root", func(c *Config) {
			valid(c)
			c.WorkspaceExceptions.PerWorkspaceRoots = []string{"/srv/workspace-sockets"}
		}, "workspace_exceptions.per_workspace_roots must include workspace_exceptions.workspace_root"},
		{"root not clean", func(c *Config) {
			valid(c)
			c.WorkspaceExceptions.PerWorkspaceRoots = []string{"/srv/workspaces", "/srv/sockets/"}
		}, "workspace_exceptions.per_workspace_roots[1] must be an absolute, clean path other than /"},
		{"nested roots", func(c *Config) {
			valid(c)
			c.WorkspaceExceptions.PerWorkspaceRoots = []string{"/srv/workspaces", "/srv/workspaces/sockets"}
		}, `workspace_exceptions.per_workspace_roots[1] "/srv/workspaces/sockets" repeats or is inside "/srv/workspaces"`},
		{"allowlist entry above a root", func(c *Config) {
			valid(c)
			c.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
			c.RequestBody.ContainerCreate.AllowedBindMounts = []string{"/srv"}
		}, `request_body.container_create.allowed_bind_mounts[0] "/srv" contains the per-workspace root "/srv/workspaces"`},
		{"allowlist slash in a profile", func(c *Config) {
			valid(c)
			c.Clients.Profiles = []ClientProfileConfig{{Name: "sample", Rules: []RuleConfig{{Match: MatchConfig{Method: "GET", Path: "/_ping"}, Action: "allow"}},
				RequestBody: RequestBodyConfig{ContainerCreate: ContainerCreateRequestBodyConfig{ApplyWorkspaceExceptions: true, AllowedBindMounts: []string{"/"}}}}}
		}, `clients.profiles[0].request_body.container_create.allowed_bind_mounts[0] "/" contains the per-workspace root`},
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
	// An entry above a root is fine in a block that does not opt in, and
	// the root itself and folders beside it are fine in one that does.
	cfg = Defaults()
	valid(&cfg)
	cfg.WorkspaceExceptions.PerWorkspaceRoots = []string{"/srv/workspaces", "/srv/workspace-sockets"}
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"/srv"}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("entry above a root without apply: %v", err)
	}
	cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions = true
	cfg.RequestBody.ContainerCreate.AllowedBindMounts = []string{"/srv/workspaces", "/srv/workspace-sockets", "/srv/shared-input"}
	if err := Validate(&cfg); err != nil {
		t.Fatalf("roots and a sibling folder: %v", err)
	}
	if got := cfg.WorkspaceExceptions.EffectivePerWorkspaceRoots(); len(got) != 2 {
		t.Fatalf("effective roots %v", got)
	}
	if got := (WorkspaceExceptionsConfig{WorkspaceRoot: "/srv/workspaces"}).EffectivePerWorkspaceRoots(); len(got) != 1 || got[0] != "/srv/workspaces" {
		t.Fatalf("default effective roots %v", got)
	}
	// require_no_restart_policy needs no file.
	cfg = Defaults()
	cfg.RequestBody.ContainerCreate.RequireNoRestartPolicy = true
	if err := Validate(&cfg); err != nil {
		t.Fatalf("require_no_restart_policy alone: %v", err)
	}
}

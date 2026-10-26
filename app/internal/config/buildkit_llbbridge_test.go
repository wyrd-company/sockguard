package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// llbBridgeProfilesYAML has profile "builder" with the passthrough on and
// profile "reader" without it. topLevel is inserted under request_body.
func llbBridgeProfilesYAML(topLevel, builderSolveAllow string) []byte {
	return []byte(`
request_body:
  buildkit:
` + topLevel + `
clients:
  default_profile: reader
  profiles:
    - name: builder
      request_body:
        buildkit:
          control:
            solve:
              allow: ` + builderSolveAllow + `
          llb_bridge:
            allow_uninspected_passthrough: true
      rules:
        - match: { method: POST, path: /grpc }
          action: allow
    - name: reader
      request_body:
        buildkit:
          control:
            solve:
              allow: true
      rules:
        - match: { method: POST, path: /grpc }
          action: allow
`)
}

func TestBuildkitLLBBridgeDefaultsOff(t *testing.T) {
	cfg := Defaults()
	if cfg.RequestBody.Buildkit.LLBBridge.AllowUninspectedPassthrough {
		t.Fatal("Defaults() turns the LLBBridge passthrough on")
	}
	loaded, err := LoadBytes(nil)
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if loaded.RequestBody.Buildkit.ToPolicy(loaded.RequestBody.Build).LLBBridge.AllowUninspectedPassthrough {
		t.Fatal("an empty config turns the LLBBridge passthrough on")
	}
}

// Profile "builder" gets the passthrough; profile "reader" and the
// top-level policy do not.
func TestBuildkitLLBBridgeIsPerProfile(t *testing.T) {
	cfg, err := LoadBytes(llbBridgeProfilesYAML("", "true"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := map[string]bool{}
	for _, profile := range cfg.Clients.Profiles {
		got[profile.Name] = profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).LLBBridge.AllowUninspectedPassthrough
	}
	if !got["builder"] {
		t.Error("profile builder: passthrough = false, want true")
	}
	if got["reader"] {
		t.Error("profile reader: passthrough = true, want false")
	}
	if cfg.RequestBody.Buildkit.ToPolicy(cfg.RequestBody.Build).LLBBridge.AllowUninspectedPassthrough {
		t.Error("top-level policy: passthrough = true, want false")
	}
}

func TestBuildkitLLBBridgeRejectedAtTopLevel(t *testing.T) {
	cfg, err := LoadBytes(llbBridgeProfilesYAML("    llb_bridge:\n      allow_uninspected_passthrough: true", "true"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	err = Validate(cfg)
	if err == nil {
		t.Fatal("Validate() = nil, want a top-level llb_bridge error")
	}
	want := "request_body.buildkit.llb_bridge.allow_uninspected_passthrough is only valid in clients.profiles[].request_body"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() = %v, want it to contain %q", err, want)
	}
}

func TestBuildkitLLBBridgeRejectedAtTopLevelFromEnv(t *testing.T) {
	t.Setenv("SOCKGUARD_REQUEST_BODY_BUILDKIT_LLB_BRIDGE_ALLOW_UNINSPECTED_PASSTHROUGH", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RequestBody.Buildkit.LLBBridge.AllowUninspectedPassthrough {
		t.Fatal("env var did not reach request_body.buildkit.llb_bridge.allow_uninspected_passthrough")
	}
	err = Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "request_body.buildkit.llb_bridge.allow_uninspected_passthrough is only valid in clients.profiles[].request_body") {
		t.Fatalf("Validate() = %v, want the top-level llb_bridge error", err)
	}
}

func TestBuildkitLLBBridgeRequiresSolveAllow(t *testing.T) {
	cfg, err := LoadBytes(llbBridgeProfilesYAML("", "false"))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	err = Validate(cfg)
	if err == nil {
		t.Fatal("Validate() = nil, want a solve.allow requirement error")
	}
	want := "clients.profiles[0].request_body.buildkit.llb_bridge.allow_uninspected_passthrough requires clients.profiles[0].request_body.buildkit.control.solve.allow: true"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() = %v, want it to contain %q", err, want)
	}
}

// The YAML example on the fork's docs page loads, validates, and turns the
// passthrough on for its profile.
func TestBuildkitLLBBridgeDocsExampleValidates(t *testing.T) {
	page, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "content", "docs", "buildkit-llb-bridge.mdx"))
	if err != nil {
		t.Fatalf("read docs page: %v", err)
	}
	_, rest, ok := strings.Cut(string(page), "```yaml\n")
	if !ok {
		t.Fatal("docs page has no yaml block")
	}
	example, _, ok := strings.Cut(rest, "```")
	if !ok {
		t.Fatal("docs page yaml block is not closed")
	}
	cfg, err := LoadBytes([]byte(example))
	if err != nil {
		t.Fatalf("LoadBytes(docs example): %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate(docs example): %v", err)
	}
	if len(cfg.Clients.Profiles) != 1 {
		t.Fatalf("docs example profiles = %d, want 1", len(cfg.Clients.Profiles))
	}
	profile := cfg.Clients.Profiles[0]
	if !profile.RequestBody.Buildkit.ToPolicy(profile.RequestBody.Build).LLBBridge.AllowUninspectedPassthrough {
		t.Fatal("docs example profile does not turn the passthrough on")
	}
}

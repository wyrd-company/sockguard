// Fork: wyrd-company/sockguard. This file holds request_body.buildkit.
// llb_bridge, the fork's opt-in LLBBridge passthrough setting, and its
// validation. Kept out of config.go, buildkit_options.go and validate.go so
// upstream security releases rebase cleanly.
package config

import (
	"fmt"

	"github.com/codeswhat/sockguard/app/internal/buildkitproxy"
)

// BuildkitLLBBridgeRequestBodyConfig gates moby.buildkit.v1.frontend.
// LLBBridge on POST /grpc. The BuildKit SDK's client.Build calls this
// service on the control connection; without this setting every call is
// denied (buildkit_method_denied).
//
// It is valid only inside clients.profiles[].request_body, and only when
// the same profile sets buildkit.control.solve.allow: see
// validateBuildkitLLBBridge. LLBBridge on POST /session has no setting and
// stays denied.
type BuildkitLLBBridgeRequestBodyConfig struct {
	// AllowUninspectedPassthrough forwards LLBBridge calls on POST /grpc
	// without inspecting them: inner LLB ops, frontends, mounts, sources
	// and ExecOp network and security modes reach the daemon as sent.
	// The outer Control/Solve checks still apply. Default false.
	AllowUninspectedPassthrough bool `mapstructure:"allow_uninspected_passthrough"`
}

func (c BuildkitLLBBridgeRequestBodyConfig) toPolicy() buildkitproxy.LLBBridgePolicy {
	return buildkitproxy.LLBBridgePolicy{AllowUninspectedPassthrough: c.AllowUninspectedPassthrough}
}

// validateBuildkitLLBBridge enforces the two scoping rules for
// llb_bridge.allow_uninspected_passthrough:
//
//   - The top-level request_body applies to every client that no profile
//     selects, so the setting there would open the passthrough for all of
//     them. It is rejected; a client must be selected into a profile that
//     sets it.
//   - LLBBridge calls only act inside a build job that an outer
//     Control/Solve starts, and that Solve is where the entitlement checks
//     run. A profile that sets the passthrough must also set
//     buildkit.control.solve.allow.
func validateBuildkitLLBBridge(cfg *Config) []string {
	var errs []string
	if cfg.RequestBody.Buildkit.LLBBridge.AllowUninspectedPassthrough {
		errs = append(errs, "request_body.buildkit.llb_bridge.allow_uninspected_passthrough is only valid in clients.profiles[].request_body; set it on the profile of each client that needs it")
	}
	for i, profile := range cfg.Clients.Profiles {
		buildkit := profile.RequestBody.Buildkit
		if buildkit.LLBBridge.AllowUninspectedPassthrough && !buildkit.Control.Solve.Allow {
			prefix := fmt.Sprintf("clients.profiles[%d].request_body", i)
			errs = append(errs, requiresError(prefix+".buildkit.llb_bridge.allow_uninspected_passthrough", prefix+".buildkit.control.solve.allow: true"))
		}
	}
	return errs
}

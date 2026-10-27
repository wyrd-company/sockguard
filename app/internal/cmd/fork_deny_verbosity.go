package cmd

import (
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// withGlobalDenyVerbosity gives a client profile's policy the global
// response.deny_verbosity. servePolicyConfig sets it on the default policy
// only, and a profile has no deny_verbosity of its own, so without this a
// profile denial always carried the minimal body.
func withGlobalDenyVerbosity(cfg *config.Config, policy filter.PolicyConfig) filter.PolicyConfig {
	policy.DenyResponseVerbosity = filter.ParseDenyResponseVerbosity(cfg.Response.DenyVerbosity)
	return policy
}

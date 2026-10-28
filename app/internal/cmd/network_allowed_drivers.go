package cmd

import (
	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
	"github.com/codeswhat/sockguard/app/internal/upstream"
)

// attachNetworkDriverInspector wires the GET /networks/{id} lookup that
// request_body.network.allowed_drivers uses on network connect and container
// create. It goes through the shared upstream resolver, like the exec-start
// inspector, and is attached for the default policy and every profile; it is
// consulted only where allowed_drivers is set.
func attachNetworkDriverInspector(cfg *config.Config, res *upstream.Resolver, policy filter.PolicyConfig) filter.PolicyConfig {
	inspect := filter.NewDockerNetworkInspectorWithRoundTripper(upstreamResolverFor(res, cfg))
	policy.Network.Drivers.Inspect = inspect
	policy.ContainerCreate.NetworkDrivers.Inspect = inspect
	return policy
}

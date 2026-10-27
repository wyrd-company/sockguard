package config

import (
	"fmt"
	"strings"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

// networkDriverOptions returns the allowed_drivers half of the network
// options. The runtime network lookup is attached by the caller (see
// cmd.attachRuntimeInspectors).
func (c NetworkRequestBodyConfig) networkDriverOptions() filter.NetworkDriverOptions {
	return filter.NetworkDriverOptions{AllowedDrivers: c.AllowedDrivers}
}

// validateNetworkAllowedDrivers checks request_body.network.allowed_drivers
// and rejects request_body.libpod_network.allowed_drivers. The libpod network
// and container routes do not apply the list, so accepting the key there
// would be a config that means something other than what it says.
func validateNetworkAllowedDrivers(prefix string, cfg RequestBodyConfig) []string {
	var errs []string
	for i, driver := range cfg.Network.AllowedDrivers {
		if strings.TrimSpace(driver) == "" {
			errs = append(errs, fmt.Sprintf("%s.network.allowed_drivers[%d] must not be empty", prefix, i))
		}
	}
	if len(cfg.LibpodNetwork.AllowedDrivers) > 0 {
		errs = append(errs, fmt.Sprintf("%s.libpod_network.allowed_drivers is not supported; request_body.network.allowed_drivers applies to the Docker-compat routes only", prefix))
	}
	return errs
}

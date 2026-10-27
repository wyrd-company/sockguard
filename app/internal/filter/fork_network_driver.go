package filter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"
)

// fork_network_driver.go holds the fork's request_body.network.allowed_drivers
// policy: an optional allowlist of network driver names, checked everywhere a
// Docker-compat request creates a network or attaches a container to one.
//
// Network create carries its driver in the body, so it is checked directly.
// The attach paths name a network that already exists, and its driver is
// known only to the daemon, so each named network is looked up with
// GET /networks/{id} and its Driver checked. The attach paths are:
//
//   - POST /networks/{id}/connect: the path network, and a non-empty
//     EndpointConfig.NetworkID, which dockerd prefers over the path name for
//     a user-defined network (getNetworkID in daemon/container_operations.go).
//   - POST /containers/create: a HostConfig.NetworkMode that names a network,
//     every NetworkingConfig.EndpointsConfig key, and every non-empty
//     EndpointsConfig[*].NetworkID, for the same reason.
//
// NetworkMode values that are not network names are not looked up. They are
// matched the way dockerd's container.NetworkMode matches them: exactly, with
// no trimming or case folding. "" and "default" select the default bridge
// network and are checked as the driver "bridge"; "host" and "none" are
// namespace modes, governed by allow_host_network and by having no network;
// "container:<ref>" joins another container's namespace and is governed by
// the namespace sharing rules. Every other value is a network name to dockerd
// and is looked up, including "HOST", " host" and Podman's "ns:<path>"
// (which a Podman upstream answers with 404, so it is denied).
//
// A lookup that fails, a network the daemon does not know, and a missing
// inspector all deny. An unset list checks nothing and looks nothing up.
// Like every preflight inspect, this cannot close the window between the
// lookup and the daemon's write.

// NetworkInspectFunc returns the driver of the network identifier names. It
// reports found=false when the daemon answers 404.
type NetworkInspectFunc func(ctx context.Context, identifier string) (driver string, found bool, err error)

// NetworkDriverOptions configures request_body.network.allowed_drivers.
type NetworkDriverOptions struct {
	// AllowedDrivers lists the admitted network driver names. Empty means the
	// check is off (upstream behavior).
	AllowedDrivers []string
	// Inspect looks up an existing network's driver for the attach paths. It
	// is runtime wiring (see cmd.attachRuntimeInspectors); nil with a
	// non-empty AllowedDrivers denies every attach that needs a lookup.
	Inspect NetworkInspectFunc
}

// defaultNetworkDriver is the driver dockerd uses when network create names
// none, and the driver of the network NetworkMode "" and "default" select.
const defaultNetworkDriver = "bridge"

type networkDriverPolicy struct {
	allowed []string
	inspect NetworkInspectFunc
}

func newNetworkDriverPolicy(opts NetworkDriverOptions) networkDriverPolicy {
	var allowed []string
	for _, driver := range opts.AllowedDrivers {
		normalized := normalizeNetworkDriver(driver)
		if normalized == "" || slices.Contains(allowed, normalized) {
			continue
		}
		allowed = append(allowed, normalized)
	}
	return networkDriverPolicy{allowed: allowed, inspect: opts.Inspect}
}

func normalizeNetworkDriver(driver string) string {
	return strings.ToLower(strings.TrimSpace(driver))
}

func (p networkDriverPolicy) enabled() bool {
	return len(p.allowed) > 0
}

// driverAllowed reports whether driver is in the list. An empty driver is
// not: callers map a create's empty Driver to "bridge" first, and an
// inspected network with no driver is denied.
func (p networkDriverPolicy) driverAllowed(driver string) bool {
	normalized := normalizeNetworkDriver(driver)
	return normalized != "" && slices.Contains(p.allowed, normalized)
}

// denyCreateReason checks a network create's own Driver. An empty Driver is
// dockerd's default, "bridge".
func (p networkDriverPolicy) denyCreateReason(driver string) string {
	if !p.enabled() {
		return ""
	}
	if strings.TrimSpace(driver) == "" {
		driver = defaultNetworkDriver
	}
	if p.driverAllowed(driver) {
		return ""
	}
	return fmt.Sprintf("network create denied: network driver %q is not in allowed_drivers", driver)
}

// denyAttachReason looks up each named network and checks its driver.
// subject prefixes the reason ("network connect", "container create").
func (p networkDriverPolicy) denyAttachReason(ctx context.Context, subject string, networks []string) string {
	if !p.enabled() {
		return ""
	}
	for _, network := range networks {
		if p.inspect == nil {
			return fmt.Sprintf("%s denied: network %q driver lookup is not configured", subject, network)
		}
		driver, found, err := p.inspect(ctx, network)
		if err != nil {
			return fmt.Sprintf("%s denied: network %q driver lookup failed", subject, network)
		}
		if !found {
			return fmt.Sprintf("%s denied: network %q not found for driver check", subject, network)
		}
		if !p.driverAllowed(driver) {
			return fmt.Sprintf("%s denied: network %q has driver %q, which is not in allowed_drivers", subject, network, driver)
		}
	}
	return ""
}

// connectNetworkDriverRequest is the part of a connect body the driver check
// reads.
type connectNetworkDriverRequest struct {
	EndpointConfig *struct {
		NetworkID string `json:"NetworkID"`
	} `json:"EndpointConfig"`
}

// denyConnectDriverReason checks POST /networks/{id}/connect. It runs before
// the body is required, so a connect whose body the daemon would reject is
// still checked against the path network.
func (p networkDriverPolicy) denyConnectDriverReason(ctx context.Context, normalizedPath string, body []byte) string {
	if !p.enabled() {
		return ""
	}
	networkID, _, _ := strings.Cut(strings.TrimPrefix(normalizedPath, "/networks/"), "/")
	networks := []string{networkID}
	if len(body) > 0 {
		var req connectNetworkDriverRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return "network connect denied: request body could not be inspected"
		}
		if req.EndpointConfig != nil {
			networks = appendNetworkReference(networks, req.EndpointConfig.NetworkID)
		}
	}
	return p.denyAttachReason(ctx, "network connect", networks)
}

// containerCreateNetworkDriverRequest is the part of a container create body
// the driver check reads.
type containerCreateNetworkDriverRequest struct {
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkingConfig struct {
		EndpointsConfig map[string]*struct {
			NetworkID string `json:"NetworkID"`
		} `json:"EndpointsConfig"`
	} `json:"NetworkingConfig"`
}

// denyContainerCreateDriverReason checks the networks a container create
// attaches to.
func (p networkDriverPolicy) denyContainerCreateDriverReason(ctx context.Context, body []byte) string {
	if !p.enabled() {
		return ""
	}
	var req containerCreateNetworkDriverRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return "container create denied: malformed JSON request body"
	}

	var networks []string
	mode := req.HostConfig.NetworkMode
	switch {
	case mode == "" || mode == "default":
		if !p.driverAllowed(defaultNetworkDriver) {
			return fmt.Sprintf("container create denied: default network driver %q is not in allowed_drivers", defaultNetworkDriver)
		}
	case networkModeNamesNetwork(mode):
		networks = appendNetworkReference(networks, mode)
	}

	names := make([]string, 0, len(req.NetworkingConfig.EndpointsConfig))
	for name := range req.NetworkingConfig.EndpointsConfig {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		networks = appendNetworkReference(networks, name)
		if endpoint := req.NetworkingConfig.EndpointsConfig[name]; endpoint != nil {
			networks = appendNetworkReference(networks, endpoint.NetworkID)
		}
	}
	return p.denyAttachReason(ctx, "container create", networks)
}

// networkModeNamesNetwork reports whether a NetworkMode value names a network
// rather than a namespace mode (see the file comment).
func networkModeNamesNetwork(mode string) bool {
	return mode != "host" && mode != "none" && !strings.HasPrefix(mode, "container:")
}

// appendNetworkReference adds a non-empty reference once, as written: dockerd
// resolves a network reference without trimming it.
func appendNetworkReference(networks []string, reference string) []string {
	if reference == "" || slices.Contains(networks, reference) {
		return networks
	}
	return append(networks, reference)
}

// NewDockerNetworkInspectorWithRoundTripper returns a NetworkInspectFunc that
// issues GET /networks/{id} through the shared upstream RoundTripper, so the
// lookup follows the same active endpoint as the request it guards. It adds
// no timeout of its own: the request context bounds it, as it bounds the
// exec-start inspector.
func NewDockerNetworkInspectorWithRoundTripper(rt http.RoundTripper) NetworkInspectFunc {
	client := &http.Client{Transport: rt}
	return func(ctx context.Context, identifier string) (string, bool, error) {
		if strings.IndexFunc(identifier, unicode.IsControl) >= 0 {
			return "", false, fmt.Errorf("network identifier holds a control character")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/networks/"+url.PathEscape(identifier), nil) // #nosec G704 -- the injected transport targets the local container-engine socket, and the identifier is path-escaped.
		if err != nil {
			return "", false, err
		}
		resp, err := client.Do(req) // #nosec G704 -- the injected transport targets the local container-engine socket, not the URL host.
		if err != nil {
			return "", false, err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return "", false, nil
		}
		if resp.StatusCode != http.StatusOK {
			return "", false, fmt.Errorf("upstream returned %s", resp.Status)
		}
		body, err := readBoundedResponseBody(resp)
		if err != nil {
			return "", false, err
		}
		var decoded struct {
			Driver *string `json:"Driver"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return "", false, err
		}
		if decoded.Driver == nil {
			return "", false, fmt.Errorf("network inspect response has no Driver")
		}
		return *decoded.Driver, true, nil
	}
}

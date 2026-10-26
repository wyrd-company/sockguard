package ownership

import (
	"slices"
	"strings"
)

// Fork-owned: keep a client's `label` list filters under ownership on the
// lists whose daemon ANDs every `label` value.
//
// addOwnerLabelFilter drops every client value under `label`, because Swarm's
// control-plane lists fold the values into a map and a repeated owner key can
// displace the proxy's selector. On the lists below no engine does that:
// Docker's Args.MatchKVList and Podman's MatchLabelFilters both return false
// unless every value matches (see internal/dockerfilters/injected.go). A kept
// client value can therefore only narrow the owner-scoped result. Clients such
// as devcontainer-builder find their containers only through these filters, so
// dropping them returned every owned container to a lookup for one workspace.
//
// Swarm lists, /events (Podman ORs event filters) and the prune endpoints are
// not listed and keep the upstream drop.

// forkOwnershipKeepsClientLabels reports whether normPath names a list on
// which client `label` values ride along with the owner selector. Only GET and
// HEAD reach these paths through addOwnerLabelFilter (see needsOwnerFilter).
func forkOwnershipKeepsClientLabels(normPath string) bool {
	switch normPath {
	case "/containers/json", "/images/json", "/networks", "/volumes",
		libpodPrefix + "containers/json",
		libpodPrefix + "images/json",
		libpodPrefix + "pods/json",
		libpodPrefix + "networks/json",
		libpodPrefix + "volumes/json":
		return true
	default:
		return false
	}
}

// forkOwnershipAppendClientLabels appends to values each client value that
// does not name labelKey and is not already present.
func forkOwnershipAppendClientLabels(values, client []string, labelKey string) []string {
	for _, value := range client {
		if forkOwnershipNamesLabelKey(value, labelKey) || slices.Contains(values, value) {
			continue
		}
		values = append(values, value)
	}
	return values
}

// forkOwnershipNamesLabelKey reports whether a `label` filter value selects on
// labelKey. The key is the text before the first `=`, read loosely so that a
// spelling one engine might accept is still caught: surrounding whitespace and
// a trailing `!` (as in `key!=value`) are removed.
func forkOwnershipNamesLabelKey(value, labelKey string) bool {
	key, _, _ := strings.Cut(value, "=")
	key = strings.TrimSpace(key)
	key = strings.TrimSpace(strings.TrimSuffix(key, "!"))
	return key == labelKey
}

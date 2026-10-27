package filter_test

import (
	"context"

	"github.com/codeswhat/sockguard/app/internal/filter"
)

// forkStartRecheckPresetInspector stands in for the daemon behind the serve
// chain's start re-check inspector in preset conformance harnesses, which
// have no daemon. It reports a container with no bind source, so a start is
// decided by the preset's rules alone and no host path reaches the resolver.
func forkStartRecheckPresetInspector(context.Context, string) (filter.ForkStartRecheckContainer, error) {
	return filter.ForkStartRecheckContainer{}, nil
}

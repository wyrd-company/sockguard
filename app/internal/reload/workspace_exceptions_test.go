package reload

import (
	"slices"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/config"
)

// Fork-owned: both halves of the immutability contract for
// workspace_exceptions (see TestUpstreamFlavorIsImmutable).
func TestWorkspaceExceptionsIsImmutable(t *testing.T) {
	t.Parallel()
	if !slices.Contains(ImmutableFields, "workspace_exceptions") {
		t.Fatal("ImmutableFields does not contain workspace_exceptions")
	}
	oldCfg := config.Defaults()
	for name, edit := range map[string]func(*config.Config){
		"file": func(c *config.Config) { c.WorkspaceExceptions.File = "/srv/policy/workspace-exceptions.json" },
		"root": func(c *config.Config) { c.WorkspaceExceptions.WorkspaceRoot = "/srv/workspaces" },
	} {
		newCfg := config.Defaults()
		edit(&newCfg)
		if changed := ImmutableDiff(&oldCfg, &newCfg); !slices.Contains(changed, "workspace_exceptions") {
			t.Fatalf("%s change: ImmutableDiff = %v, want workspace_exceptions", name, changed)
		}
	}
	same := config.Defaults()
	if changed := ImmutableDiff(&oldCfg, &same); slices.Contains(changed, "workspace_exceptions") {
		t.Fatalf("no change: ImmutableDiff = %v", changed)
	}
}

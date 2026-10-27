// ---
// relationships:
//   references: ../../../docs/content/docs/symlink-bind-sources.mdx
// ---

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/codeswhat/sockguard/app/internal/config"
	"github.com/codeswhat/sockguard/app/internal/filter"
)

// Fork-owned: diagnostics for the paths resolved in this proxy's namespace.
// A file (including a socket) is a valid allowlist entry. Service bind roots
// resolve on swarm nodes; plugins do not use the resolver, so neither is checked.
func checkBindRootVisibility(cfg *config.Config, logger *slog.Logger) error {
	var failures []error
	check := func(block string, entries []string, strict bool) {
		for _, entry := range entries {
			if _, err := os.Stat(entry); err != nil {
				reason := "cannot be inspected in the proxy mount namespace"
				switch {
				case errors.Is(err, fs.ErrNotExist):
					reason = "does not exist in the proxy mount namespace"
				case errors.Is(err, fs.ErrPermission):
					reason = "permission denied in the proxy mount namespace"
				}
				diagnostic := fmt.Errorf("%s.allowed_bind_mounts: %q %s; mount it read-only at the same path: %w", block, entry, reason, err)
				if strict {
					logger.Error("bind root visibility check failed", "block", block, "path", entry, "error", diagnostic)
					failures = append(failures, diagnostic)
				} else {
					logger.Warn("bind root visibility check failed", "block", block, "path", entry, "error", diagnostic)
				}
			}
		}
	}
	checkBody := func(block string, body config.RequestBodyConfig) {
		check(block+".container_create", body.ContainerCreate.AllowedBindMounts, body.ContainerCreate.ApplyWorkspaceExceptions)
		check(block+".libpod_container_create", body.LibpodContainerCreate.AllowedBindMounts, false)
	}
	checkBody("base.request_body", cfg.RequestBody)
	for _, profile := range cfg.Clients.Profiles {
		checkBody(fmt.Sprintf("profile %q.request_body", profile.Name), profile.RequestBody)
	}
	return errors.Join(failures...)
}

func checkReloadBindRoots(cfg *config.Config, logger *slog.Logger) error {
	if err := checkBindRootVisibility(cfg, logger); err != nil {
		return err
	}
	if cfg.WorkspaceExceptions.Enabled() {
		_, err := filter.CheckWorkspaceExceptionRoots(cfg.WorkspaceExceptions.WorkspaceRoot, cfg.WorkspaceExceptions.PerWorkspaceRoots)
		return err
	}
	return nil
}

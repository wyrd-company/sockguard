package config

import (
	"fmt"
	"path"
)

// Fork-owned (wyrd-company/sockguard): the workspace exceptions block.
//
// workspace_exceptions names the exceptions file and the workspace root its
// keys must sit directly under. Both are bound at startup (reload-immutable).
// A container_create block reads the file only when it sets
// apply_workspace_exceptions. See docs/content/docs/workspace-exceptions.mdx.

// WorkspaceExceptionsConfig is the top-level workspace_exceptions block.
type WorkspaceExceptionsConfig struct {
	// File is the absolute path of the exceptions JSON file. Empty turns the
	// feature off.
	File string `mapstructure:"file"`
	// WorkspaceRoot is the absolute, canonical folder whose direct children
	// are workspaces. Required when File is set.
	WorkspaceRoot string `mapstructure:"workspace_root"`
}

// Enabled reports whether an exceptions file is configured.
func (c WorkspaceExceptionsConfig) Enabled() bool {
	return c.File != ""
}

// validateWorkspaceExceptions checks the block's syntax. Whether the root is
// canonical is a filesystem check, made when the store is built at startup.
func validateWorkspaceExceptions(cfg *Config) []string {
	var errs []string
	we := cfg.WorkspaceExceptions
	if we.Enabled() {
		if !path.IsAbs(we.File) || path.Clean(we.File) != we.File {
			errs = append(errs, fmt.Sprintf("workspace_exceptions.file must be an absolute, clean path, got %q", we.File))
		}
		switch {
		case we.WorkspaceRoot == "":
			errs = append(errs, requiredWhenError("workspace_exceptions.workspace_root", "workspace_exceptions.file is set"))
		case !path.IsAbs(we.WorkspaceRoot) || path.Clean(we.WorkspaceRoot) != we.WorkspaceRoot || we.WorkspaceRoot == "/":
			errs = append(errs, fmt.Sprintf("workspace_exceptions.workspace_root must be an absolute, clean path other than /, got %q", we.WorkspaceRoot))
		}
	} else if we.WorkspaceRoot != "" {
		errs = append(errs, requiresError("workspace_exceptions.workspace_root", "workspace_exceptions.file"))
	}
	if !we.Enabled() {
		if cfg.RequestBody.ContainerCreate.ApplyWorkspaceExceptions {
			errs = append(errs, requiresError("request_body.container_create.apply_workspace_exceptions", "workspace_exceptions.file"))
		}
		for i, profile := range cfg.Clients.Profiles {
			if profile.RequestBody.ContainerCreate.ApplyWorkspaceExceptions {
				errs = append(errs, requiresError(fmt.Sprintf("clients.profiles[%d].request_body.container_create.apply_workspace_exceptions", i), "workspace_exceptions.file"))
			}
		}
	}
	return errs
}

package config

import (
	"fmt"
	"path"
	"slices"
	"strings"
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
	// PerWorkspaceRoots are the folders whose direct children belong to one
	// workspace each: in a block with apply_workspace_exceptions, a bind
	// under one must be inside <root>/<basename W>. Empty means
	// [WorkspaceRoot]; when set, it must contain WorkspaceRoot.
	PerWorkspaceRoots []string `mapstructure:"per_workspace_roots"`
}

// EffectivePerWorkspaceRoots is PerWorkspaceRoots, or [WorkspaceRoot] when
// it is empty.
func (c WorkspaceExceptionsConfig) EffectivePerWorkspaceRoots() []string {
	if len(c.PerWorkspaceRoots) == 0 && c.WorkspaceRoot != "" {
		return []string{c.WorkspaceRoot}
	}
	return c.PerWorkspaceRoots
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
		errs = append(errs, validatePerWorkspaceRoots(cfg)...)
	} else {
		if we.WorkspaceRoot != "" {
			errs = append(errs, requiresError("workspace_exceptions.workspace_root", "workspace_exceptions.file"))
		}
		if len(we.PerWorkspaceRoots) > 0 {
			errs = append(errs, requiresError("workspace_exceptions.per_workspace_roots", "workspace_exceptions.file"))
		}
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

// validatePerWorkspaceRoots checks the roots' syntax, and that no
// allowed_bind_mounts entry of a block with apply_workspace_exceptions
// contains a root. Scoping narrows each entry at or under a root to the
// request's folder; an entry above a root ("/srv", "/") cannot be narrowed
// that way and would admit every workspace's folder.
func validatePerWorkspaceRoots(cfg *Config) []string {
	var errs []string
	we := cfg.WorkspaceExceptions
	roots := we.EffectivePerWorkspaceRoots()
	if len(we.PerWorkspaceRoots) > 0 && !slices.Contains(we.PerWorkspaceRoots, we.WorkspaceRoot) {
		errs = append(errs, "workspace_exceptions.per_workspace_roots must include workspace_exceptions.workspace_root")
	}
	for i, root := range we.PerWorkspaceRoots {
		if !path.IsAbs(root) || path.Clean(root) != root || root == "/" {
			errs = append(errs, fmt.Sprintf("workspace_exceptions.per_workspace_roots[%d] must be an absolute, clean path other than /, got %q", i, root))
			continue
		}
		for j, other := range we.PerWorkspaceRoots {
			if i != j && (root == other || strings.HasPrefix(root, other+"/")) {
				errs = append(errs, fmt.Sprintf("workspace_exceptions.per_workspace_roots[%d] %q repeats or is inside %q", i, root, other))
			}
		}
	}
	check := func(prefix string, cc ContainerCreateRequestBodyConfig) {
		if !cc.ApplyWorkspaceExceptions {
			return
		}
		for i, entry := range cc.AllowedBindMounts {
			cleaned := path.Clean(entry)
			for _, root := range roots {
				if cleaned == "/" || strings.HasPrefix(root, cleaned+"/") {
					errs = append(errs, fmt.Sprintf("%s.allowed_bind_mounts[%d] %q contains the per-workspace root %q; list the root itself or folders beside it", prefix, i, entry, root))
				}
			}
		}
	}
	check("request_body.container_create", cfg.RequestBody.ContainerCreate)
	for i, profile := range cfg.Clients.Profiles {
		check(fmt.Sprintf("clients.profiles[%d].request_body.container_create", i), profile.RequestBody.ContainerCreate)
	}
	return errs
}

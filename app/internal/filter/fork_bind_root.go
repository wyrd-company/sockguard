// ---
// relationships:
//   references: ../../../docs/content/docs/workspace-exceptions.mdx
// ---

package filter

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Fork-owned: shared startup and config-reload validation of namespace roots.

// CheckWorkspaceExceptionRoots validates the canonical directories and returns
// their effective list. Callers only use it when workspace_exceptions.file is set.
func CheckWorkspaceExceptionRoots(root string, roots []string) ([]string, error) {
	if err := checkWorkspaceRoot(root); err != nil {
		return nil, err
	}
	return checkPerWorkspaceRoots(root, roots)
}

func workspaceRootAccessError(root string, err error) error {
	reason := "cannot be inspected in the proxy mount namespace"
	switch {
	case errors.Is(err, fs.ErrNotExist):
		reason = "does not exist in the proxy mount namespace"
	case errors.Is(err, fs.ErrPermission):
		reason = "permission denied in the proxy mount namespace"
	}
	return fmt.Errorf("workspace root %q %s; mount it read-only at the same path: %w", root, reason, err)
}

// checkWorkspaceRoot requires root to be absolute, clean, not "/", and free
// of symlinks in the proxy's mount namespace, and an existing directory.
func checkWorkspaceRoot(root string) error {
	if !path.IsAbs(root) || path.Clean(root) != root || root == "/" {
		return fmt.Errorf("workspace root %q must be an absolute, clean path other than /", root)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return workspaceRootAccessError(root, err)
	}
	if resolved != root {
		return fmt.Errorf("workspace root %q is not canonical: it resolves to %q", root, resolved)
	}
	info, err := os.Stat(root)
	if err != nil {
		return workspaceRootAccessError(root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("workspace root %q is not a directory; mount it read-only at the same path", root)
	}
	return nil
}

// checkPerWorkspaceRoots returns the effective per-workspace roots: root
// alone when roots is empty. Each is checked like the workspace root, root
// must be listed, and no root may be inside another (a folder name would then
// scope two ways).
func checkPerWorkspaceRoots(root string, roots []string) ([]string, error) {
	if len(roots) == 0 {
		return []string{root}, nil
	}
	if !slices.Contains(roots, root) {
		return nil, fmt.Errorf("per-workspace roots %q must include the workspace root %q", roots, root)
	}
	for i, r := range roots {
		if r != root {
			if err := checkWorkspaceRoot(r); err != nil {
				return nil, fmt.Errorf("per-workspace root: %w", err)
			}
		}
		for j, other := range roots {
			if i != j && (r == other || strings.HasPrefix(r, other+"/")) {
				return nil, fmt.Errorf("per-workspace root %q repeats or is inside %q", r, other)
			}
		}
	}
	return slices.Clone(roots), nil
}

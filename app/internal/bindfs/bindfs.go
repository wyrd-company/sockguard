// Package bindfs holds the filesystem lookups the bind-source resolver in
// internal/filter makes (fork-owned, wyrd-company/sockguard).
//
// The lookups are plain os.Lstat and os.Readlink. A test binary can call
// ConfineForTests so that a lookup outside its own temporary directories
// reports a plain directory: a bind source such as "/usr/libexec/x" then
// resolves to itself on every host, whatever that host has installed there,
// and a test of the resolver uses a fixture under its temporary directory.
package bindfs

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// realRoots is nil outside tests. When set, it returns the directories under
// which lookups use the real filesystem.
var realRoots func() []string

// ConfineForTests makes every lookup outside the directories roots returns
// report an existing directory that is not a symlink. roots is called on each
// lookup, so it can follow a TMPDIR that TestMain sets after init. Each root
// counts in both its written and its resolved spelling. Call it from a test
// file's init function only; production code never calls it.
func ConfineForTests(roots func() []string) {
	realRoots = roots
}

// Lstat is os.Lstat, except outside the real roots of a confined test binary.
func Lstat(name string) (fs.FileInfo, error) {
	if realRoots != nil && !underRealRoot(name) {
		return plainDir(path.Base(name)), nil
	}
	return os.Lstat(name)
}

// Readlink is os.Readlink. Lstat never reports a symlink outside the real
// roots, so a confined test binary never reaches it there.
func Readlink(name string) (string, error) {
	return os.Readlink(name)
}

func underRealRoot(name string) bool {
	for _, root := range realRoots() {
		spellings := []string{filepath.Clean(root)}
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			spellings = append(spellings, resolved)
		}
		for _, r := range spellings {
			if name == r || strings.HasPrefix(name, r+"/") {
				return true
			}
		}
	}
	return false
}

type plainDir string

func (d plainDir) Name() string     { return string(d) }
func (plainDir) Size() int64        { return 0 }
func (plainDir) Mode() fs.FileMode  { return fs.ModeDir | 0o755 }
func (plainDir) ModTime() time.Time { return time.Time{} }
func (plainDir) IsDir() bool        { return true }
func (plainDir) Sys() any           { return nil }

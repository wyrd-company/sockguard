// relationships:
//
// references: [../../../docs/content/docs/symlink-bind-sources]
package bindfs

import (
	"os"
	"path/filepath"
	"sync"
)

// Fork-owned test support. The public testing APIs keep production free of a
// testing dependency, reflection into testing internals, and unsafe code.
type realRootTest interface {
	Helper()
	Setenv(string, string)
	Cleanup(func())
	Fatalf(string, ...any)
}

var realRootAdmission struct {
	sync.Mutex
	open bool
}

// RealRootForTest opens real lookups under root until t's cleanup. It restores
// the exact previous confinement. root must be an existing absolute temporary
// directory owned by the caller. It cannot be used by a parallel test (or a
// descendant of one), or nested inside another open real root.
func RealRootForTest(t realRootTest, root string) {
	t.Helper()
	// Setenv is the public testing API that refuses parallel tests and their
	// descendants. It also prevents a later t.Parallel call on this test.
	func() {
		defer func() {
			if recover() != nil {
				t.Fatalf("real bind root cannot be used with t.Parallel")
			}
		}()
		t.Setenv("SOCKGUARD_TEST_BIND_FS_REAL_ROOT", root)
	}()
	info, err := os.Stat(root)
	if !filepath.IsAbs(root) || err != nil || !info.IsDir() {
		t.Fatalf("real bind root must be an existing absolute temporary directory")
		return
	}
	realRootAdmission.Lock()
	if realRootAdmission.open {
		realRootAdmission.Unlock()
		t.Fatalf("another real bind root is already open")
		return
	}
	previous := realRoots
	realRootAdmission.open = true
	realRoots = func() []string { return []string{root} }
	realRootAdmission.Unlock()
	t.Cleanup(func() {
		realRootAdmission.Lock()
		defer realRootAdmission.Unlock()
		realRoots = previous
		realRootAdmission.open = false
	})
}

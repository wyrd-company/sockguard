package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
)

// Bind-source lookups use the real filesystem only under TMPDIR, which
// TestMain points at a directory of this run. Every other path is a plain
// directory, so a test that names a host path ("/srv/roots", "/dev/sdb1")
// gets the same result on every host, whatever is installed there. Tests of
// the resolver itself use fixtures under t.TempDir.
func init() {
	bindfs.ConfineForTests(func() []string { return []string{os.TempDir()} })
}

// TestSymlinkBindHostPathsAreHermetic puts the same symlink to "/" outside
// TMPDIR and under t.TempDir. Outside, it is a plain directory and the source
// passes; under t.TempDir, it resolves and is denied.
func TestSymlinkBindHostPathsAreHermetic(t *testing.T) {
	outside, err := os.MkdirTemp(filepath.Dir(os.TempDir()), "symlink-bind-outside-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) })
	inside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{outside, inside} {
		if err := os.Symlink("/", filepath.Join(dir, "link")); err != nil {
			t.Fatal(err)
		}
	}

	if got := denySymlinkedBindSourceReason("t", "bind mount source", outside+"/link", outside+"/link", []string{outside}); got != "" {
		t.Fatalf("outside TMPDIR: deny reason = %q, want allowed", got)
	}
	want := `t denied: bind mount source "` + inside + `/link" resolves to "/", which is not allowlisted`
	if got := denySymlinkedBindSourceReason("t", "bind mount source", inside+"/link", inside+"/link", []string{inside}); got != want {
		t.Fatalf("under t.TempDir: deny reason = %q, want %q", got, want)
	}
}

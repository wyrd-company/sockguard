package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codeswhat/sockguard/app/internal/bindfs"
)

// Every bind-source lookup is a plain directory, except where a test opens
// its own temporary root (TestServeChainForkStartRecheckDeniesASwappedBindSource). A serve-chain test that names a
// host path ("/usr/libexec/podman/catatonit", "/srv/roots") then gets the
// same result on every host, whatever is installed there.
func init() {
	bindfs.ConfineForTests(func() []string { return nil })
}

// TestBindSourceLookupsAreHermetic checks that the confinement is active in
// this test binary: a real symlink reads as a plain directory.
func TestBindSourceLookupsAreHermetic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink("/", p); err != nil {
		t.Fatal(err)
	}
	info, err := bindfs.Lstat(p)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("bindfs.Lstat(%q) = %v, %v; want a plain directory", p, info, err)
	}
}

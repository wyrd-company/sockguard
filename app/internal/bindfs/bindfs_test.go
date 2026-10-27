package bindfs

import (
	"os"
	"path/filepath"
	"testing"
)

func confine(t *testing.T, roots ...string) {
	t.Helper()
	ConfineForTests(func() []string { return roots })
	t.Cleanup(func() { realRoots = nil })
}

func link(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "link")
	if err := os.Symlink("/", p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLstatUnconfinedIsReal(t *testing.T) {
	p := link(t, t.TempDir())
	info, err := Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat(%q) = %v, %v; want the real symlink", p, info, err)
	}
}

func TestLstatUnderRealRootIsReal(t *testing.T) {
	root := t.TempDir()
	p := link(t, root)
	confine(t, root)
	info, err := Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat(%q) = %v, %v; want the real symlink", p, info, err)
	}
	if target, err := Readlink(p); err != nil || target != "/" {
		t.Fatalf("Readlink(%q) = %q, %v; want \"/\"", p, target, err)
	}
}

func TestLstatOutsideRealRootsIsPlainDirectory(t *testing.T) {
	p := link(t, t.TempDir())
	confine(t, t.TempDir())
	info, err := Lstat(p)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Name() != "link" {
		t.Fatalf("Lstat(%q) = %v, %v; want a plain directory named link", p, info, err)
	}
	missing := filepath.Join(filepath.Dir(p), "absent")
	if info, err := Lstat(missing); err != nil || !info.IsDir() {
		t.Fatalf("Lstat(%q) = %v, %v; want a plain directory", missing, info, err)
	}
}

func TestLstatRealRootCountsInResolvedSpelling(t *testing.T) {
	real := t.TempDir()
	p := link(t, real)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	confine(t, alias)
	info, err := Lstat(p)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Lstat(%q) under the resolved root = %v, %v; want the real symlink", p, info, err)
	}
}

func TestLstatEmptyRootIsIgnored(t *testing.T) {
	p := link(t, t.TempDir())
	confine(t, "")
	if info, err := Lstat(p); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("Lstat(%q) = %v, %v; want a plain directory", p, info, err)
	}
}

func TestLstatSiblingWithSharedPrefixIsPlainDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	sibling := root + "x"
	for _, dir := range []string{root, sibling} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	p := link(t, sibling)
	confine(t, root)
	if info, err := Lstat(p); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("Lstat(%q) = %v, %v; want a plain directory", p, info, err)
	}
}

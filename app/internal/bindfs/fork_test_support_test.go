// relationships:
//
// references: [../../../docs/content/docs/symlink-bind-sources]
package bindfs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealRootForTestRestoresPreviousConfinement(t *testing.T) {
	root, previous := t.TempDir(), t.TempDir()
	p, q := link(t, root), link(t, previous)
	confine(t, previous)
	t.Run("open", func(t *testing.T) {
		RealRootForTest(t, root)
		if info, err := Lstat(p); err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("real root not opened: %v %v", info, err)
		}
		if info, err := Lstat(q); err != nil || !info.IsDir() {
			t.Fatalf("other root unexpectedly open: %v %v", info, err)
		}
	})
	if info, err := Lstat(p); err != nil || !info.IsDir() {
		t.Fatalf("real root was not restored: %v %v", info, err)
	}
	if info, err := Lstat(q); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("previous confinement was not restored: %v %v", info, err)
	}
	t.Run("open again", func(t *testing.T) { RealRootForTest(t, root) })
}

func TestRealRootForTestRefusesUnsafeUse(t *testing.T) {
	for _, mode := range []string{"parallel", "parallel-parent", "late-parallel", "nested", "missing", "relative", "file"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRealRootForTestRefusalChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), "SOCKGUARD_TEST_REAL_ROOT_REFUSAL="+mode)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("unsafe helper use admitted: %s", out)
			}
			want := "t.Parallel"
			if mode == "nested" {
				want = "another real bind root is already open"
			}
			if mode == "missing" || mode == "relative" || mode == "file" {
				want = "existing absolute temporary directory"
			}
			if !strings.Contains(string(out), want) {
				t.Fatalf("wrong refusal for %s: %s", mode, out)
			}
		})
	}
}

func TestRealRootForTestRefusalChild(t *testing.T) {
	mode := os.Getenv("SOCKGUARD_TEST_REAL_ROOT_REFUSAL")
	if mode == "" {
		return
	}
	root := t.TempDir()
	switch mode {
	case "parallel":
		t.Parallel()
	case "parallel-parent":
		t.Parallel()
		t.Run("child", func(t *testing.T) { RealRootForTest(t, root) })
		return
	case "nested":
		RealRootForTest(t, root)
	case "missing":
		root = filepath.Join(root, "missing")
	case "relative":
		root = "."
	case "file":
		root = filepath.Join(root, "file")
		if err := os.WriteFile(root, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	RealRootForTest(t, root)
	if mode == "late-parallel" {
		t.Parallel()
	}
}

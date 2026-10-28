package reload

import (
	"testing"

	"github.com/fsnotify/fsnotify"
)

// TriggerOnRemove makes a Remove of the watched file arm a reload; without
// it a Remove is ignored, as before.
func TestReloaderTriggerOnRemove(t *testing.T) {
	t.Parallel()
	target := t.TempDir() + "/watched.json"
	for _, tc := range []struct {
		opt  bool
		want bool
	}{{true, true}, {false, false}} {
		rl, err := New(Options{Path: target, OnReload: func() {}, TriggerOnRemove: tc.opt})
		if err != nil {
			t.Fatal(err)
		}
		if got := rl.eventTargetsConfig(fsnotify.Event{Name: target, Op: fsnotify.Remove}); got != tc.want {
			t.Fatalf("TriggerOnRemove=%t: Remove arms reload = %t, want %t", tc.opt, got, tc.want)
		}
		if rl.eventTargetsConfig(fsnotify.Event{Name: target + ".other", Op: fsnotify.Remove}) {
			t.Fatalf("TriggerOnRemove=%t: a Remove of another file must not arm a reload", tc.opt)
		}
	}
}

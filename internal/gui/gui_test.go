package gui

import (
	"sync/atomic"
	"testing"
	"time"
)

// New/Close must not panic or deadlock. If the session has no interactive
// desktop (for example a service), window creation may fail and is skipped.
func TestNewClose(t *testing.T) {
	var protect, review atomic.Bool
	g, err := New(Options{Title: "CookieGuard test", Protect: &protect, ProtectReview: &review})
	if err != nil {
		t.Skipf("gui unavailable in this session: %v", err)
	}
	g.SetStatus("test")
	g.Append("hello")
	time.Sleep(150 * time.Millisecond)
	g.Close()
}

func TestProtectLabel(t *testing.T) {
	var protect atomic.Bool
	opts := Options{Protect: &protect}
	if got := protectLabel(opts); got == "" {
		t.Fatal("empty label when off")
	}
	off := protectLabel(opts)
	protect.Store(true)
	on := protectLabel(opts)
	if off == on {
		t.Fatal("label did not change when protection toggled")
	}
}

package tray

import (
	"testing"
	"time"
)

// Start/Close must not panic or deadlock. On a session without an interactive
// desktop (for example a service), Start may fail; that is skipped rather than
// failing the suite.
func TestStartClose(t *testing.T) {
	trayIcon, err := Start(Options{Tooltip: "CookieGuard test", Items: []MenuItem{{ID: 1, Label: "Quit"}}})
	if err != nil {
		t.Skipf("tray unavailable in this session: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	trayIcon.Close()
}

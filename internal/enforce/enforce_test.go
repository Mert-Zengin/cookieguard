package enforce

import (
	"testing"

	"github.com/cookieguard/internal/threat"
)

func signals(ids ...string) []threat.Signal {
	out := make([]threat.Signal, 0, len(ids))
	for _, id := range ids {
		out = append(out, threat.Signal{ID: id})
	}
	return out
}

func TestDisabledByDefault(t *testing.T) {
	if d := Decide(1234, "stealer.exe", "high", signals("remote_debugging_switch"), false, false); d.Terminate {
		t.Fatal("terminated while protection disabled")
	}
}

func TestHighSeverityTerminates(t *testing.T) {
	d := Decide(1234, "stealer.exe", "high", signals("remote_debugging_switch"), true, false)
	if !d.Terminate {
		t.Fatalf("high severity not terminated: %+v", d)
	}
}

func TestReviewNotTerminatedByDefault(t *testing.T) {
	d := Decide(1234, "tool.exe", "review", signals("untrusted_cookie_access", "unsigned_binary", "user_writable_binary"), true, false)
	if d.Terminate {
		t.Fatal("review terminated without --protect-review")
	}
	d = Decide(1234, "tool.exe", "review", signals("untrusted_cookie_access", "unsigned_binary", "user_writable_binary"), true, true)
	if !d.Terminate {
		t.Fatal("review not terminated with --protect-review")
	}
	// Missing one of the two required signals must not terminate.
	d = Decide(1234, "tool.exe", "review", signals("untrusted_cookie_access", "unsigned_binary"), true, true)
	if d.Terminate {
		t.Fatal("terminated without user-writable signal")
	}
}

func TestCriticalAndSelfNeverTerminated(t *testing.T) {
	for _, name := range []string{"explorer.exe", "lsass.exe", "MsMpEng.exe", "svchost.exe"} {
		if d := Decide(1234, name, "high", signals("remote_debugging_switch"), true, true); d.Terminate {
			t.Errorf("critical process %s terminated", name)
		}
	}
	if d := Decide(selfPID, "attacker.exe", "high", signals("remote_debugging_switch"), true, true); d.Terminate {
		t.Fatal("self process terminated")
	}
	if d := Decide(4, "System", "high", signals("remote_debugging_switch"), true, true); d.Terminate {
		t.Fatal("System pid terminated")
	}
}

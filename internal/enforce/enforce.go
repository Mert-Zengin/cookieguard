// Package enforce decides whether an observed access should be terminated.
// It is intentionally conservative: user-mode termination cannot prevent a read
// that already happened, so it is opt-in, high-confidence only, and never
// applied to critical Windows processes.
package enforce

import (
	"strings"

	"github.com/cookieguard/internal/threat"
)

// criticalNames are Windows processes that must never be terminated by this
// tool even if they match a signal. Killing them can crash or lock the machine.
var criticalNames = map[string]bool{
	"system": true, "idle": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "winlogon.exe": true, "services.exe": true,
	"lsass.exe": true, "svchost.exe": true, "dwm.exe": true, "explorer.exe": true,
	"audiodg.exe": true, "fontdrvhost.exe": true, "sihost.exe": true,
	"registry": true, "memory compression": true, "secure system": true,
	"msmpeng.exe": true, "securityhealthservice.exe": true, "windefend": true,
}

// IsCritical reports whether a process must be left alone.
func IsCritical(name string) bool {
	return criticalNames[strings.ToLower(strings.TrimSpace(name))]
}

// Decision describes the outcome of the enforcement policy.
type Decision struct {
	Terminate bool
	Reason    string
}

// Decide applies the opt-in enforcement policy.
//
//   - protect: terminate only when the assessment reached "high" severity.
//   - reviewToo: additionally terminate unsigned processes running from a
//     user-writable location that hold a readable handle. This is more
//     aggressive and can end legitimate tools; callers must warn the user.
//
// Critical processes, the current process, and PID 0-4 are never terminated.
func Decide(pid int, name string, level string, signals []threat.Signal, protect, reviewToo bool) Decision {
	if !protect {
		return Decision{}
	}
	if pid <= 4 || pid == selfPID {
		return Decision{Reason: "protected pid"}
	}
	if IsCritical(name) {
		return Decision{Reason: "critical process"}
	}
	hasUserWritable := false
	hasUnsigned := false
	for _, s := range signals {
		switch s.ID {
		case "user_writable_binary":
			hasUserWritable = true
		case "unsigned_binary":
			hasUnsigned = true
		}
	}
	switch {
	case level == "high":
		return Decision{Terminate: true, Reason: "high-severity documented technique"}
	case reviewToo && hasUserWritable && hasUnsigned:
		return Decision{Terminate: true, Reason: "unsigned binary in user-writable location"}
	default:
		return Decision{}
	}
}

var selfPID = currentPID()

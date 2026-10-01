// Package threat maps observed browser-data access to documented infostealer
// techniques. It never attributes an observation to a specific malware family:
// a shared technique is not attribution, and legitimate software may match.
package threat

import (
	"path/filepath"
	"strings"

	"github.com/cookieguard/internal/browser"
	"github.com/cookieguard/internal/risk"
)

// Severity is the review priority of a single signal.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityReview Severity = "review"
	SeverityHigh   Severity = "high"
)

// Signal is one concrete, explainable indicator. Detail is safe, defensive text.
type Signal struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

// Assessment is the result of evaluating one process observation.
// Level is "expected", "review", or "high". Families lists the
// publicly-reported families known to use at least one matched technique; it
// is context, not a verdict or an attribution.
type Assessment struct {
	Level    string   `json:"level"`
	Signals  []Signal `json:"signals,omitempty"`
	Families []string `json:"associated_families,omitempty"`
}

func (a Assessment) Has(severity Severity) bool {
	for _, s := range a.Signals {
		if s.Severity == severity {
			return true
		}
	}
	return false
}

// userWritablePrefixes are locations from which consumers can launch untrusted
// binaries. This is a review hint, not proof of malice.
func userWritable(path string) bool {
	p := strings.ToLower(filepath.ToSlash(path))
	for _, marker := range []string{
		"/appdata/local/temp/", "/appdata/locallow/temp/", "/windows/temp/", "/tmp/",
		"/downloads/", "/public/", "/programdata/",
	} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

const remoteDebuggingHelp = "browser started with a remote-debugging switch; a documented cookie/session theft technique that interacts with a live browser profile"

func hasRemoteDebugging(cmd string) string {
	c := strings.ToLower(cmd)
	for _, flag := range []string{
		"--remote-debugging-port", "--remote-debugging-address",
		"--remote-debugging-pipe", "--remote-debugging-targets",
	} {
		if strings.Contains(c, flag) {
			return flag
		}
	}
	return ""
}

// profileArgument reports a command line that points at a browser profile
// directory, which is how some stealers keep using a live, decrypted profile.
func profileArgument(cmd string) bool {
	c := strings.ToLower(filepath.ToSlash(cmd))
	return strings.Contains(c, "/user data/") ||
		strings.Contains(c, "--user-data-dir") ||
		strings.Contains(c, "--profile-directory")
}

// trustedParents are generic Windows session processes and browsers whose
// child browser startup is routine. Only used to reduce noise, never to grant
// access; an untrusted parent is a review signal, not a block.
func trustedParent(name string) bool {
	if browser.IsBrowserProcess(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "explorer.exe", "services.exe", "svchost.exe", "winlogon.exe",
		"runtimebroker.exe", "sihost.exe", "taskmgr.exe", "cmd.exe",
		"powershell.exe", "windowsterminal.exe", "openwith.exe",
		"startmenuexperiencehost.exe", "shellexperiencehost.exe",
		"searchhost.exe", "userinit.exe", "googleupdate.exe",
		"microsoftedgeupdate.exe", "opera.exe", "launcher.exe":
		return true
	default:
		return false
	}
}

// Assess labels one observation. It is deterministic and side-effect free apart
// from reading the file signature of the observed executable.
func Assess(p risk.ProcessInfo) Assessment {
	browserLayout := risk.BrowserLocation(p.Path)
	signed := risk.ValidSignature(p.Path)

	signals := []Signal{}
	if browserLayout && signed {
		signals = append(signals, Signal{
			ID: "expected_browser", Severity: SeverityInfo,
			Detail: "executable name, installation layout, and embedded signature match an expected browser",
		})
	}

	if !browserLayout {
		signals = append(signals, Signal{
			ID: "untrusted_cookie_access", Severity: SeverityReview,
			Detail: "process is not an expected browser binary but holds a readable handle to protected browser data",
		})
		if !signed {
			signals = append(signals, Signal{
				ID: "unsigned_binary", Severity: SeverityReview,
				Detail: "executable has no verifiable embedded Authenticode signature (offline check)",
			})
		}
	}
	if userWritable(p.Path) {
		signals = append(signals, Signal{
			ID: "user_writable_binary", Severity: SeverityReview,
			Detail: "executable runs from a user-writable or temporary location",
		})
	}

	if flag := hasRemoteDebugging(p.CommandLine); flag != "" {
		signals = append(signals, Signal{
			ID: "remote_debugging_switch", Severity: SeverityHigh,
			Detail: remoteDebuggingHelp + " (" + flag + ")",
		})
	}
	if profileArgument(p.CommandLine) {
		signals = append(signals, Signal{
			ID: "profile_argument", Severity: SeverityReview,
			Detail: "command line references a browser profile or user-data directory",
		})
	}
	if browserLayout && p.ParentName != "" && !trustedParent(p.ParentName) {
		signals = append(signals, Signal{
			ID: "browser_launched_by_untrusted_parent", Severity: SeverityReview,
			Detail: "expected browser was launched by a parent that is not a known session, browser, or updater process",
		})
	}

	assessment := Assessment{Level: "review", Signals: signals}
	switch {
	case assessment.Has(SeverityHigh):
		assessment.Level = "high"
	case browserLayout && signed && len(signals) == 1:
		assessment.Level = "expected"
	}
	assessment.Families = associatedFamilies(signals)
	return assessment
}

func associatedFamilies(signals []Signal) []string {
	seen := map[string]bool{}
	for _, s := range signals {
		for _, family := range familiesForSignal[s.ID] {
			seen[family] = true
		}
	}
	out := make([]string, 0, len(seen))
	for _, family := range familyOrder {
		if seen[family] {
			out = append(out, family)
		}
	}
	return out
}

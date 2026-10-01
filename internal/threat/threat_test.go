package threat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cookieguard/internal/risk"
)

func TestUnknownBinaryIsReviewNotExpected(t *testing.T) {
	a := Assess(risk.ProcessInfo{PID: 1, Name: "unknown.exe", Path: `C:\Temp\unknown.exe`})
	if a.Level != "review" {
		t.Fatalf("unknown binary level = %q, want review", a.Level)
	}
	if !contains(a, "untrusted_cookie_access") || !contains(a, "unsigned_binary") {
		t.Fatalf("missing review signals: %+v", a.Signals)
	}
}

func TestRemoteDebuggingIsHigh(t *testing.T) {
	a := Assess(risk.ProcessInfo{
		PID: 2, Name: "chrome.exe", Path: `C:\Temp\chrome.exe`,
		CommandLine: `"C:\Temp\chrome.exe" --remote-debugging-port=9222 --user-data-dir="C:\Users\x\AppData\Local\Google\Chrome\User Data"`,
	})
	if a.Level != "high" {
		t.Fatalf("level = %q, want high", a.Level)
	}
	if !contains(a, "remote_debugging_switch") || !contains(a, "profile_argument") {
		t.Fatalf("missing debugging/profile signals: %+v", a.Signals)
	}
	if !hasFamily(a, "VoidStealer") {
		t.Fatalf("remote debugging should associate VoidStealer context: %+v", a.Families)
	}
}

func TestUserWritableLocation(t *testing.T) {
	for _, path := range []string{
		`C:\Users\x\AppData\Local\Temp\payload.exe`,
		`C:\Users\x\Downloads\setup.exe`,
		`C:\ProgramData\dropper.exe`,
	} {
		a := Assess(risk.ProcessInfo{Path: path})
		if !contains(a, "user_writable_binary") {
			t.Errorf("no user_writable_binary for %s", path)
		}
	}
	if contains(Assess(risk.ProcessInfo{Path: `C:\Program Files\Vendor\app.exe`}), "user_writable_binary") {
		t.Fatal("Program Files wrongly flagged as user-writable")
	}
}

func TestBrowserLayoutWithUntrustedParentIsReview(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramFiles", root)
	chrome := filepath.Join(root, `Google\Chrome\Application\chrome.exe`)
	if err := os.MkdirAll(filepath.Dir(chrome), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chrome, []byte("unsigned fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	// Layout matches but the fixture is not signed, so it must never be expected.
	a := Assess(risk.ProcessInfo{Path: chrome, Name: "chrome.exe", ParentName: "invoice.exe"})
	if a.Level == "expected" {
		t.Fatal("unsigned lookalike classified as expected")
	}
	if !contains(a, "browser_launched_by_untrusted_parent") {
		t.Fatalf("untrusted parent not flagged: %+v", a.Signals)
	}
	trusted := Assess(risk.ProcessInfo{Path: chrome, Name: "chrome.exe", ParentName: "explorer.exe"})
	if contains(trusted, "browser_launched_by_untrusted_parent") {
		t.Fatalf("explorer parent wrongly flagged: %+v", trusted.Signals)
	}
}

func TestAssessProcessSignals(t *testing.T) {
	// Unsigned process in a user-writable location -> review.
	a := AssessProcess(risk.ProcessInfo{Path: `C:\Users\x\AppData\Local\Temp\payload.exe`})
	if a.Level != "review" || !contains(a, "user_writable_binary") || !contains(a, "unsigned_binary") {
		t.Fatalf("unexpected assessment: %+v", a)
	}
	// Not user-writable -> info (ignored).
	if got := AssessProcess(risk.ProcessInfo{Path: `C:\Program Files\Vendor\app.exe`}); got.Level != "info" {
		t.Fatalf("non-user-writable process flagged: %+v", got)
	}
	// Remote debugging -> high even outside a user-writable path.
	high := AssessProcess(risk.ProcessInfo{Path: `C:\Program Files\Vendor\app.exe`, CommandLine: `app.exe --remote-debugging-port=9222`})
	if high.Level != "high" || !contains(high, "remote_debugging_switch") {
		t.Fatalf("expected high for remote debugging: %+v", high)
	}
	if !hasFamily(high, "VoidStealer") {
		t.Fatalf("missing family context: %+v", high.Families)
	}
}

func TestClassifyExpectedBrowserNotDowngraded(t *testing.T) { // A signed browser in its expected layout with only weak review hints must
	// stay "expected", otherwise normal browser self-access floods the log.
	weak := []Signal{{ID: "expected_browser", Severity: SeverityInfo}, {ID: "browser_launched_by_untrusted_parent", Severity: SeverityReview}}
	if got := classify(true, true, weak); got != "expected" {
		t.Fatalf("expected browser downgraded to %q", got)
	}
	high := append(append([]Signal{}, weak...), Signal{ID: "remote_debugging_switch", Severity: SeverityHigh})
	if got := classify(true, true, high); got != "high" {
		t.Fatalf("high signal ignored: %q", got)
	}
	if got := classify(true, false, weak); got != "review" {
		t.Fatalf("unsigned lookalike should be review, got %q", got)
	}
	if got := classify(false, true, weak); got != "review" {
		t.Fatalf("non-browser layout should be review, got %q", got)
	}
}

func TestCatalogIsCompleteAndSourced(t *testing.T) {
	catalog := Catalog()
	if len(catalog) != len(familyOrder) {
		t.Fatalf("catalog size %d, familyOrder %d", len(catalog), len(familyOrder))
	}
	seen := map[string]bool{}
	for _, family := range catalog {
		if family.Name == "" || family.Source == "" || len(family.Signals) == 0 {
			t.Fatalf("incomplete family entry: %+v", family)
		}
		seen[family.Name] = true
		for _, signal := range family.Signals {
			if len(familiesForSignal[signal]) == 0 {
				t.Fatalf("family %s references unknown signal %q", family.Name, signal)
			}
		}
	}
	for _, name := range familyOrder {
		if !seen[name] {
			t.Fatalf("familyOrder entry missing from catalog: %s", name)
		}
	}
	if len(TechniqueSources) == 0 {
		t.Fatal("no technique sources")
	}
}

func contains(a Assessment, id string) bool {
	for _, s := range a.Signals {
		if s.ID == id {
			return true
		}
	}
	return false
}

func hasFamily(a Assessment, name string) bool {
	for _, f := range a.Families {
		if f == name {
			return true
		}
	}
	return false
}

package browser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExactBrowserNames(t *testing.T) {
	for _, name := range []string{"chrome.exe", "CHROME.EXE", "msedge.exe", "firefox.exe", "brave.exe", "vivaldi.exe", "opera.exe"} {
		if !IsBrowserProcess(name) {
			t.Errorf("rejected %s", name)
		}
	}
	for _, name := range []string{"chrome_update.exe", "notfirefox.exe", "edge", "chrome.exe.bak", "mychrome.exe", "", `C:\Temp\chrome.exe`} {
		if IsBrowserProcess(name) {
			t.Errorf("accepted lookalike %s", name)
		}
	}
}

func TestDiscoverProfilesAndSidecars(t *testing.T) {
	root := t.TempDir()
	fixtures := []string{
		`AppData\Local\Google\Chrome\User Data\Profile 12\Network\Cookies`,
		`AppData\Local\Google\Chrome\User Data\Profile 12\Network\Cookies-wal`,
		`AppData\Local\Google\Chrome\User Data\Local State`,
		`AppData\Local\Google\Chrome\User Data\Default\Login Data`,
		`AppData\Local\Microsoft\Edge\User Data\Default\Cookies`,
		`AppData\Local\Microsoft\Edge\User Data\Local State`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release\cookies.sqlite`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\other.profile\cookies.sqlite-shm`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release\key4.db`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\abc.default-release\logins.json`,
	}
	for _, rel := range append(append([]string{}, fixtures...),
		`AppData\Local\Google\Chrome\User Data\Default\Network\Cookies.backup`,
		`AppData\Local\Google\Chrome\User Data\Default\History`) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := FindSensitivePaths(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != len(fixtures) {
		t.Fatalf("unexpected paths: %v", paths)
	}
	seen := make(map[string]bool)
	for _, p := range paths {
		seen[p] = true
	}
	for _, rel := range fixtures {
		if !seen[filepath.Join(root, rel)] {
			t.Errorf("missing %s", rel)
		}
	}
	paths, err = FindSensitivePaths(t.TempDir())
	if err != nil || len(paths) != 0 {
		t.Fatalf("empty profile: %v %v", paths, err)
	}
}

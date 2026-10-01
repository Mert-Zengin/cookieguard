package browser

import (
	"os"
	"path/filepath"
	"strings"
)

// sensitiveNames is the exact, lower-case file-name allowlist. Only browser
// state that infostealers are documented to target is included; the scanner
// never reads contents, so this is a monitoring scope, not a data collection.
var sensitiveNames = map[string]bool{
	"cookies": true, "cookies-wal": true, "cookies-shm": true, "cookies-journal": true,
	"cookies.sqlite": true, "cookies.sqlite-wal": true, "cookies.sqlite-shm": true, "cookies.sqlite-journal": true,
	// Chromium App-Bound Encryption key material and credential stores.
	"local state": true,
	"login data":  true, "login data-journal": true,
	"web data": true, "web data-journal": true,
	// Firefox credential stores.
	"key4.db": true, "logins.json": true,
}

var sensitivePatterns = []string{
	`AppData\Local\Google\Chrome\User Data\*\Network\Cookies*`,
	`AppData\Local\Google\Chrome\User Data\*\Cookies*`,
	`AppData\Local\Google\Chrome\User Data\Local State`,
	`AppData\Local\Google\Chrome\User Data\*\Login Data*`,
	`AppData\Local\Google\Chrome\User Data\*\Web Data*`,
	`AppData\Local\Microsoft\Edge\User Data\*\Network\Cookies*`,
	`AppData\Local\Microsoft\Edge\User Data\*\Cookies*`,
	`AppData\Local\Microsoft\Edge\User Data\Local State`,
	`AppData\Local\Microsoft\Edge\User Data\*\Login Data*`,
	`AppData\Local\Microsoft\Edge\User Data\*\Web Data*`,
	`AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Network\Cookies*`,
	`AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State`,
	`AppData\Local\Vivaldi\User Data\*\Network\Cookies*`,
	`AppData\Local\Vivaldi\User Data\Local State`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite*`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\*\key4.db`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\*\logins.json`,
	`AppData\Roaming\Opera Software\Opera Stable\Network\Cookies*`,
	`AppData\Roaming\Opera Software\Opera Stable\Local State`,
	`AppData\Roaming\Opera Software\Opera GX Stable\Network\Cookies*`,
	`AppData\Roaming\Opera Software\Opera GX Stable\Local State`,
}

// FindSensitivePaths returns cookie/credential files for the supported
// browsers under profilePath. Missing profiles are not an error; an empty
// result means "nothing to observe", never "safe".
func FindSensitivePaths(profilePath string) ([]string, error) {
	var paths []string
	seen := make(map[string]bool)
	for _, pattern := range sensitivePatterns {
		matches, err := filepath.Glob(filepath.Join(profilePath, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			if !sensitiveNames[strings.ToLower(filepath.Base(path))] {
				continue
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			key := strings.ToLower(path)
			if !seen[key] {
				paths = append(paths, path)
				seen[key] = true
			}
		}
	}
	return paths, nil
}

// IsBrowserProcess returns true only for an exact browser executable name.
func IsBrowserProcess(processName string) bool {
	switch strings.ToLower(processName) {
	case "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "vivaldi.exe", "opera.exe":
		return true
	default:
		return false
	}
}

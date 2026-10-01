package browser

import (
	"os"

	"path/filepath"
	"strings"
)

// FindCookiePaths returns paths to browser cookie files
func FindCookiePaths(profilePath string) ([]string, error) {
	var paths []string
	patterns := []string{
		`AppData\Local\Google\Chrome\User Data\*\Network\Cookies*`,
		`AppData\Local\Google\Chrome\User Data\*\Cookies*`,
		`AppData\Local\Microsoft\Edge\User Data\*\Network\Cookies*`,
		`AppData\Local\Microsoft\Edge\User Data\*\Cookies*`,
		`AppData\Local\BraveSoftware\Brave-Browser\User Data\*\Network\Cookies*`,
		`AppData\Local\Vivaldi\User Data\*\Network\Cookies*`,
		`AppData\Roaming\Mozilla\Firefox\Profiles\*\cookies.sqlite*`,
		`AppData\Roaming\Opera Software\Opera Stable\Network\Cookies*`,
		`AppData\Roaming\Opera Software\Opera GX Stable\Network\Cookies*`,
	}
	seen := make(map[string]bool)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(profilePath, pattern))
		if err != nil {
			return nil, err
		}
		for _, path := range matches {
			name := strings.ToLower(filepath.Base(path))
			if name != "cookies" && name != "cookies-wal" && name != "cookies-shm" && name != "cookies-journal" &&
				name != "cookies.sqlite" && name != "cookies.sqlite-wal" && name != "cookies.sqlite-shm" && name != "cookies.sqlite-journal" {
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

// IsBrowserProcess returns true if process is a browser
func IsBrowserProcess(processName string) bool {
	switch strings.ToLower(processName) {
	case "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "vivaldi.exe", "opera.exe":
		return true
	default:
		return false
	}
}

package browser

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// FindCookiePaths returns paths to browser cookie files
func FindCookiePaths(profilePath string) ([]string, error) {
	paths := []string{}

	// Chrome/Edge
	chromePaths := []string{
		filepath.Join(profilePath, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
		filepath.Join(profilePath, "AppData", "Local", "Google", "Chrome", "User Data", "Profile 1", "Network", "Cookies"),
	}

	edgePaths := []string{
		filepath.Join(profilePath, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Network", "Cookies"),
		filepath.Join(profilePath, "AppData", "Local", "Microsoft", "Edge", "User Data", "Profile 1", "Network", "Cookies"),
	}

	// Firefox
	firefoxPath := filepath.Join(profilePath, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "*.default", "cookies.sqlite")

	// Add to list if exists
	for _, path := range chromePaths {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	for _, path := range edgePaths {
		if _, err := os.Stat(path); err == nil {
			paths = append(paths, path)
		}
	}
	if _, err := os.Stat(firefoxPath); err == nil {
		paths = append(paths, firefoxPath)
	}

	return paths, nil
}

// IsBrowserProcess returns true if process is a browser
func IsBrowserProcess(processName string) bool {
	lowerName := strings.ToLower(processName)
	return strings.Contains(lowerName, "chrome") ||
		strings.Contains(lowerName, "edge") ||
		strings.Contains(lowerName, "firefox") ||
		strings.Contains(lowerName, "brave") ||
		strings.Contains(lowerName, "vivaldi")
}
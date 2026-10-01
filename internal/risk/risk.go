package risk

import (
	"os"
	"strings"
	"time"

	"github.com/cookieguard/internal/browser"
)

type ProcessInfo struct {
	PID   int
	Name  string
	Path  string
	IsBrowser bool
}

// IsAllowed returns true if process is allowed to access cookies
func IsAllowed(p ProcessInfo) bool {
	// Allow browser processes (Chrome, Edge, Firefox)
	if p.IsBrowser {
		return true
	}

	// Allow known system processes
	if strings.Contains(strings.ToLower(p.Path), "system32") || 
		systems.Contains(strings.ToLower(p.Path), "windows\system32") {
		return true
	}

	// Allow processes that are allowed by user (e.g., Chrome)
	if browser.IsBrowserProcess(p.Name) {
		return true
	}

	// Allow processes created within the last 5 minutes (common for legit apps)
	if p.CreatedAt.Before(time.Now().Add(-5 * time.Minute)) {
		return true
	}

	return false
}

// IsAllowedByUser returns true if user has explicitly allowed the process
func IsAllowedByUser(p ProcessInfo) bool {
	// In a real implementation, this would check a user-configured allowlist
	// For demo, we return false (user must manually allow)
	return false
}

// IsSuspicious returns true if process is suspicious
func IsSuspicious(p ProcessInfo) bool {
	// Check if process is not a browser and not a system process
	return !p.IsBrowser && !strings.Contains(strings.ToLower(p.Path), "system32")
}
// Package risk labels observations; it does not classify malware families.
package risk

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/cookieguard/internal/browser"
	"golang.org/x/sys/windows"
)

type ProcessInfo struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	StartTime   int64  `json:"start_time"`
	CommandLine string `json:"command_line,omitempty"`
	ParentPID   int    `json:"parent_pid,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	ParentPath  string `json:"parent_path,omitempty"`
}

// BrowserLocation requires an exact executable name and installation layout.
// A substring or a "system32" folder never grants trust.
func BrowserLocation(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	path = strings.ToLower(filepath.Clean(path))
	if !browser.IsBrowserProcess(filepath.Base(path)) {
		return false
	}
	for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
		if root == "" {
			continue
		}
		for _, rel := range []string{
			`Google\Chrome\Application\chrome.exe`, `Microsoft\Edge\Application\msedge.exe`,
			`Mozilla Firefox\firefox.exe`, `BraveSoftware\Brave-Browser\Application\brave.exe`,
			`Vivaldi\Application\vivaldi.exe`,
		} {
			if path == strings.ToLower(filepath.Clean(filepath.Join(root, rel))) {
				return true
			}
		}
	}
	return false
}

// ValidSignature checks embedded Authenticode trust offline. Catalog-only or
// unverifiable executables are not silently trusted. A signature does not
// prove benign behavior; injected browser code is outside this model.
func ValidSignature(path string) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	file := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p}
	data := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		UnionChoice: windows.WTD_CHOICE_FILE, StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&file),
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	return err == nil
}

func IsAllowed(p ProcessInfo) bool { return BrowserLocation(p.Path) && ValidSignature(p.Path) }

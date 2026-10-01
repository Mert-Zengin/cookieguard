package risk

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBrowserLocation(t *testing.T) {
	t.Setenv("ProgramFiles", `C:\Program Files`)
	t.Setenv("ProgramFiles(x86)", `C:\Program Files (x86)`)
	t.Setenv("LOCALAPPDATA", `C:\Users\fixture\AppData\Local`)
	for _, path := range []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`, `C:\Users\fixture\AppData\Local\Google\Chrome\Application\CHROME.EXE`} {
		if !BrowserLocation(path) {
			t.Errorf("rejected layout: %s", path)
		}
	}
	for _, path := range []string{`C:\Temp\chrome.exe`, `C:\Temp\system32\tool.exe`, `C:\Program Files Evil\Google\Chrome\Application\chrome.exe`, `C:\Program Files\Google\Chrome\Application\chrome_update.exe`, `chrome.exe`, ""} {
		if BrowserLocation(path) {
			t.Errorf("accepted unsafe layout: %s", path)
		}
	}
}

func TestUnsignedFileNeverAllowed(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ProgramFiles", root)
	file := filepath.Join(root, `Google\Chrome\Application\chrome.exe`)
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("not an executable or a signature"), 0600); err != nil {
		t.Fatal(err)
	}
	if !BrowserLocation(file) {
		t.Fatal("fixture should match layout")
	}
	if IsAllowed(ProcessInfo{Path: file, Name: "chrome.exe"}) {
		t.Fatal("unsigned lookalike allowed")
	}
	if ValidSignature(filepath.Join(root, "missing")) {
		t.Fatal("missing file signature accepted")
	}
}

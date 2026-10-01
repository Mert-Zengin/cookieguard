package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/cookieguard/internal/browser"
	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/risk"
	"github.com/cookieguard/internal/watcher"
	"github.com/cookieguard/internal/notify"
)

var (
	installFlag = flag.Bool("install", false, "Install as startup (HKCU\Run)")
	uninstallFlag = flag.Bool("uninstall", false, "Uninstall from startup")
	scanFlag = flag.Bool("scan", false, "Scan for active cookie access")
)

func main() {
	flag.Parse()

	if *installFlag {
		install()
		return
	}

	if *uninstallFlag {
		uninstall()
		return
	}

	if *scanFlag {
		handle.ScanAll()
		return
	}

	// Start monitoring
	user, _ := user.Current()
	profilePath := user.HomeDir

	// Find browser cookie paths
	cookiePaths, err := browser.FindCookiePaths(profilePath)
	if err != nil {
		fmt.Printf("Error finding cookie paths: %v\n", err)
		os.Exit(1)
	}

	// Start watcher
	w := watcher.New(cookiePaths)
	if err := w.Start(); err != nil {
		fmt.Printf("Watcher error: %v\n", err)
		os.Exit(1)
	}

	// Wait for signals
	fmt.Println("Monitoring browser cookies... Press Ctrl+C to exit")
	select {}
}

func install() {
	user, _ := user.Current()
	cookieguardPath := filepath.Join(os.Getenv("GOPATH"), "bin", "cookieguard.exe")

	// Add to HKCU\Run
	hkey := "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
	keyName := "CookieGuard"

	cmd := fmt.Sprintf(`reg add "%s" /v "%s" /t REG_SZ /d "%s" /f`, hkey, keyName, cookieguardPath)

	if err := exec.Command("cmd", "/c", cmd).Run(); err != nil {
		fmt.Printf("Failed to install: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Installed as startup (HKCU\Run)")
}

func uninstall() {
	hkey := "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
	keyName := "CookieGuard"

	cmd := fmt.Sprintf(`reg delete "%s" /v "%s" /f`, hkey, keyName)

	if err := exec.Command("cmd", "/c", cmd).Run(); err != nil {
		fmt.Printf("Failed to uninstall: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Uninstalled from startup")
}
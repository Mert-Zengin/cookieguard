// Command simulate is a BENIGN behaviour simulator for testing CookieGuard. It
// opens and reads browser-data files the same way an infostealer does, but it
// never exfiltrates, never persists, and never modifies anything. It only reads
// files you explicitly point it at, and it refuses to run without --yes.
//
// Use it inside an isolated VM or Windows Sandbox against synthetic files. Do
// not point it at a profile that holds real sessions.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cookieguard/internal/browser"
)

func main() {
	file := flag.String("file", "", "single file to open (synthetic)")
	profile := flag.String("profile", "", "discover browser data under this profile directory")
	hold := flag.Duration("hold", 8*time.Second, "how long to keep the readable handles open")
	debugPort := flag.Int("remote-debugging-port", 0, "if set, keeps handles open and simulates a debugging-style access")
	yes := flag.Bool("yes", false, "confirm you are running against synthetic data in an isolated environment")
	flag.Parse()

	if !*yes {
		fmt.Fprintln(os.Stderr, "refusing to run: pass --yes to confirm this is a synthetic, isolated test")
		os.Exit(2)
	}
	if *profile == "" && *file == "" {
		if home, err := os.UserHomeDir(); err == nil {
			*profile = home
		}
	}

	var targets []string
	if *file != "" {
		abs, err := filepath.Abs(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "path:", err)
			os.Exit(1)
		}
		targets = []string{abs}
	} else {
		found, err := browser.FindSensitivePaths(*profile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "discover:", err)
			os.Exit(1)
		}
		targets = found
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no browser-data files found; create some with tools/fakecookies")
		os.Exit(1)
	}

	if *debugPort != 0 {
		fmt.Printf("simulating a remote-debugging-style access (port %d)\n", *debugPort)
	}

	handles := make([]*os.File, 0, len(targets))
	defer func() {
		for _, h := range handles {
			h.Close()
		}
	}()
	buf := make([]byte, 16)
	for _, path := range targets {
		f, err := os.Open(path)
		if err != nil {
			fmt.Println("skip:", path, err)
			continue
		}
		n, _ := f.Read(buf) // read a few bytes; no exfiltration
		handles = append(handles, f)
		fmt.Printf("opened+read %d bytes: %s\n", n, path)
	}
	fmt.Printf("holding %d readable handle(s) for %s (CookieGuard should observe this)\n", len(handles), *hold)
	time.Sleep(*hold)
	fmt.Println("releasing handles; done")
}

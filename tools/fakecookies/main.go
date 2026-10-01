// Command fakecookies creates a synthetic browser-data layout so CookieGuard can
// be tested in a clean VM without logging into any real account. It only creates
// small dummy files and never writes to an existing file.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

var files = []string{
	`AppData\Local\Google\Chrome\User Data\Default\Network\Cookies`,
	`AppData\Local\Google\Chrome\User Data\Local State`,
	`AppData\Local\Google\Chrome\User Data\Default\Login Data`,
	`AppData\Local\Google\Chrome\User Data\Default\Web Data`,
	`AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies`,
	`AppData\Local\Microsoft\Edge\User Data\Local State`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\sandbox.default\cookies.sqlite`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\sandbox.default\key4.db`,
	`AppData\Roaming\Mozilla\Firefox\Profiles\sandbox.default\logins.json`,
}

func main() {
	profile := flag.String("profile", "", "target user profile directory (e.g. C:\\Users\\sandbox)")
	flag.Parse()
	if *profile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			*profile = home
		}
	}
	if *profile == "" {
		fmt.Fprintln(os.Stderr, "no profile directory; pass -profile")
		os.Exit(2)
	}
	created := 0
	for _, rel := range files {
		full := filepath.Join(*profile, rel)
		if _, err := os.Stat(full); err == nil {
			fmt.Println("skip (exists):", full)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir:", err)
			os.Exit(1)
		}
		// Dummy content: this is not a real cookie database.
		if err := os.WriteFile(full, []byte("CookieGuard sandbox fixture; not real data\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write:", err)
			os.Exit(1)
		}
		fmt.Println("created:", full)
		created++
	}
	fmt.Printf("done: %d file(s) created under %s\n", created, *profile)
}

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/cookieguard/internal/browser"
	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/notify"
	"github.com/cookieguard/internal/proc"
	"github.com/cookieguard/internal/watcher"
	"golang.org/x/sys/windows/registry"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, diagnostics io.Writer) error {
	command := "run"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		command, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("cookieguard "+command, flag.ContinueOnError)
	fs.SetOutput(diagnostics)
	lang := fs.String("lang", "tr", "Output language: tr or en")
	interval := fs.Duration("interval", 5*time.Second, "Delay between scans (minimum 100ms)")
	profile := fs.String("profile", "", "Windows user profile directory")
	file := fs.String("file", "", "Observe one explicitly selected file instead of browser profiles")
	jsonOutput := fs.Bool("json", false, "Emit JSON Lines instead of text")
	includeBrowsers := fs.Bool("include-browsers", false, "Also report expected browser access")
	logPath := fs.String("log", "", "Append local JSON Lines events to this file (contains paths, not cookies)")
	desktop := fs.Bool("notify", false, "Show rate-limited Windows review alerts")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *lang != "tr" && *lang != "en" {
		return errors.New("--lang must be tr or en")
	}
	message := func(tr, en string) string {
		if *lang == "tr" {
			return tr
		}
		return en
	}
	switch command {
	case "version":
		fmt.Fprintln(out, "CookieGuard", version)
		return nil
	case "install":
		if err := install(*lang); err != nil {
			return err
		}
		fmt.Fprintln(out, message("Oturum açılışına eklendi; mevcut EXE konumunu değiştirmeyin. Yönetici yetkisi vermez.", "Added to login startup; do not move this EXE. Does not grant administrator rights."))
		return nil
	case "uninstall":
		if err := uninstall(); err != nil {
			return err
		}
		fmt.Fprintln(out, message("Oturum açılışı kaydı kaldırıldı.", "Login startup entry removed."))
		return nil
	case "run", "scan":
	default:
		return fmt.Errorf("unknown command %q (run, scan, version, install, uninstall)", command)
	}
	if command == "run" && *interval < 100*time.Millisecond {
		return errors.New("scan interval must be at least 100ms")
	}
	if *profile == "" {
		var err error
		*profile, err = os.UserHomeDir()
		if err != nil {
			return err
		}
	}
	discover := func() ([]string, error) {
		if *file != "" {
			p, err := filepath.Abs(*file)
			if err != nil {
				return nil, err
			}
			info, err := os.Stat(p)
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, errors.New("--file must be a regular file")
			}
			return []string{p}, nil
		}
		return browser.FindCookiePaths(*profile)
	}
	paths, err := discover()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New(message("Çerez dosyası bulunamadı. --profile veya test için --file kullanın.", "No cookie files found. Use --profile or --file for a test."))
	}
	fmt.Fprintln(diagnostics, message("Gözlem modu: hırsızlığı kesin olarak engellemez; kısa erişimleri kaçırabilir.", "Observation mode: does not guarantee prevention; may miss short-lived access."))
	if !proc.IsElevated() {
		fmt.Fprintln(diagnostics, message("Yönetici yetkisi yok: diğer kullanıcıların ve korumalı işlemlerin kapsamı sınırlı.", "Not elevated: coverage of other users and protected processes is limited."))
	}
	if command == "scan" {
		var scanner handle.Scanner
		report, err := scanner.Scan(paths)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var eventLog *os.File
	if *logPath != "" {
		if err := os.MkdirAll(filepath.Dir(*logPath), 0700); err != nil {
			return err
		}
		eventLog, err = os.OpenFile(*logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer eventLog.Close()
	}
	var alerts *notify.Desktop
	if *desktop {
		alerts = notify.NewDesktop(ctx)
	}
	fmt.Fprintf(diagnostics, "%s: %d; Ctrl+C\n", message("İzlenen dosyalar", "Observed files"), len(paths))
	lastStatus := ""
	w := watcher.Watcher{
		Interval: *interval, Discover: discover, IncludeBrowsers: *includeBrowsers,
		Status: func(r handle.Report) {
			status := fmt.Sprintf("%d/%d/%d/%d", r.TargetsAvailable, r.InaccessibleProcesses, r.UnresolvedHandles, len(r.UnavailableTargets))
			if status != lastStatus {
				fmt.Fprintf(diagnostics, "%s: observed_files=%d inaccessible_processes=%d unresolved_handles=%d unavailable_files=%d\n", message("Tarama kapsamı", "Scan coverage"), r.TargetsAvailable, r.InaccessibleProcesses, r.UnresolvedHandles, len(r.UnavailableTargets))
				lastStatus = status
			}
		},
		Emit: func(e watcher.Event) error {
			if eventLog != nil {
				if err := json.NewEncoder(eventLog).Encode(e); err != nil {
					return err
				}
			}
			if alerts != nil && e.Kind == "review_access" {
				alerts.Show("CookieGuard", fmt.Sprintf("%s\nPID=%d\nEXE=%s\nFILE=%s", message("İncelenmesi gereken dosya erişimi. Saldırı kanıtı değildir.", "File access to review. This is not proof of an attack."), e.Process.PID, e.Process.Path, e.File))
			}
			if *jsonOutput {
				return json.NewEncoder(out).Encode(e)
			}
			label := message("İNCELE: okunabilir dosya erişimi (tek başına saldırı kanıtı değil)", "REVIEW: readable file access (not proof of an attack)")
			if e.Kind == "browser_access" {
				label = message("Beklenen tarayıcı erişimi", "Expected browser access")
			}
			_, err := fmt.Fprintf(out, "[%s] %s PID=%d EXE=%q FILE=%q\n", e.Time.Format(time.RFC3339), label, e.Process.PID, e.Process.Path, e.File)
			return err
		},
	}
	return w.Run(ctx)
}

const startupKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func install(lang string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	log := filepath.Join(cache, "CookieGuard", "events.jsonl")
	key, _, err := registry.CreateKey(registry.CURRENT_USER, startupKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue("CookieGuard", `"`+exe+`" run --lang `+lang+` --notify --log "`+log+`"`)
}

func uninstall() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, startupKey, registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	err = key.DeleteValue("CookieGuard")
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}

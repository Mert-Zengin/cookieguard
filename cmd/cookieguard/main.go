package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/cookieguard/assets"
	"github.com/cookieguard/internal/browser"
	"github.com/cookieguard/internal/enforce"
	"github.com/cookieguard/internal/handle"
	"github.com/cookieguard/internal/notify"
	"github.com/cookieguard/internal/proc"
	"github.com/cookieguard/internal/threat"
	"github.com/cookieguard/internal/tray"
	"github.com/cookieguard/internal/watcher"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var version = "dev"

func main() {
	// Make Turkish/English diagnostics render correctly in the Windows console.
	if err := windows.SetConsoleOutputCP(65001); err == nil {
		_ = windows.SetConsoleCP(65001)
	}
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
	trayIcon := fs.Bool("tray", true, "Show a notification-area (taskbar tray) icon while running")
	protect := fs.Bool("protect", false, "OPT-IN: terminate processes that match a high-severity technique")
	protectReview := fs.Bool("protect-review", false, "OPT-IN, more aggressive: also terminate unsigned binaries running from user-writable locations")
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
	case "threats":
		return json.NewEncoder(out).Encode(struct {
			Families  []threat.Family `json:"families"`
			Technique []string        `json:"technique_sources"`
		}{threat.Catalog(), threat.TechniqueSources})
	case "run", "scan":
	default:
		return fmt.Errorf("unknown command %q (run, scan, version, install, uninstall, threats)", command)
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
		return browser.FindSensitivePaths(*profile)
	}
	paths, err := discover()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New(message("Tarayıcı çerez/kimlik dosyası bulunamadı. --profile veya test için --file kullanın.", "No browser cookie/credential files found. Use --profile or --file for a test."))
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
	if *protect || *protectReview {
		fmt.Fprintln(diagnostics, message(
			"ENGEL MODU AÇIK: yalnızca yüksek/uygun sinyalde işlem sonlandırılır. Yanlış pozitif meşru bir aracı kapatabilir. Varsayılan kapalıdır, kendi sorumluluğunuzda kullanın.",
			"ENFORCEMENT ON: processes are terminated only on high/qualifying signals. A false positive can close a legitimate tool. Off by default; use at your own risk."))
	}
	resolvedLog := *logPath
	if resolvedLog == "" {
		if cache, err := os.UserCacheDir(); err == nil {
			resolvedLog = filepath.Join(cache, "CookieGuard", "events.jsonl")
		}
	}
	var trayIconHandle *tray.Tray
	if *trayIcon && !*jsonOutput {
		if t, err := tray.Start(tray.Options{
			Tooltip:   message("CookieGuard çalışıyor (gözlem)", "CookieGuard running (observing)"),
			IconBytes: assets.Icon,
			Balloon:   message("CookieGuard çalışıyor. Simgeyi görmek için bildirim alanındaki ^ okuna bakın.", "CookieGuard is running. Look at the ^ arrow in the notification area if you do not see the icon."),
			Items: []tray.MenuItem{
				{ID: 1, Label: message("Kayıt dosyasını aç", "Open event log")},
				{ID: 2, Label: message("Kayıt klasörünü aç", "Open log folder")},
				{Separator: true},
				{ID: 3, Label: message("Çıkış", "Quit")},
			},
			OnSelect: func(id int) {
				switch id {
				case 1:
					openPath(resolvedLog)
				case 2:
					openPath(filepath.Dir(resolvedLog))
				case 3:
					stop()
				}
			},
			OnDoubleClick: func() { openPath(resolvedLog) },
		}); err == nil {
			trayIconHandle = t
			defer trayIconHandle.Close()
		} else {
			fmt.Fprintf(diagnostics, "%s: %v\n", message("Tepsi simgesi başlatılamadı", "Tray icon failed to start"), err)
		}
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
				alerts.Show("CookieGuard", fmt.Sprintf("%s\n%s\nPID=%d\nEXE=%s\nFILE=%s", message("İncelenmesi gereken dosya erişimi. Saldırı kanıtı değildir.", "File access to review. This is not proof of an attack."), signalSummary(e), e.Process.PID, e.Process.Path, e.File))
			}
			if *protect || *protectReview {
				decision := enforce.Decide(e.Process.PID, e.Process.Name, e.Level, e.Signals, true, *protectReview)
				if decision.Terminate {
					killErr := proc.Kill(uint32(e.Process.PID))
					record := action{
						Time: time.Now().UTC(), Kind: "terminate", PID: e.Process.PID,
						Path: e.Process.Path, Reason: decision.Reason,
					}
					if killErr != nil {
						record.Error = killErr.Error()
					}
					if eventLog != nil {
						_ = json.NewEncoder(eventLog).Encode(record)
					}
					fmt.Fprintf(diagnostics, "%s PID=%d EXE=%q REASON=%s ERR=%v\n",
						message("ENGELLENDİ", "BLOCKED"), record.PID, record.Path, record.Reason, killErr)
				}
			}
			if *jsonOutput {
				return json.NewEncoder(out).Encode(e)
			}
			label := message("İNCELE: okunabilir dosya erişimi (tek başına saldırı kanıtı değil)", "REVIEW: readable file access (not proof of an attack)")
			if e.Kind == "browser_access" {
				label = message("Beklenen tarayıcı erişimi", "Expected browser access")
			}
			if e.Level == "high" {
				label = message("YÜKSEK ÖNCELİK: belgelenmiş bir hırsızlık tekniğiyle uyumlu", "HIGH: matches a documented theft technique")
			}
			_, err := fmt.Fprintf(out, "[%s] %s PID=%d EXE=%q FILE=%q SIGNALS=%s\n", e.Time.Format(time.RFC3339), label, e.Process.PID, e.Process.Path, e.File, signalSummary(e))
			return err
		},
	}
	return w.Run(ctx)
}

// action is a local record of an enforcement decision and its outcome.
type action struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`
	PID    int       `json:"pid"`
	Path   string    `json:"path"`
	Reason string    `json:"reason"`
	Error  string    `json:"error,omitempty"`
}

// openPath opens a file or folder with the user's default handler. It never
// runs a shell string; arguments are passed separately.
func openPath(path string) {
	if path == "" {
		return
	}
	_ = exec.Command("cmd", "/c", "start", "", path).Start()
}

const startupKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func signalSummary(e watcher.Event) string {
	if len(e.Signals) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(e.Signals))
	for _, s := range e.Signals {
		parts = append(parts, s.ID+":"+string(s.Severity))
	}
	return strings.Join(parts, ",")
}

func install(lang string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Prefer a windowless build for login startup so no console window appears;
	// fall back to this executable when it is not present.
	if gui := filepath.Join(filepath.Dir(exe), "cookieguard-tray.exe"); fileExists(gui) {
		exe = gui
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

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
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

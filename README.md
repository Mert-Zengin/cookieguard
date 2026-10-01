<div align="center">

<img src="assets/cookieguard.png" width="96" alt="CookieGuard shield logo">

# CookieGuard

**Windows browser-cookie & credential access monitor — defensive security.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](#)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8.svg?logo=go&logoColor=white)](go.mod)
[![Release](https://img.shields.io/github/v/release/Mert-Zengin/cookieguard?sort=semver&label=release)](https://github.com/Mert-Zengin/cookieguard/releases)
[![Stars](https://img.shields.io/github/stars/Mert-Zengin/cookieguard?style=social)](https://github.com/Mert-Zengin/cookieguard/stargazers)

Observes processes holding readable handles to browser cookies and credential
stores. **Not an antivirus, not an access-control driver, and not a guarantee
against cookie theft.** It shows a tray icon, opens a live window on
double-click, and offers opt-in enforcement.

</div>

> [!WARNING]
> This is an **observation** tool. Enforcement is off by default, can end a
> legitimate process, and does not intercept a read that already happened.
> **Empty output never means "safe".** CookieGuard is not a substitute for
> Microsoft Defender or your endpoint protection.

## Contents

- [Quick start](#quick-start)
- [What works](#what-works)
- [Limits](#limits--read-before-relying-on-this-tool)
- [Threat signals](#threat-signals-and-sources)
- [Window (GUI)](#window-gui)
- [Tray icon](#tray-icon)
- [Enforcement](#enforcement-opt-in-off-by-default)
- [Sandbox testing without malware](#sandbox-testing-without-malware)
- [Icons, builds, and code signing](#icons-builds-and-code-signing)
- [Tests](#tests)
- [Türkçe](#türkçe)

## Quick start

Download the latest [release](https://github.com/Mert-Zengin/cookieguard/releases)
(`cookieguard.exe` + `cookieguard-tray.exe`) or build it yourself:

```powershell
./build.ps1 -Version v1.3.2
```

| I want to… | Command |
|---|---|
| Open a live window + tray icon | double-click `cookieguard-tray.exe` (or `.\cookieguard.exe gui`) |
| Run quietly in the tray | `.\cookieguard-tray.exe run --lang en` |
| One-shot scan (JSON on stdout) | `.\cookieguard.exe scan --lang en` |
| Print the documented threat catalog | `.\cookieguard.exe threats` |
| Add to login startup | `.\cookieguard.exe install` |
| Turn on enforcement (opt-in) | add `--protect` (high only) or `--protect-review` |
| Test safely without malware | `./sandbox/prepare.ps1` (see [Sandbox testing](#sandbox-testing-without-malware)) |

## What works

- Periodic native Windows handle enumeration (`NtQuerySystemInformation`),
  rather than filesystem-change notifications that cannot observe reads.
- File matching by volume and file identity, including hard links. Files are
  reopened and profiles rediscovered on every scan to handle replacement.
- Chrome, Edge, Firefox, Brave, Vivaldi, and common Opera cookie locations;
  Chromium profile directories and Firefox profile suffixes are not hardcoded.
- Cookie database WAL, SHM, and journal sidecars are included.
- Exact browser executable names, expected installation layouts, and embedded
  Authenticode verification before labeling access as expected browser access.
  Name substrings and `system32` locations do not grant trust.
- Browser-data scope beyond cookies: `Local State` (Chromium encryption key
  material), `Login Data`, `Web Data`, and Firefox `key4.db`/`logins.json`.
- Behavior signals derived from public infostealer reporting: untrusted-binary
  access, unsigned binaries, user-writable/temporary locations, Chromium
  remote-debugging switches, browser-profile arguments, and unexpected browser
  parents. Signals explain *why* an access is interesting; they do not name a
  malware family.
- Review alerts, optional Windows dialogs, optional local JSON Lines logs.
  Repeated observations are deduplicated while continuously visible.
- Explicit coverage-gap counters and English/Turkish operational messages.
- Login startup entry using the Windows registry API, not a shell command.
- A notification-area (tray) icon with menu entries to open the log, open the
  log folder, and quit, so it is visible that the monitor is running.
- A native window (`gui` command, or just double-click) that shows live events,
  scan coverage, and a button to turn enforcement on/off at runtime.
- Opt-in enforcement (`--protect`, `--protect-review`) that terminates a process
  only on configured high-confidence signals, never critical Windows processes,
  and logs every action. Off by default.

## Limits — read before relying on this tool

| Capability | Current status |
|---|---|
| Observe a readable file handle still open during a scan | Implemented; synthetic Windows integration tests |
| Prove file contents were read or stolen | Not supported |
| Opt-in termination on a high-confidence signal | Implemented and live-tested; not true read-time prevention |
| Reliably catch short-lived reads between scans | Not supported |
| Detect a browser started with remote-debugging switches | Signal implemented (`remote_debugging_switch`, high) |
| Detect browser injection or in-memory scraping | Not implemented |
| Attribute an access to Lumma, RedLine, Vidar, Raccoon, Agent Tesla, Rhadamanthys, Gremlin, DarkCloud, VoidStealer, Epsilon, or Rakhni | Not supported; only shared technique context |
| Zero false positives, <1% CPU, <5 MiB RAM | Not guaranteed; measure on your machine |

An observation is **not proof of malware**. Antivirus, backup, migration, and
other legitimate software may access these files. By default CookieGuard does
not kill processes or change cookie permissions or security policies;
enforcement only happens if you explicitly enable `--protect`/`--protect-review`.

Expected browser access is hidden by default. Use `--include-browsers` to see it.
A valid signature and familiar path are heuristics, not attestation of running
code or verification of a particular publisher. Offline verification may fail
for legitimate binaries (for example catalog-only signatures or unavailable
trust data); these accesses remain visible for review. Injected code can still
operate inside a signed browser.

Run with administrator rights for broader coverage, but protected processes,
other users, exited processes, and failed handle resolutions can remain outside
coverage. **Empty observations never mean the machine is safe.** Scanning uses
undocumented native table layouts and needs testing on each supported Windows
version. File metadata queries can be delayed by storage/network drivers;
cancellation takes effect between scans, not during a blocked native query.
The interval is a delay *after* each scan, not a guaranteed detection latency.

The system handle buffer is reused and capped at 64 MiB; parsing and Go runtime
memory are additional. CPU and memory depend on system handle counts. Smaller
intervals increase work and still cannot guarantee prevention.

## Troubleshooting

- **I only see my browser reading its own files.** That is normal. A signed
  browser in its expected layout is hidden by default; run with
  `--include-browsers` if you want to see it. After v1.3.2, a weak hint such as
  an unusual parent no longer downgrades an expected browser, so normal
  self-access stops flooding the log.
- **A known stealer or the simulator was not detected.** Most likely the file
  handle was opened and closed between two scans; a one-shot read can always be
  missed. Lower `--interval` (e.g. `250ms`) and keep the process reading/holding
  the file longer. True read-time coverage needs an access-audit or minifilter
  design (see below).
- **`unsigned_binary` shows for a legitimate program.** Offline Authenticode
  verification can fail for catalog-only or trust-unavailable binaries; treat it
  as a review hint, not a verdict.

## Threat signals and sources

Signals are severity-ranked and explainable. `high` means the observation matches
a specifically documented theft technique (currently Chromium remote-debugging
switches). `review` means the access deserves a look but has legitimate
explanations. `expected` means a signed binary in a known browser layout.

| Signal | Meaning | Public technique reference |
|---|---|---|
| `untrusted_cookie_access` | Non-browser binary holds a readable handle | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) |
| `unsigned_binary` | No verifiable embedded signature (offline) | Family sourcing below |
| `user_writable_binary` | Runs from Temp/Downloads/ProgramData | Family sourcing below |
| `remote_debugging_switch` | `--remote-debugging-*` on the command line | [Elastic](https://www.elastic.co/guide/en/security/8.19/potential-cookies-theft-via-browser-debugging.html), [Red Canary](https://redcanary.com/blog/threat-intelligence/google-chrome-app-bound-encryption/) |
| `profile_argument` | Command line points at a browser profile | ABE-bypass research below |
| `browser_launched_by_untrusted_parent` | Browser started by a non-session/browser parent | Family sourcing below |

Documented families used for context only (never attribution):
Lumma ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)),
RedLine ([Microsoft WDSI](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:Win32/RedLineStealer!rfn&ThreatID=2147817010)),
Vidar ([Unit 42](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)),
Raccoon ([MITRE S1148](https://attack.mitre.org/software/S1148/)),
Agent Tesla ([Fortinet](https://www.fortinet.com/blog/threat-research/unmasking-agent-tesla-deep-dive-into-multi-stage-campaign)),
Rhadamanthys ([Check Point](https://blog.checkpoint.com/research/rhadamanthys-0-9-2-a-stealer-that-keeps-evolving/)),
Gremlin ([Unit 42](https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/)),
DarkCloud ([Unit 42](https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/)),
VoidStealer ([Gen Digital](https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass)),
Epsilon ([Malpedia](https://malpedia.caad.fkie.fraunhofer.de/details/win.epsilon_stealer)).
Run `cookieguard threats` for the machine-readable catalog.

## Window (GUI)

Double-clicking `cookieguard.exe` (or `cookieguard-tray.exe`) with no arguments
opens a native window; `cookieguard.exe gui` does the same from a terminal. The
window shows:

- a status line with how many files are observed and how many processes/handles
  were inaccessible or unresolved (coverage gaps, not "safe");
- a live list of access events with time, level, PID, executable, file, and
  signals;
- buttons: **Koruma: kapali/ac** (toggle enforcement live), **Kaydi Ac** (open
  the log), **Temizle** (clear the view), **Cikis** (quit).

The window does not change what is monitored; enforcement stays off until you
either pass `--protect`/`--protect-review` or click the toggle. A false positive
can close a legitimate tool.

## Tray icon

While `run` is active (and stdout is not `--json`), CookieGuard shows a
notification-area icon with a right-click menu: open the event log, open the log
folder, and quit. A double-click opens the log. Windows 11 hides new tray icons
by default — click the `^` arrow and drag the CookieGuard icon onto the taskbar
to keep it visible. The windowless `cookieguard-tray.exe` build is intended for
`install` so no console window appears at login.

## Enforcement (opt-in, off by default)

User-mode monitoring cannot intercept a read that already happened, so
enforcement is deliberately limited and off by default:

- `--protect` terminates a process only when the assessment is `high` (currently
  the Chromium remote-debugging technique).
- `--protect-review` additionally terminates a process that is both unsigned and
  running from a user-writable location while holding a readable handle.
- Critical Windows processes (`lsass.exe`, `explorer.exe`, `MsMpEng.exe`, …),
  PID 0–4, and CookieGuard itself are never terminated.
- Every decision is written to the log as a `terminate` record with the reason
  and any error.

A false positive can close a legitimate tool (for example a backup or migration
utility). Use it only if you accept that risk. Terminating another user's or a
protected process requires administrator rights.

## Sandbox testing without malware

You do **not** need a real malware sample to validate CookieGuard. Two built-in
tools reproduce stealer-like behaviour on synthetic files only:

```powershell
# 1) Build the Windows Sandbox test kit and generate a .wsb config
./sandbox/prepare.ps1 -Version v1.3.2
# 2) Double-click sandbox\CookieGuard.generated.wsb
```

Inside the sandbox, `run-test.ps1` creates fake browser data, starts CookieGuard,
and runs the benign simulator in observation mode and then with `--protect-review`.
Alternatively, on any isolated VM:

```powershell
go run ./tools/fakecookies -profile $env:USERPROFILE      # synthetic cookies + Local State
go run ./tools/simulate   --profile $env:USERPROFILE --yes  # opens+reads them, holds handles
# optional: simulate a debugging-style access (triggers the high signal)
go run ./tools/simulate   --remote-debugging-port 9222 --hold 20s --yes
```

`tools/simulate` only opens and reads files you point it at; it never
exfiltrates, persists, or modifies anything, and refuses to run without `--yes`.
One caveat observed in live testing: an unsigned process may be reported as
`unsigned_binary` because offline Authenticode verification can fail for
legitimate binaries. See [docs/SANDBOX_TESTING.md](docs/SANDBOX_TESTING.md) for
a real-sample workflow in an isolated VM or Any.Run (never on a real machine).

## Icons, builds, and code signing

```powershell
./build.ps1 -Version v1.3-dev
```

`build.ps1` regenerates the icon, resource file, runs tests and vet, and produces
`cookieguard.exe` (console) and `cookieguard-tray.exe` (windowless). The icon
(`assets/cookieguard.ico`) and manifest are drawn from code and embedded with
`github.com/akavel/rsrc`; the generated `rsrc.syso` is not committed.

This project does **not** ship a real code-signing certificate. Signing requires a
trusted certificate you own:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f your-cert.pfx cookieguard.exe
```

Until it is signed, Windows SmartScreen may warn on first run. A self-signed
certificate only silences the warning on machines that trust it; do not present
that as trusted signing.

## Build and use (Windows, Go 1.26.0+)

```powershell
go test ./...
go vet ./...
go build -trimpath -ldflags "-X main.version=v1.3.2" -o cookieguard.exe ./cmd/cookieguard
.\cookieguard.exe version
.\cookieguard.exe gui          # opens the window
.\cookieguard.exe run --lang en
```

| Command / option | Meaning |
|---|---|
| `run` (or no command) | Observe the current user's discovered cookie files |
| `gui` | Same as `run` but with a live window (also the default on double-click) |
| `scan` | Single scan; report and coverage counters as JSON on stdout |
| `version` | Print embedded build version |
| `threats` | Print the documented family/technique catalog and sources as JSON |
| `install` / `uninstall` | Add/remove this EXE's current-user login startup entry |
| `--lang tr` / `--lang en` | Operational message language (default: Turkish) |
| `--interval 5s` | Delay between scans (default: 5s, minimum: 100ms) |
| `--profile "C:\Users\Example"` | Select another Windows user profile |
| `--file "C:\path\synthetic-file"` | Observe one explicitly selected file |
| `--include-browsers` | Also emit expected browser observations |
| `--json` | Run-mode events as JSON Lines |
| `--log "C:\path\events.jsonl"` | Append run-mode events to a local log |
| `--notify` | Show review dialogs; at most one open, rate-limited to 30s |
| `--tray` | Show the notification-area icon (default true; `--tray=false` to disable) |
| `--protect` | OPT-IN: terminate a process only when a high-severity signal matches |
| `--protect-review` | OPT-IN, aggressive: also terminate unsigned binaries from user-writable locations |
| `--help` | List flags |

Example:

```powershell
.\cookieguard.exe run --lang en --json --notify --log "$env:LOCALAPPDATA\CookieGuard\events.jsonl"
.\cookieguard.exe scan --lang en
.\cookieguard.exe install
# To stop running: Ctrl+C. Removing startup does not stop an existing process.
.\cookieguard.exe uninstall
```

Installing is optional and is **not** done by the build or tests. Keep the EXE at
the same location after installation. Startup runs in observation mode with
dialogs and a log at `%LOCALAPPDATA%\CookieGuard\events.jsonl`; it does not request
elevation or install a service. Logs append without automatic rotation; monitor
disk usage. Uninstall removes only the startup entry and preserves logs.

Diagnostics go to stderr, leaving JSON stdout machine-readable. Logs include
process paths, file paths (possibly usernames), PID, start time, access rights,
event time and event kind. Cookie contents are never read, decrypted, logged,
or transmitted. CookieGuard has no telemetry. Logs are not tamper-resistant.

## Tests

```powershell
go test -v ./...
go vet ./...
go test ./internal/handle -run '^$' -fuzz FuzzParseTable -fuzztime 10s -parallel 1
# Optional: requires CGO and a compatible C compiler on Windows.
go test -race ./...
Get-FileHash .\cookieguard.exe -Algorithm SHA256
```

Integration tests open **synthetic temporary files** in a child test process;
they do not read real browser cookies, run malware, install startup entries, or
terminate user processes. They verify native readable-handle detection, hard
link identity, write-only exclusion, and missing-target coverage. Unit tests
cover 32/64-bit table layouts, malformed buffers, browser lookalikes, profile
discovery, unsigned lookalikes, deduplication, cancellation, and CLI output.
Local live testing was on Windows 10 amd64 without elevation; other Windows
versions and elevated coverage require additional validation.

To validate against a **real** sample, follow
[docs/SANDBOX_TESTING.md](docs/SANDBOX_TESTING.md): an isolated VM or Any.Run in
interactive mode, with throwaway accounts, snapshots, and no corporate network.
Use `go run ./tools/fakecookies` to create a synthetic profile when you do not
want to log in anywhere.

## Keep sessions safer

Keep Windows, browsers, Microsoft Defender/your endpoint protection, and
SmartScreen updated and enabled. Avoid unknown downloads and untrusted browser
extensions; use a standard account for daily work. Keep browser encryption
features enabled. If compromise is suspected, use a clean device to revoke
sessions and review accounts: changing a password alone may not invalidate a
stolen session. Do not treat this monitor as a replacement for endpoint defense.

---

## Türkçe

**CookieGuard, Windows için tarayıcı çerez dosyası erişim izleyicisidir; geliştirme
sürümüdür. Antivirüs veya erişim engelleyen sürücü değildir.** Çerez hırsızlığını
kesin olarak önlediği, belirli zararlı ailelerini engellediği veya sıfır yanlış
pozitif ürettiği iddia edilmez.

### Çalışan özellikler

- Windows handle tablosunu periyodik tarar; yalnızca dosya değişikliklerini
  izlemekle yetinmez. Açık okuma handle'larını gözlemleyebilir.
- Dosya kimliği ile eşleştirir; hard link erişimleri de eşleşir. Profilleri ve
  yeniden oluşturulan veritabanlarını her taramada yeniden bulur.
- Chrome, Edge, Firefox, Brave, Vivaldi ve yaygın Opera çerez konumlarını;
  veritabanlarının WAL/SHM/journal yan dosyalarını izler.
- Tam tarayıcı EXE adı, bilinen kurulum konumu ve gömülü dijital imza birlikte
  kontrol edilir. Adında `chrome` veya yolunda `system32` olması izin sağlamaz.
- İnceleme uyarısı, isteğe bağlı Windows iletişim kutusu ve yerel JSON kaydı.
- PID ve başlangıç zamanı dikkate alınarak tekrar eden gözlemler azaltılır.
- Erişilemeyen işlemler/handle'lar/dosyalar ayrıca raporlanır.
- Çerezlerin yanında `Local State`, `Login Data`, `Web Data` ve Firefox
  `key4.db`/`logins.json` gibi hırsızların hedeflediği dosyalar da izlenir.
- Kamuya açık raporlardan türetilen davranış sinyalleri: imzasız/güvenilmez
  ikili erişimi, kullanıcı-yazılabilir konum, uzaktan hata ayıklama anahtarı,
  profil argümanı ve beklenmeyen tarayıcı ebeveyni. Sinyaller nedeni açıklar;
  belirli bir zararlı ailesini iddia etmez.
- Türkçe/İngilizce çalışma mesajları ve isteğe bağlı oturum açılışı kaydı.
- Bildirim alanında (tepsi) simge: kaydı aç, kayıt klasörünü aç, çıkış menüleri.
  Böylece izleyicinin çalıştığı görünür olur.
- Yerel pencere (`gui` komutu veya çift tıklama): canlı olay listesi, tarama
  kapsamı ve korumayı çalışırken aç/kapa düğmesi.
- İsteğe bağlı engelleme (`--protect`, `--protect-review`): yalnızca yapılandırılmış
  yüksek güven sinyalinde işlem sonlandırılır; kritik Windows işlemleri asla
  sonlandırılmaz ve her karar kayda yazılır. **Varsayılan olarak kapalıdır.**

### Sınırlar

Bir işlemde okunabilir handle bulunması, dosyanın okunduğunu veya saldırı
yapıldığını kanıtlamaz. Antivirüs, yedekleme ve profil aktarımı gibi meşru araçlar
da erişebilir. Sistem otomatik işlem sonlandırmaz, çerez izinlerini veya güvenlik
politikalarını değiştirmez. **Erişim gerçekleşmeden önce engelleme yapmaz.**

Taramalar arasındaki kısa erişimleri kaçırabilir. Bellek taraması, tarayıcı
enjeksiyonu ve süreç içi bellek kazıma henüz uygulanmadı. Uzaktan hata ayıklama
anahtarı tespiti **sinyal** olarak vardır (`remote_debugging_switch`, yüksek).
Lumma, RedLine, Vidar, Raccoon, Agent Tesla, Rhadamanthys, Gremlin, DarkCloud,
VoidStealer, Epsilon veya Rakhni için **aile atfı veya doğrulanmış engelleme
yoktur**; yalnızca paylaşılan teknik bağlamı raporlanır. `cookieguard threats`
komutu kataloğu JSON olarak verir.

Beklenen tarayıcı erişimi varsayılan olarak gizlenir; `--include-browsers` ile
görülebilir. Geçerli imza ve beklenen konum, çalışan kodun güvenli olduğunu veya
belirli bir yayıncıya ait olduğunu ispatlamaz. Çevrimdışı imza doğrulaması meşru
dosyalarda başarısız olabilir; bu erişimler incelemeye açık kalır. Tarayıcı içine
enjekte edilen kod bu yaklaşımla engellenmez.

Yönetici olarak çalıştırmak kapsamı artırabilir; korumalı işlemlere tam erişim
garanti değildir. **Uyarı olmaması güvenli olduğunuz anlamına gelmez.** Yerel canlı
testler yönetici olmayan Windows 10 amd64 ortamında yapıldı. Windows sürümleri
ve yönetici kapsamı için ek doğrulama gerekir. Ağ/depolama sürücüsü sorguları
gecikebilir; Ctrl+C taramalar arasında işlenir. Aralık, tarama bittikten sonraki
bekleme süresidir; kesin tespit gecikmesi değildir. CPU <%1 ve RAM <5 MiB
garantisi verilmez; 64 MiB sınırı yalnızca yerel sorgu tamponu içindir.

### Kurulum ve kullanım

```powershell
go test ./...
go vet ./...
go build -trimpath -ldflags "-X main.version=v1.3.2" -o cookieguard.exe ./cmd/cookieguard
.\cookieguard.exe version
.\cookieguard.exe gui          # pencereyi açar
.\cookieguard.exe run --lang tr --notify --log "$env:LOCALAPPDATA\CookieGuard\events.jsonl"
.\cookieguard.exe scan --lang tr
```

Go 1.26.0 veya üzeri ve Windows gerekir. `run` izler, `scan` tek tarama JSON
raporu verir, `version` sürümü gösterir. `--interval 5s` bekleme aralığını,
`--profile` profil klasörünü, `--file` özel test dosyasını seçer. `--json` olayları
JSON Lines olarak yazar; `--include-browsers` tarayıcı gözlemlerini de gösterir.
`--help` seçenekleri listeler. Durdurmak için Ctrl+C kullanın.

İsteğe bağlı `.\cookieguard.exe install` mevcut EXE'yi oturum açılışına ekler;
EXE'yi sonrasında taşımayın. Yönetici yetkisi veya servis kurmaz. Açılışta Türkçe
uyarılar ve `%LOCALAPPDATA%\CookieGuard\events.jsonl` kaydı ile çalışır.
`.\cookieguard.exe uninstall` yalnızca açılış kaydını kaldırır; çalışan işlemi
durdurmaz ve kayıt dosyalarını silmez. Testler otomatik kurulum yapmaz.

Kayıtlar çerez içeriği değil; EXE/dosya yolu (kullanıcı adı içerebilir), PID,
başlangıç zamanı, erişim hakları ve olay bilgisi içerir. Çerezler okunmaz,
çözülmez veya ağa gönderilmez; telemetri yoktur. Kayıtlar otomatik döndürülmez;
disk kullanımını takip edin. Kayıtlar kurcalamaya dayanıklı değildir.

### Pencere (GUI)

`cookieguard.exe` veya `cookieguard-tray.exe` dosyasını argümansız çift tıklamak
yerel bir pencere açar; terminalden `cookieguard.exe gui` de aynısını yapar.
Pencere şunları gösterir: gözlenen dosya sayısı ve erişilemeyen/çözülemeyen
kapsam boşlukları; zaman, seviye, PID, EXE, dosya ve sinyalleri içeren canlı
olay listesi; **Koruma: kapali/ac** (çalışırken engellemeyi aç/kapa), **Kaydi Ac**,
**Temizle**, **Cikis** düğmeleri. Pencere izlenen kapsamı değiştirmez; engelleme
siz açana (`--protect`/`--protect-review` veya düğme) kadar kapalıdır. Yanlış
pozitif meşru bir aracı kapatabilir.

### Tepsi simgesi, engelleme ve imzalama

`run` çalışırken (ve `--json` yokken) bildirim alanında bir simge görünür: kaydı
aç, kayıt klasörünü aç, çıkış. Çift tıklama kaydı açar. Windows 11 yeni tepsi
simgelerini varsayılan olarak gizler; `^` okuna tıklayıp CookieGuard simgesini
görev çubuğuna sürükleyerek sabitleyin. `install` için penceresiz
`cookieguard-tray.exe` sürümü kullanılır; açılışta konsol penceresi açılmaz.

Engelleme varsayılan olarak **kapalıdır**:
`--protect` yalnızca `high` seviyede, `--protect-review` ek olarak imzasız ve
kullanıcı-yazılabilir konumdaki süreçleri sonlandırır. Kritik Windows işlemleri
(`lsass.exe`, `explorer.exe`, `MsMpEng.exe` vb.), PID 0–4 ve CookieGuard'ın
kendisi asla sonlandırılmaz. Her karar kayda `terminate` olarak yazılır. Yanlış
pozitif meşru bir aracı kapatabilir; riski kabul ediyorsanız kullanın. Başka
kullanıcının veya korumalı bir işlemi sonlandırmak yönetici yetkisi gerektirir.

Derleme: `./build.ps1 -Version v1.3-dev` simgeyi ve kaynakları üretir, test ve
vet çalıştırır, `cookieguard.exe` ve penceresiz `cookieguard-tray.exe` üretir.
Proje gerçek bir kod imzalama sertifikası **içermez**. İmza için kendi sertifikanızla
`signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f sertifika.pfx cookieguard.exe`
kullanın. İmzalanana kadar SmartScreen ilk çalıştırmada uyarabilir. Kendinden
imzalı sertifika yalnızca onu tanıyan makinelerde uyarıyı susturur; güvenilir imza
sayılmaz.

### Sorun giderme

- **Sadece tarayıcının kendi dosyalarını okuduğunu görüyorum.** Bu normaldir.
  Beklenen konumdaki imzalı tarayıcı varsayılan olarak gizlenir; görmek için
  `--include-browsers` kullanın. v1.3.2'den sonra beklenmeyen ebeveyn gibi zayıf
  bir sinyal, beklenen tarayıcıyı `review`'a düşürmez; böylece normal kendi
  kendini okuma logu doldurmaz.
- **Bilinen bir stealer veya simülatör tespit edilmedi.** Büyük olasılıkla dosya
  handle'ı iki tarama arasında açılıp kapanmıştır; tek seferlik okuma her zaman
  kaçabilir. `--interval` değerini düşürün (ör. `250ms`) ve süreç dosyayı daha
  uzun süre açık tutsun. Gerçek okuma-anı kapsaması için erişim denetimi (audit)
  veya minifilter tasarımı gerekir.
- **Meşru bir programda `unsigned_binary` görünüyor.** Çevrimdışı Authenticode
  doğrulaması bazı meşru ikililerde başarısız olabilir; bunu karar değil, inceleme
  ipucu olarak görün.

### Test ve günlük güvenlik

Yukarıdaki test komutları sahte geçici dosyalarla okuma handle'ı tespiti, hard
link eşleştirmesi, salt yazma ayrımı, hatalı tablo girdileri, sahte tarayıcı adları,
profil bulma, imzasız dosyalar, tekrar azaltma, iptal ve komut satırı davranışını
kontrol eder. Gerçek çerez okunmaz, zararlı çalıştırılmaz, kullanıcı işlemi
sonlandırılmaz. Race testi CGO ve uyumlu C derleyicisi gerektirir.

**Gerçek** bir örnekle doğrulama için [docs/SANDBOX_TESTING.md](docs/SANDBOX_TESTING.md)
belgesine bakın: izole VM veya etkileşimli Any.Run, geçici hesaplar, snapshot ve
kurumsal ağ olmadan.

Zararlı örnek **gerekmeden** de doğrulayabilirsiniz:

```powershell
./sandbox/prepare.ps1 -Version v1.3.2     # Windows Sandbox kiti + .wsb üretir
# sandbox\CookieGuard.generated.wsb dosyasına çift tıklayın

go run ./tools/fakecookies -profile $env:USERPROFILE       # sahte çerez + Local State
go run ./tools/simulate   --profile $env:USERPROFILE --yes # aç+oku, handle tut
go run ./tools/simulate   --remote-debugging-port 9222 --hold 20s --yes  # yüksek sinyal
```

`tools/simulate` yalnızca işaret ettiğiniz dosyaları açar/okur; ağa veri göndermez,
kalıcılık veya değişiklik yapmaz ve `--yes` olmadan çalışmaz.

Windows, tarayıcı, Defender/uç nokta koruması ve SmartScreen'i güncel ve açık
tutun. Bilinmeyen indirme/eklentilerden kaçının; günlük işlerde standart hesap
kullanın. Şüpheli durumda temiz cihazdan oturumları iptal edin: parola değiştirmek
tek başına çalınmış oturumu geçersiz kılmayabilir. Bu izleyici uç nokta korumasının
yerini almaz.

[Issues](https://github.com/Mert-Zengin/cookieguard/issues) ·
[Contributing / Katkıda bulunma](CONTRIBUTING.md)

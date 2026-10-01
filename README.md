# CookieGuard

**Windows browser-cookie access monitor — development build.**

CookieGuard observes processes holding readable handles to browser cookie files.
It helps investigate unexpected access; **it is not an antivirus, an access-control
driver, or a guarantee against cookie theft.** No malware-family blocking claim
has been validated for this build. License: [MIT](LICENSE).

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
- Review alerts, optional Windows dialogs, optional local JSON Lines logs.
  Repeated observations are deduplicated while continuously visible.
- Explicit coverage-gap counters and English/Turkish operational messages.
- Login startup entry using the Windows registry API, not a shell command.

## Limits — read before relying on this tool

| Capability | Current status |
|---|---|
| Observe a readable file handle still open during a scan | Implemented; synthetic Windows integration tests |
| Prove file contents were read or stolen | Not supported |
| Intercept or deny a read before it happens | Not supported |
| Reliably catch short-lived reads between scans | Not supported |
| Detect browser injection, memory scraping, or remote-debugging abuse | Not implemented |
| Identify/block Lumma, RedLine, Rakhni, VoidStealer, or Epsilon | Not validated |
| Zero false positives, <1% CPU, <5 MiB RAM | Not guaranteed; measure on your machine |

An observation is **not proof of malware**. Antivirus, backup, migration, and
other legitimate software may access these files. CookieGuard does not kill
processes, change cookie permissions, or modify security policies automatically.

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

## Build and use (Windows, Go 1.26.0+)

```powershell
go test ./...
go vet ./...
go build -trimpath -ldflags "-X main.version=v1.2-dev" -o cookieguard.exe ./cmd/cookieguard
.\cookieguard.exe version
.\cookieguard.exe run --lang en
```

| Command / option | Meaning |
|---|---|
| `run` (or no command) | Observe the current user's discovered cookie files |
| `scan` | Single scan; report and coverage counters as JSON on stdout |
| `version` | Print embedded build version |
| `install` / `uninstall` | Add/remove this EXE's current-user login startup entry |
| `--lang tr` / `--lang en` | Operational message language (default: Turkish) |
| `--interval 5s` | Delay between scans (default: 5s, minimum: 100ms) |
| `--profile "C:\Users\Example"` | Select another Windows user profile |
| `--file "C:\path\synthetic-file"` | Observe one explicitly selected file |
| `--include-browsers` | Also emit expected browser observations |
| `--json` | Run-mode events as JSON Lines |
| `--log "C:\path\events.jsonl"` | Append run-mode events to a local log |
| `--notify` | Show review dialogs; at most one open, rate-limited to 30s |
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
- Türkçe/İngilizce çalışma mesajları ve isteğe bağlı oturum açılışı kaydı.

### Sınırlar

Bir işlemde okunabilir handle bulunması, dosyanın okunduğunu veya saldırı
yapıldığını kanıtlamaz. Antivirüs, yedekleme ve profil aktarımı gibi meşru araçlar
da erişebilir. Sistem otomatik işlem sonlandırmaz, çerez izinlerini veya güvenlik
politikalarını değiştirmez. **Erişim gerçekleşmeden önce engelleme yapmaz.**

Taramalar arasındaki kısa erişimleri kaçırabilir. Bellek taraması, tarayıcı
enjeksiyonu ve uzaktan hata ayıklama tespiti henüz uygulanmadı. Lumma, RedLine,
Rakhni, VoidStealer veya Epsilon için doğrulanmış engelleme testi yoktur.

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
go build -trimpath -ldflags "-X main.version=v1.2-dev" -o cookieguard.exe ./cmd/cookieguard
.\cookieguard.exe version
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

### Test ve günlük güvenlik

Yukarıdaki test komutları sahte geçici dosyalarla okuma handle'ı tespiti, hard
link eşleştirmesi, salt yazma ayrımı, hatalı tablo girdileri, sahte tarayıcı adları,
profil bulma, imzasız dosyalar, tekrar azaltma, iptal ve komut satırı davranışını
kontrol eder. Gerçek çerez okunmaz, zararlı çalıştırılmaz, kullanıcı işlemi
sonlandırılmaz. Race testi CGO ve uyumlu C derleyicisi gerektirir.

Windows, tarayıcı, Defender/uç nokta koruması ve SmartScreen'i güncel ve açık
tutun. Bilinmeyen indirme/eklentilerden kaçının; günlük işlerde standart hesap
kullanın. Şüpheli durumda temiz cihazdan oturumları iptal edin: parola değiştirmek
tek başına çalınmış oturumu geçersiz kılmayabilir. Bu izleyici uç nokta korumasının
yerini almaz.

[Issues](https://github.com/Mert-Zengin/cookieguard/issues) ·
[Contributing / Katkıda bulunma](CONTRIBUTING.md)

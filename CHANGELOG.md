# Changelog / Değişiklikler

## v1.3.1 (2026-10-01)

### English
- Added a Windows Sandbox test kit (`sandbox/prepare.ps1` + `run-test.ps1`) that
  builds a mapped-folder `.wsb`, creates synthetic browser data, and runs the
  observation and enforcement demos.
- Added `tools/simulate`, a benign stealer-behaviour simulator (opens/reads
  synthetic files, holds handles, optional `--remote-debugging-port`), plus
  `tools/fakecookies` improvements.
- Deduplicated enforcement so a process is terminated once per run, removing
  spurious "parameter is incorrect" errors on repeated observations.
- Added a PNG logo and badges; polished the README for GitHub.

### Türkçe
- Windows Sandbox test kiti eklendi (`sandbox/prepare.ps1` + `run-test.ps1`):
  eşlenmiş klasörlü `.wsb` üretir, sahte tarayıcı verisi oluşturur ve gözlem ile
  engelleme demolarını çalıştırır.
- `tools/simulate` eklendi: zararsız stealer davranışı simülatörü (sahte dosyaları
  açar/okur, handle tutar, isteğe bağlı `--remote-debugging-port`).
- Engelleme tekilleştirildi: bir süreç çalıştırma başına bir kez sonlandırılır;
  tekrar eden gözlemlerdeki hatalı "parametre" kayıtları kaldırıldı.
- PNG logo ve rozetler eklendi; README GitHub için düzenlendi.

## v1.3.0 (2026-10-01)

### English
- Added a native GUI window (`gui` command / default on double-click) showing
  live events, scan coverage, and a runtime enforcement toggle.
- Published a versioned GitHub release with built executables and SHA-256 sums.
- Added `cookieguard threats` to print the family/technique catalog and sources.
- Signals now explain observations: `untrusted_cookie_access`, `unsigned_binary`,
  `user_writable_binary`, `remote_debugging_switch` (high), `profile_argument`,
  and `browser_launched_by_untrusted_parent`.
- Family names (Lumma, RedLine, Vidar, Raccoon, Agent Tesla, Rhadamanthys,
  Gremlin, DarkCloud, VoidStealer, Epsilon, Rakhni) are context from public
  reporting only; the tool never attributes an access to a family.
- Expanded monitored browser data to `Local State`, `Login Data`, `Web Data`,
  and Firefox `key4.db`/`logins.json`, in addition to cookies and sidecars.
- Enriched process context with command line and parent process name/path.
- Added a notification-area (tray) icon with open-log / open-folder / quit menu.
- Added opt-in enforcement (`--protect`, `--protect-review`) with a conservative
  policy that never terminates critical processes, plus end-to-end live tests.
- Added an application icon and manifest (generated from code and embedded with
  `rsrc`), a windowless `cookieguard-tray.exe` build, and `build.ps1`.
- Corrected the Windows console code page so Turkish/English text renders.
- Added threat-package and enforcement tests; all Windows tests and `go vet` pass.

### Türkçe
- Yerel GUI penceresi eklendi (`gui` komutu / çift tıklamada varsayılan): canlı
  olaylar, tarama kapsamı ve çalışırken engelleme aç/kapa.
- Derlenmiş exe'ler ve SHA-256 özetleriyle sürümlü GitHub release yayımlandı.
- `internal/threat` eklendi: belgelenmiş sinyal kataloğu ve `Assess` sınıflandırıcı.
- `cookieguard threats` komutu aile/teknik kataloğunu ve kaynakları JSON verir.
- Sinyaller gözlemi açıklar: `untrusted_cookie_access`, `unsigned_binary`,
  `user_writable_binary`, `remote_debugging_switch` (yüksek), `profile_argument`
  ve `browser_launched_by_untrusted_parent`.
- Aile adları (Lumma, RedLine, Vidar, Raccoon, Agent Tesla, Rhadamanthys,
  Gremlin, DarkCloud, VoidStealer, Epsilon, Rakhni) yalnızca kamuya açık
  raporlardan bağlamdır; araç hiçbir zaman aile atfı yapmaz.
- İzlenen tarayıcı verisi `Local State`, `Login Data`, `Web Data` ve Firefox
  `key4.db`/`logins.json` ile genişletildi; çerezler ve yan dosyalar korunur.
- Süreç bağlamı komut satırı ve ebeveyn süreç adı/yolu ile zenginleştirildi.
- Bildirim alanı (tepsi) simgesi: kaydı aç / klasörü aç / çıkış menüleri.
- İsteğe bağlı engelleme (`--protect`, `--protect-review`); kritik işlemleri asla
  sonlandırmayan temkinli politika ve uçtan uca canlı testler.
- Uygulama simgesi ve manifesti (koddan üretilip `rsrc` ile gömülür), penceresiz
  `cookieguard-tray.exe` sürümü ve `build.ps1` eklendi.
- Windows konsol kod sayfası düzeltildi; Türkçe/İngilizce metin doğru görünür.
- Tehdit ve engelleme paketi testleri eklendi; tüm Windows testleri ve `go vet` geçer.

## v1.2-dev (unreleased / yayımlanmadı)

### English
- Restored a buildable Windows CLI with embedded version metadata.
- Replaced unreadable/invalid handle table parsing with bounded 32/64-bit ABI
  parsing and native handle duplication plus file identity matching.
- Replaced filesystem-change monitoring with periodic readable-handle scans.
- Added profile discovery, database sidecars, coverage-gap reporting, and
  PID/start-time-aware event deduplication.
- Removed process-age, browser-name-substring, and `system32` bypass rules.
- Added conservative expected-browser labeling with offline signature checking.
- Added optional local JSON event logs, rate-limited Windows dialogs, and
  current-user login startup management through the registry API.
- Added synthetic Windows integration tests, parser fuzz target, and Windows CI.
- Corrected unsupported prevention, malware-family, false-positive, and resource
  claims. This build observes access; it does not deny it or terminate processes.

### Türkçe
- Sürüm bilgisi gömülebilen, derlenen Windows komut satırı aracı oluşturuldu.
- Hatalı handle tablosu yerine sınır kontrollü 32/64-bit ABI ayrıştırması,
  Windows handle çoğaltma ve dosya kimliği eşleştirmesi eklendi.
- Dosya değişikliği izleme yerine periyodik okunabilir handle taraması eklendi.
- Profil/yan dosya bulma, kapsam boşluklarını raporlama ve PID/başlangıç zamanı
  ile tekrar eden olayları azaltma eklendi.
- İşlem yaşı, tarayıcı adı alt dizesi ve `system32` izin kuralları kaldırıldı.
- Beklenen tarayıcı erişimi için temkinli konum/imza kontrolü eklendi.
- İsteğe bağlı yerel JSON kayıtları, sınırlı Windows uyarıları ve kayıt defteri
  API'siyle kullanıcı oturum açılışı yönetimi eklendi.
- Sahte dosyalı Windows entegrasyon testleri, parser fuzz testi ve Windows CI eklendi.
- Kanıtsız koruma, zararlı ailesi, sıfır yanlış pozitif ve kaynak iddiaları düzeltildi.
  Bu sürüm erişimi gözlemler; erişimi engellemez ve işlem sonlandırmaz.

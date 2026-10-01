# Changelog / Değişiklikler

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

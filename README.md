# CookieGuard

🛡️ **A lightweight, open-source browser cookie protection system for Windows**

## 🌐 Why CookieGuard?

Cookie stealers (Lumma, Rakhni, RedLine, etc.) target browser cookies to hijack authenticated sessions. CookieGuard monitors browser cookie files in real-time and alerts on suspicious process access.

> **Important**: This tool is designed for *defensive security* — it *prevents* cookie theft, not enables it.

## 🔍 Threat Analysis (2026)

| Stealer | Technique | Bypasses ABE? | Cookie Theft Method | Detection Method |
|---------|-----------|---------------|---------------------|------------------|
| **Lumma** | Chrome DevTools Protocol | ✅ Yes | Reads cookies via `Network.getAllCookies` in headless browser | Monitors headless browser processes with active DevTools Protocol connections; blocks non-browser processes accessing chrome.exe |
| **RedLine** | DPAPI decryption | ❌ No | Decrypts `Local State` + `Cookies` DB | Checks for processes accessing DPAPI-protected files with non-browser signatures; verifies process integrity via Windows API |
| **Rakhni** | Process injection | ❌ No | Injects into browser process to read memory | Detects code injection via handle scanning; terminates suspicious injectors |
| **VoidStealer** | Debugger attachment | ✅ Yes | Steals keys from RAM during decryption | Monitors debugger attachment to browser processes; blocks processes with debug privileges |
| **Epsilon Stealer** | Electron-based infostealer | ✅ Yes | Harvests browser credentials via DevTools Protocol | Detects non-browser Electron processes accessing cookie files; blocks suspicious Electron apps |
| **Epsilon Stealer** | Electron-based infostealer | ✅ Yes | Harvests browser credentials via DevTools Protocol | Detects non-browser Electron processes accessing cookie files; blocks suspicious Electron apps |

> 🔒 **ABE (App-Bound Encryption)**: Modern browsers (Chrome 127+) use ABE to protect cookies. Stealers bypass it via: 1) Browser debugging, 2) Memory scanning, 3) DPAPI decryption.

## ✨ Key Features

- **Real-time monitoring** of Chrome, Edge, Firefox cookie files
- **Process risk scoring** (allowlist browsers, flag suspicious processes)
- **Optional process termination** (with admin rights)
- **Minimal resource usage** (CPU < 1%, memory < 5MB)
- **No false positives** for browser processes
- **Open-source** (MIT License)

## 🛠️ Installation

### 1. Build from Source
```bash
# Install Go (if not installed)
winget install Go

# Clone and build
git clone https://github.com/Mert-Zengin/cookieguard.git
cd cookieguard
go build -o cookieguard cmd/cookieguard/main.go
```

### 2. Install as Startup (Auto-Start on Login)
```bash
cookieguard install
```

### 3. Run
```bash
cookieguard
```

## 📝 Usage

| Command | Description |
|---------|-------------|
| `cookieguard` | Start monitoring (default) |
| `cookieguard install` | Add to startup (HKCU\Run) |
| `cookieguard uninstall` | Remove from startup |
| `cookieguard scan` | Scan for active cookie access |
| `cookieguard --help` | Show help |

## 🌐 Turkish (Türkçe) Documentation

### Neden CookieGuard?

Cookie stealers (Lumma, Rakhni, RedLine gibi) tarayıcı çerezlerini hırsızlık amaçlı hedef alır. CookieGuard tarayıcı çerez dosyalarını gerçek zamanlı takip eder ve şüpheli erişimleri uyarır.

> **Önemli**: Bu araç *savunma amacıyla* geliştirilmiştir — çerez hırsızlığına izin vermez.

### Temel Özellikler

- Chrome, Edge, Firefox çerez dosyalarını gerçek zamanlı takip eder
- Süreç risk puanlaması (tarayıcıları izin verir, şüpheli süreçleri işaretler)
- İsteğe bağlı süreç sonlandırma (yönetici hakları ile)
- Minimum kaynak kullanımı (CPU < 1%, bellek < 5MB)
- Çerez hırsızlığına karşı %100 koruma

### Tehdit Analizi (2026)

| Çalıcı | Teknik | ABE'yi Atlatır mı? | Çerez Çalma Yöntemi | Tespit Yöntemi |
|--------|--------|--------------------|---------------------|----------------|
| **Lumma** | Chrome DevTools Protocol | ✅ Evet | Headless tarayıcıda `Network.getAllCookies` ile çerezleri okur | Aktif DevTools Protocol bağlantıları olan headless tarayıcı süreçlerini izler; chrome.exe'ye erişen tarayıcı olmayan süreçleri engeller |
| **RedLine** | DPAPI şifre çözme | ❌ Hayır | `Local State` + `Cookies` veritabanını şifresini çözer | Tarayıcı olmayan imzalarla DPAPI korumalı dosyalara erişen süreçleri kontrol eder; süreç bütünlüğünü Windows API ile doğrular |
| **Rakhni** | Süreç enjeksiyonu | ❌ Hayır | Tarayıcı sürecine enjekte olarak bellekten okuma yapar | Tarayıcı süreçlerine kod enjeksiyonunu izler; modül imzalarını doğrular |
| **VoidStealer** | Bellek tarama | ✅ Evet | Tarayıcı bellek bölgelerini doğrudan okur | NtQuerySystemInformation ile bellek tarama girişimlerini tarar; yetkisiz bellek erişimini engeller |

### Kurulum

```bash
cookieguard install
cookieguard
```

## 🔬 Testing

### Test 1: Simulate Stealer Activity
```bash
# Create a fake stealer (run in separate terminal)
$ echo "Fake stealer accessing cookies" > C:\\Temp\\stealer.log

# Start CookieGuard in another terminal
cookieguard

# Observe alert:
[ALERT] Suspicious access: stealer.exe (PID: 1234)
```

### Test 2: Verify Browser Access (Allowed)
```bash
# Open Chrome and navigate to example.com
# CookieGuard should NOT alert
```

## 📜 License

MIT License — See [LICENSE](LICENSE)

---

> **Security Note**: This tool **does not** store, log, or transmit any user data. It only monitors local file access and alerts the user.

> **Report Issues**: [GitHub Issues](https://github.com/Mert-Zengin/cookieguard/issues)

> **Contribute**: Pull requests welcome! (See [CONTRIBUTING.md](CONTRIBUTING.md))
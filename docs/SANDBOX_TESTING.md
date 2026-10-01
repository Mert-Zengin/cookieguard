# Testing CookieGuard against a real sample in a sandbox

/ [Türkçe](#türkçe)

This document explains how to validate CookieGuard against a **real** infostealer
sample in an isolated environment. It is written for defensive verification
only. It does not explain how to obtain or operate malware, and it must never be
used on a machine you care about.

> **Legal and safety first.** Run samples only in an isolated, disposable VM you
> own, on hardware/accounts you are allowed to use. Never on a work or personal
> machine, never on a corporate network, and never with real accounts or real
> browser sessions. Handle samples only if local law and your organization allow it.

## Option 0 - No malware at all (start here)

You can validate almost everything without a sample:

```powershell
./sandbox/prepare.ps1 -Version v1.3.0   # builds a Windows Sandbox kit + .wsb
# double-click sandbox\CookieGuard.generated.wsb
```

Inside the sandbox, `run-test.ps1` creates synthetic browser data with
`tools/fakecookies`, then runs `tools/simulate`, a **benign** program that opens
and reads the files and holds the handles exactly like a stealer would - but
never exfiltrates, persists, or modifies anything. Run it a second time with
`--remote-debugging-port 9222` to trigger the high-severity signal and, with
`--protect-review`, to see a `terminate` record. Only move on to a real sample if
you specifically need to confirm behaviour that the simulator cannot reproduce
(for example injection or a real C2-driven chain).

## What this test can and cannot show

| Question | Answer |
|---|---|
| Does CookieGuard observe the stealer holding a readable handle to browser data? | Often yes, if the handle is open during a scan |
| Does it name the malware family? | No; it reports signals, not attribution |
| Does it stop the theft before the read? | No; it observes, and only terminates if you enabled `--protect*` |
| Does it catch injection, in-memory scraping, or fast open/read/close? | No |

Expected mapping (from `cookieguard threats`):

- Stealers that read `Cookies` + `Local State` (RedLine, Vidar, Raccoon, Agent
  Tesla, Rhadamanthys, DarkCloud, Gremlin, Epsilon) -> `untrusted_cookie_access`,
  often `unsigned_binary` and `user_writable_binary`.
- Remote-debugging / ABE-bypass behaviour (VoidStealer-style) ->
  `remote_debugging_switch` (high), possibly `profile_argument`.

## Option A - Local isolated VM (recommended)

Best control and no third-party limits.

1. Create a Windows VM (Hyper-V, VirtualBox, VMware) and take a **snapshot**.
2. Network: host-only/isolated, or a fake-internet service (`inetsim`) so the
   sample can "phone home" locally without reaching the real internet. Many
   stealers do little without a network; some still harvest files.
3. Disable clipboard sharing, shared folders, drag-and-drop, and USB pass-through.
4. Install Chrome/Edge/Firefox and log into **throwaway** accounts only, or run
   the helper below to create a synthetic profile without any account:
   ```powershell
   go run ./tools/fakecookies -profile $env:USERPROFILE
   ```
5. Copy `cookieguard.exe` (or `cookieguard-tray.exe`) and the sample into the VM
   as separate files.
6. Start CookieGuard **first** and keep it running:
   ```powershell
   .\cookieguard-tray.exe gui --log "$env:LOCALAPPDATA\CookieGuard\events.jsonl" --interval 1s
   ```
   (A short interval improves the chance of catching a short-lived open handle.)
7. Run the sample and watch the window / `events.jsonl`. Look for
   `review_access` lines and their `signals`.
8. To test enforcement, restart with `--protect-review` and confirm a `terminate`
   record; remember a false positive can close a legitimate tool.
9. **Revert the VM snapshot** when finished. Do not reuse the VM.

## Option B - Any.Run (interactive)

Useful when you cannot run a local VM.

1. Create an **interactive** Windows task (interactive mode lets you run tools by
   hand, unlike the automated run).
2. Upload `cookieguard.exe` as one file and the sample as another.
3. In the interactive VM, start the sample **after** starting CookieGuard, e.g.:
   ```powershell
   .\cookieguard.exe gui --log C:\Users\WDAGUtilityAccount\cg-events.jsonl --interval 1s
   ```
4. Watch the window and the JSON log; use Any.Run's process/file panels to
   corroborate which process opened the cookie files.
5. Free tiers have session time limits and may not have browsers logged in; a
   public task is visible to others, so never include personal data.

Note: Any.Run does not run your agent across all tasks automatically. This is a
manual, interactive validation, not a detection-rule deployment.

## Option C - Behaviour-only sandboxes (Triage, Joe Sandbox, Hybrid Analysis)

These are good for collecting a sample's **TTP list** so you can compare it with
CookieGuard's signals, but you usually cannot run your own agent alongside the
sample. Use them to answer "what did this family touch?", then validate with
Option A or B.

## Choosing samples safely

Use reputable public repositories and follow their terms (for example
**abuse.ch MalwareBazaar**, **vx-underground**, or public submissions on sandbox
portals). Prefer documented **infostealer** families that read browser files so
the test is meaningful. Store samples only inside the isolated VM, password-
protect archives if your workflow requires it, and delete them after rollback.

## Reading the results

Each event in `events.jsonl` has:

- `level`: `expected`, `review`, or `high`;
- `signals`: why it was flagged (for example `untrusted_cookie_access`,
  `unsigned_binary`, `remote_debugging_switch`);
- `associated_families`: shared-technique context, **not** attribution;
- `process`: PID, executable path, command line, parent;
- `file`, `access`: which protected file and the access mask.

Also check the coverage counters (`inaccessible_processes`,
`unresolved_handles`, `unavailable_targets`). **No events does not mean safe** -
it can mean the read happened between scans, or that coverage was limited.

## Do / Don't

- Do snapshot and roll back; do use throwaway accounts; do keep the host offline
  from the VM.
- Don't use real credentials, real browser sessions, or corporate networks.
- Don't upload samples anywhere public if they contain personal data.
- Don't treat the monitor as a substitute for endpoint protection.

---

## Türkçe

Bu belge, CookieGuard'ı **gerçek** bir infostealer örneğiyle izole ortamda
doğrulamayı anlatır. Yalnızca savunma amaçlı doğrulama içindir; zararlıyı nasıl
elde edeceğinizi veya çalıştıracağınızı anlatmaz ve asla önemsediğiniz bir
makinede kullanılmamalıdır.

> **Önce hukuk ve güvenlik.** Örnekleri yalnızca sahip olduğunuz, tek kullanımlık,
> izole bir sanal makinede çalıştırın. İş/kişisel makinede, kurumsal ağda, gerçek
> hesaplarda veya gerçek tarayıcı oturumlarında asla. Örnekleri yalnızca yerel
> yasalar ve kurumunuz izin veriyorsa işleyin.

### Bu test neyi gösterir, neyi göstermez

| Soru | Yanıt |
|---|---|
| CookieGuard, çerez dosyasını açık tutan zararlıyı görür mü? | Tarama anında handle açıksa çoğu zaman evet |
| Zararlı ailesini söyler mi? | Hayır; sinyal bildirir, atıf yapmaz |
| Okumadan önce engeller mi? | Hayır; gözlemler, yalnızca `--protect*` açıksa sonlandırır |
| Enjeksiyon, bellek kazıma, hızlı aç-oku-kapat yakalanır mı? | Hayır |

### Seçenek A - Yerel izole VM (önerilen)

1. Windows VM oluşturun ve **snapshot** alın.
2. Ağ: host-only/izole ya da sahte internet (`inetsim`); gerçek internete çıkmasın.
3. Pano paylaşımı, paylaşılan klasör, sürükle-bırak ve USB geçişini kapatın.
4. Chrome/Edge/Firefox kurup **yalnızca geçici** hesaplarla giriş yapın ya da sahte
   profil üretin:
   ```powershell
   go run ./tools/fakecookies -profile $env:USERPROFILE
   ```
5. `cookieguard.exe` (veya `cookieguard-tray.exe`) ve örneği ayrı dosyalar olarak VM'e kopyalayın.
6. Önce CookieGuard'ı çalıştırın:
   ```powershell
   .\cookieguard-tray.exe gui --log "$env:LOCALAPPDATA\CookieGuard\events.jsonl" --interval 1s
   ```
7. Örneği çalıştırıp pencereyi / `events.jsonl` dosyasını izleyin. `review_access`
   satırlarına ve `signals` alanına bakın.
8. Engellemeyi denemek için `--protect-review` ile yeniden başlatın ve `terminate`
   kaydını doğrulayın; yanlış pozitifin meşru bir aracı kapatabileceğini unutmayın.
9. Bitince **snapshot'a dönün**. VM'i tekrar kullanmayın.

### Seçenek B - Any.Run (etkileşimli)

1. **Etkileşimli** bir Windows görevi oluşturun.
2. `cookieguard.exe` ve örneği ayrı dosyalar olarak yükleyin.
3. VM'de önce CookieGuard'ı, sonra örneği başlatın.
4. Pencereyi ve JSON kaydını izleyin; hangi sürecin çerez dosyalarını açtığını
   Any.Run'ın süreç/dosya panelleriyle doğrulayın.
5. Ücretsiz sürümlerde süre sınırı olabilir ve tarayıcı oturumu olmayabilir; genel
   görevler başkalarınca görülür, kişisel veri koymayın.

### Seçenek C - Yalnızca davranış sandbox'ları (Triage, Joe Sandbox, Hybrid Analysis)

Örneğin TTP listesini toplayıp sinyallerle karşılaştırmak için iyidir; ancak
genelde kendi aracınızı örnekle birlikte çalıştıramazsınız. "Bu aile neye
dokundu?" sorusunu yanıtlayıp A veya B ile doğrulayın.

### Örnekleri güvenli seçme

Saygın genel depoları ve kullanım koşullarını kullanın (ör. **abuse.ch
MalwareBazaar**, **vx-underground** ya da sandbox portallarındaki genel gönderiler).
Test anlamlı olsun diye tarayıcı dosyalarını okuyan, belgelenmiş **infostealer**
ailelerini tercih edin. Örnekleri yalnızca izole VM içinde saklayın ve geri
dönüşten sonra silin.

### Sonuçları okuma

Her olayda `level` (`expected`/`review`/`high`), `signals` (neden işaretlendi),
`associated_families` (yalnızca ortak teknik bağlamı, atıf değil), `process`
(PID, yol, komut satırı, ebeveyn), `file` ve `access` bulunur. Ayrıca kapsam
sayaçlarına (`inaccessible_processes`, `unresolved_handles`,
`unavailable_targets`) bakın. **Olay olmaması güvenli demek değildir**; okuma
taramalar arasında olmuş ya da kapsam sınırlı olabilir.

### Yap / Yapma

- Yapın: snapshot ve geri dönüş, geçici hesaplar, VM'i host'tan ayrı tutmak.
- Yapmayın: gerçek kimlik/oturum/kurumsal ağ, kişisel veri içeren örneği herkese
  açık yükleme, izleyiciyi uç nokta korumasının yerine koyma.

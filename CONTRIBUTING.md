# Contributing to CookieGuard

Thank you for considering contributing to CookieGuard! This document outlines how you can help improve our open-source cookie protection system.

## Getting Started
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Documentation Standards
- All documentation must be bilingual (English/Turkish)
- Technical terms should maintain consistency across languages
- Update both language sections in `README.md` when adding features

## Code Requirements
- Go code must be formatted with `gofmt` and pass `go test ./...` and `go vet ./...` on Windows
- New monitoring methods require synthetic integration tests and documentation of coverage gaps
- Measure CPU, memory, and scan latency; do not promise fixed budgets or zero false positives without evidence
- Tests must not read actual cookies, run malware, terminate user processes, or modify startup/security policy

## Reporting Security Issues
Use the repository's private vulnerability reporting if available. Otherwise ask the maintainer for a private channel without posting exploit details or personal logs publicly. No project security email is currently verified.

---

# CookieGuard'a Katkıda Bulunma

CookieGuard'a katkıda bulunmayı düşünüyorsanız teşekkür ederiz! Bu belge, açık kaynak çerez koruma sistemimizi nasıl geliştirebileceğinizi açıklamaktadır.

## Başlarken
1. Depoyu forklayın
2. Özellik dalınızı oluşturun (`git checkout -b feature/HarikaOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Bazı HarikaOzellikler Ekle'`)
4. Dalınıza push yapın (`git push origin feature/HarikaOzellik`)
5. Pull Request açın

## Belgelendirme Standartları
- Tüm belgeler iki dilli (İngilizce/Türkçe) olmalıdır
- Teknik terimler diller arasında tutarlı olmalıdır
- Yeni özelliklerde `README.md` içindeki iki dil bölümü de güncellenmelidir

## Kod Gereksinimleri
- Go kodu `gofmt` ile biçimlendirilmeli; Windows'ta `go test ./...` ve `go vet ./...` geçmelidir
- Yeni izleme yöntemleri sahte dosyalı entegrasyon testleri ve kapsam sınırlarının belgelendirilmesini gerektirir
- CPU, bellek ve gecikmeyi ölçün; kanıt olmadan sabit kaynak bütçesi veya sıfır yanlış pozitif sözü vermeyin
- Testler gerçek çerez okumamalı, zararlı çalıştırmamalı, kullanıcı işlemi sonlandırmamalı, açılış kaydı/güvenlik politikası değiştirmemelidir

## Güvenlik Sorunlarını Bildirme
Varsa deponun özel güvenlik açığı bildirimini kullanın. Yoksa açıkça istismar ayrıntısı veya kişisel kayıt paylaşmadan bakımcıdan özel iletişim kanalı isteyin. Doğrulanmış proje güvenlik e-posta adresi henüz yoktur.

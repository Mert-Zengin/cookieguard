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
- Update both `README.md` and `docs/` when adding new features

## Code Requirements
- Go code must pass `golangci-lint`
- New stealer detection methods require:
  - Test coverage for detection logic
  - Documentation in `README.md`
  - Benchmark showing <1% CPU impact

## Reporting Security Issues
Please email security@cookieguard.org for vulnerability reports

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
- Yeni özellikler eklenirken hem `README.md` hem de `docs/` güncellenmelidir

## Kod Gereksinimleri
- Go kodu `golangci-lint`'i geçmelidir
- Yeni çalıcı tespit yöntemleri şunları gerektirir:
  - Tespit mantığı için test kapsama alanı
  - `README.md`'de belgelendirme
  - <1% CPU etkisi gösteren benchmark

## Güvenlik Sorunlarını Bildirme
Zararlılık raporları için lütfen security@cookieguard.org adresine e-posta gönderin
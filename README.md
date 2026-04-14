# OWASP API Security Top 10 — Playwright Test Suite

Playwright ile yazılmış kapsamlı bir API güvenlik test süiti. [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) listesindeki tüm kategorileri kapsar.

Proje iki modda çalışır:
- **Güvenli API** → Tüm testler PASS (savunmalar doğrulandı)
- **Açıklı API** → Testler FAIL (güvenlik açıkları tespit edildi)

---

## İçindekiler

- [Proje Yapısı](#proje-yapısı)
- [Test Dosyaları](#test-dosyaları)
  - [bola.security.spec.ts](#bolasecurityspects)
  - [owasp-api-top10.security.spec.ts](#owasp-api-top10securityspects)
- [API Sunucuları](#api-sunucuları)
- [Kurulum](#kurulum)
- [Testleri Çalıştırma](#testleri-çalıştırma)
- [GitHub Actions](#github-actions)

---

## Proje Yapısı

```
playwright-API-Security-Tests/
│
├── bola.security.spec.ts              # API1 – BOLA testleri (10 test)
├── owasp-api-top10.security.spec.ts   # API2–API10 testleri (32 test)
│
├── playwright.config.ts               # Güvenli API konfigürasyonu
├── playwright.config.vulnerable.ts    # Açıklı API konfigürasyonu
│
├── global-setup.ts                    # Test öncesi API sunucusunu başlatır
├── global-teardown.ts                 # Test sonrası API sunucusunu durdurur
│
├── api-server/
│   ├── server.js                      # Güvenli API sunucusu (port 3000)
│   └── server-vulnerable.js           # Kasıtlı açıklı API sunucusu (port 3001)
│
├── .github/
│   └── workflows/
│       └── security-tests.yml         # GitHub Actions workflow
│
├── package.json
└── .env                               # API_BASE_URL, PORT, JWT_SECRET
```

---

## Test Dosyaları

### `bola.security.spec.ts`

**API1 – Broken Object Level Authorization (BOLA / IDOR)**

Kullanıcıların yalnızca kendi kaynaklarına erişebildiğini doğrular. Bir kullanıcının başka bir kullanıcının verisini okuyup okuyamadığını, değiştirip değiştiremediğini ve silebilip silemeyeceğini test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-BOLA-01 | User A kendi profiline erişebilmeli | Pozitif kontrol — meşru erişim 200 dönmeli |
| TC-BOLA-02 | User B kendi profiline erişebilmeli | Pozitif kontrol — meşru erişim 200 dönmeli |
| TC-BOLA-03 | `[EXPLOIT]` User B, User A profilini GET ile okuyamamalı | Yatay yetki yükseltme — 403/404 beklenir |
| TC-BOLA-04 | `[EXPLOIT]` User B, User A profilini PUT ile değiştirememeli | Başkasının profilini güncelleme — 403/404 beklenir |
| TC-BOLA-05 | `[EXPLOIT]` User B, User A profilini DELETE ile silememeli | Hesap silme saldırısı — 403/404 beklenir |
| TC-BOLA-06 | `[EXPLOIT]` User B, User A'ya ait siparişi okuyamamalı | Sipariş kaydına yetkisiz erişim — 403/404 beklenir |
| TC-BOLA-07 | `[EXPLOIT]` Sıralı ID brute-force — 10 farklı ID | Integer ID tahmin saldırısı — 0 başarılı erişim beklenir |
| TC-BOLA-08 | Token olmadan kaynaklara erişim engellenmiş olmalı | Kimlik doğrulama yokken 401/403 beklenir |
| TC-BOLA-09 | Admin her kullanıcıya erişebilmeli | Pozitif kontrol — admin için 200 beklenir |
| TC-BOLA-10 | Hata yanıtı hassas veri sızdırmamalı | 403 yanıtında `password`, `secret`, `token` olmamalı |

---

### `owasp-api-top10.security.spec.ts`

**API2 – Broken Authentication**

JWT token doğrulama ve brute-force korumasını test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-AUTH-01 | Geçersiz token ile erişim reddedilmeli | Rastgele string token → 401/403 |
| TC-AUTH-02 | Süresi dolmuş token ile erişim reddedilmeli | Expire edilmiş JWT → 401/403 |
| TC-AUTH-03 | Token olmadan erişim reddedilmeli | Authorization header yok → 401/403 |
| TC-AUTH-04 | Brute-force — 10 hatalı deneme sonrası rate-limit | 10 paralel yanlış şifre → en az 1 tane 429 beklenir |
| TC-AUTH-05 | `alg:none` JWT kabul edilmemeli | İmzasız token algoritma saldırısı → 401/403 |

---

**API3 – Broken Object Property Level Authorization**

Mass assignment ve hassas veri ifşası açıklarını test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-BOPLA-01 | Kullanıcı kendi rolünü yükseltemememeli | `role: "admin"` PUT ile göndermek → rol değişmemeli |
| TC-BOPLA-02 | Yanıtta hassas alanlar olmamalı | `password`, `passwordHash`, `secretKey` response'da görünmemeli |
| TC-BOPLA-03 | PATCH ile sadece izin verilen alanlar güncellenmeli | `credits: 99999`, `verified: true` → değişmemeli |

---

**API4 – Unrestricted Resource Consumption**

Payload boyutu, sayfalama limiti ve rate limiting kontrollerini test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-CONS-01 | 10 MB payload → 413 dönmeli | Body size limit kontrolü |
| TC-CONS-02 | `limit=10000` sayfalama isteği throttle edilmeli | Maksimum 100 kayıt dönmeli |
| TC-CONS-03 | 20 paralel istek → rate limit devreye girmeli | En az 1 tane 429 beklenir |

---

**API5 – Broken Function Level Authorization**

Normal kullanıcının admin endpoint'lerine erişimini test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-BFLA-01 | Normal kullanıcı `/api/admin/users` erişememeli | Admin endpoint'e yetkisiz erişim → 403/404 |
| TC-BFLA-02 | Normal kullanıcı admin ile kullanıcı silememeli | `DELETE /api/admin/users/:id` → 403/404 |
| TC-BFLA-03 | HTTP method değiştirerek bypass edilememeli | POST/PUT/PATCH ile admin config → 403/404/405 |

---

**API6 – Unrestricted Access to Sensitive Business Flows**

Race condition, self-referral ve negatif miktar açıklarını test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-FLOW-01 | 10 paralel satın alma — sadece 1 başarılı olmalı | Stok race condition koruması |
| TC-FLOW-02 | Kullanıcı kendi referral kodunu kullanamaz | Self-referral engeli → 400/403/422 |
| TC-FLOW-03 | Negatif miktar ile sipariş verilememeli | `quantity: -1` → 400/422 |

---

**API7 – Server Side Request Forgery (SSRF)**

Webhook URL'lerinde internal/private adreslere erişim engelini test eder.

| Test ID | SSRF Payload | Açıklama |
|---------|-------------|----------|
| TC-SSRF-1 | `http://169.254.169.254/latest/meta-data/` | AWS metadata endpoint → 400/403/422 |
| TC-SSRF-2 | `http://metadata.google.internal/...` | GCP metadata endpoint → 400/403/422 |
| TC-SSRF-3 | `http://localhost:8080/admin` | Internal servis erişimi → 400/403/422 |
| TC-SSRF-4 | `http://127.0.0.1:22` | SSH port tarama → 400/403/422 |
| TC-SSRF-5 | `file:///etc/passwd` | Local dosya okuma → 400/403/422 |
| TC-SSRF-6 | `http://[::1]/admin` | IPv6 loopback → 400/403/422 |

---

**API8 – Security Misconfiguration**

Güvenlik header'ları, stack trace ifşası, açık debug endpoint'leri ve CORS yapılandırmasını test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-MISCONF-01 | Güvenlik HTTP header'ları mevcut olmalı | `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security` |
| TC-MISCONF-02 | Hata yanıtı stack trace sızdırmamalı | `Error:`, `at Object.`, `.js:42` gibi ifadeler yanıtta olmamalı |
| TC-MISCONF-03 | Debug/Swagger endpoint'leri kapalı olmalı | `/swagger`, `/__debug`, `/actuator`, `/metrics` → 401/403/404 |
| TC-MISCONF-04 | CORS wildcard (`*`) kullanılmamalı | `Origin: evil.com` ile istek → `Access-Control-Allow-Origin: *` olmamalı |

---

**API9 – Improper Inventory Management**

Eski API versiyonları ve belgelenmemiş endpoint'leri test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-INV-01 | API v1 aktif olmamalı veya deprecated header dönmeli | `/api/v1/users/me` → 404/410 veya `Deprecation` header |
| TC-INV-02 | Internal endpoint'ler erişilebilir olmamalı | `/api/internal`, `/api/v0/users`, `/api/beta/admin` → 401/403/404 |

---

**API10 – Unsafe Consumption of APIs**

URL whitelist, XSS sanitizasyon ve open redirect açıklarını test eder.

| Test ID | Test Adı | Açıklama |
|---------|----------|----------|
| TC-UNSAFE-01 | Whitelist dışı webhook URL reddedilmeli | `http://attacker.com`, `http://localhost` → 400/403/422 |
| TC-UNSAFE-02 | XSS payload store edilip servis edilmemeli | `<script>alert('xss')</script>` → sanitize edilmeli |
| TC-UNSAFE-03 | Open redirect olmamalı | `?redirect=http://evil.com` → dış URL'e yönlendirme olmamalı |

---

## API Sunucuları

### `server.js` — Güvenli API (Port 3000)

Tüm OWASP güvenlik kontrollerini uygular. Tüm testler **PASS** olur.

### `server-vulnerable.js` — Açıklı API (Port 3001)

Kasıtlı olarak güvensiz yazılmıştır. Testler çalıştırıldığında güvenlik açıkları **tespit edilir** ve testler **FAIL** olur.

**Kasıtlı açıklar:**

| OWASP | Açık |
|-------|------|
| API1 | Object-level yetki kontrolü yok — her kullanıcı herkese erişebilir |
| API2 | `jwt.decode()` kullanılıyor (doğrulama yok), brute-force koruması yok, `alg:none` kabul ediliyor |
| API3 | `Object.assign(user, req.body)` — tüm alanlar mass-assignment ile değiştirilebilir |
| API4 | Body size limiti yok, sayfalama kısıtı yok, rate limiting yok |
| API5 | Admin endpoint'lerde rol kontrolü yok |
| API6 | Race condition koruması yok, self-referral kontrolü yok, negatif miktar kontrolü yok |
| API7 | Webhook URL doğrulaması yok — internal adresler kabul ediliyor |
| API8 | Güvenlik header'ları yok, CORS wildcard (`*`), stack trace ifşa ediliyor |
| API9 | API v1 aktif, internal route'lar erişilebilir |
| API10 | URL whitelist yok, XSS sanitizasyonu yok, open redirect var |

**Ön tanımlı kullanıcılar (her iki sunucu için aynı):**

| E-posta | Şifre | ID | Rol |
|---------|-------|----|-----|
| user_a@test.com | Password123! | 10 | user |
| user_b@test.com | Password123! | 2 | user |
| admin@test.com | AdminPass123! | 3 | admin |

---

## Kurulum

**Gereksinimler:** Node.js 18+

```bash
# 1. Bağımlılıkları kur
npm install
cd api-server && npm install && cd ..
```

---

## Testleri Çalıştırma

### Güvenli API — Tüm testler PASS

```bash
npx playwright test
```

### Açıklı API — Güvenlik açıkları tespit edilir (FAIL beklenir)

```bash
npx playwright test --config=playwright.config.vulnerable.ts
```

### Belirli bir dosya

```bash
# Sadece BOLA testleri
npx playwright test bola.security.spec.ts

# Sadece OWASP Top 10 testleri
npx playwright test owasp-api-top10.security.spec.ts
```

### HTML rapor görüntüleme

```bash
npx playwright test
npx playwright show-report
```

### API sunucusunu manuel başlatma

```bash
# Güvenli API
node api-server/server.js

# Açıklı API
node api-server/server-vulnerable.js
```

> **Not:** `globalSetup` sayesinde testler çalıştırıldığında API sunucusu otomatik başlar ve biter. Manuel başlatmaya gerek yoktur.

---

## GitHub Actions

Repo → **Actions** sekmesi → **OWASP API Security Tests** → **Run workflow**

| Seçenek | Komut | Beklenen Sonuç |
|---------|-------|----------------|
| `secure` | `npx playwright test` | 42/42 PASS |
| `vulnerable` | `npx playwright test --config=playwright.config.vulnerable.ts` | ~16 FAIL |
| `both` | Her ikisi sırayla | Secure PASS + Vulnerable FAIL |

Her çalıştırmada HTML rapor **artifact** olarak 30 gün saklanır.

> Testler `APIRequestContext` kullanır (saf HTTP, browser açılmaz). Bu nedenle `playwright install` adımı atlanır ve CI süresi kısalır.

---

## Test Sonuçları

| Mod | Toplam | PASS | FAIL |
|-----|--------|------|------|
| Güvenli API | 42 | 42 | 0 |
| Açıklı API | 42 | ~5 | ~16 (+21 skip) |

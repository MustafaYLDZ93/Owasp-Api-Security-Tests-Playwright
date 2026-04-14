import { test, expect, APIRequestContext, request } from "@playwright/test";

/**
 * OWASP API Security Top 10 (2023) — Playwright Security Test Suite
 *
 * API1  – BOLA  → bola.security.spec.ts (ayrı dosya, bu dosyada YOK)
 * API2  – Broken Authentication
 * API3  – Broken Object Property Level Authorization
 * API4  – Unrestricted Resource Consumption
 * API5  – Broken Function Level Authorization
 * API6  – Unrestricted Access to Sensitive Business Flows
 * API7  – Server Side Request Forgery (SSRF)
 * API8  – Security Misconfiguration
 * API9  – Improper Inventory Management
 * API10 – Unsafe Consumption of APIs
 */

const BASE_URL = process.env.API_BASE_URL ?? "http://localhost:3000";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function login(
  ctx: APIRequestContext,
  email: string,
  password: string
): Promise<string> {
  const res = await ctx.post(`${BASE_URL}/api/auth/login`, {
    data: { email, password },
  });
  expect(res.status(), `Login failed for ${email}`).toBe(200);
  const body = await res.json();
  return body.token as string;
}

async function authHeader(token: string) {
  return { Authorization: `Bearer ${token}` };
}

// ---------------------------------------------------------------------------
// API2 – Broken Authentication
// ---------------------------------------------------------------------------

test.describe("API2 – Broken Authentication", () => {
  let ctx: APIRequestContext;

  test.beforeAll(async () => {
    ctx = await request.newContext();
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-AUTH-01 | Geçersiz token ile korumalı endpoint erişimi reddedilmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: { Authorization: "Bearer invalid.token.here" },
    });
    expect([401, 403]).toContain(res.status());
  });

  test("TC-AUTH-02 | Süresi dolmuş token ile erişim reddedilmeli", async () => {
    // Önceden expire edilmiş bir JWT (iat/exp geçmişte)
    const expiredToken =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyX2EiLCJpYXQiOjE2MDAwMDAwMDAsImV4cCI6MTYwMDAwMDAwMX0.INVALID";
    const res = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${expiredToken}` },
    });
    expect([401, 403]).toContain(res.status());
  });

  test("TC-AUTH-03 | Token olmadan korumalı endpoint erişimi reddedilmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/me`);
    expect([401, 403]).toContain(res.status());
  });

  test("TC-AUTH-04 | Brute-force login — 10 hatalı deneme sonrası hesap kilitlenmeli veya rate-limit devreye girmeli", async () => {
    const attempts = Array.from({ length: 10 }, (_, i) =>
      ctx.post(`${BASE_URL}/api/auth/login`, {
        data: { email: "user_a@test.com", password: `WrongPass${i}!` },
      })
    );
    const results = await Promise.all(attempts);
    const statuses = results.map((r) => r.status());

    // En az bir 429 (rate-limit) veya 423 (locked) bekleniyor
    const blocked = statuses.filter((s) => [423, 429].includes(s));
    expect(
      blocked.length,
      `Brute-force koruması yok! Tüm yanıtlar: ${statuses}`
    ).toBeGreaterThan(0);
  });

  test("TC-AUTH-05 | Algoritma karıştırma — alg:none JWT kabul edilmemeli", async () => {
    // alg:none saldırısı: imzasız token
    const algNoneToken = Buffer.from(
      JSON.stringify({ alg: "none", typ: "JWT" })
    )
      .toString("base64url")
      .concat(
        "." +
          Buffer.from(JSON.stringify({ sub: "admin", role: "admin" })).toString(
            "base64url"
          ) +
          "."
      );

    const res = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: { Authorization: `Bearer ${algNoneToken}` },
    });
    expect([401, 403]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// API3 – Broken Object Property Level Authorization
// ---------------------------------------------------------------------------

test.describe("API3 – Broken Object Property Level Authorization", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-BOPLA-01 | Kullanıcı kendi rolünü mass-assignment ile yükseltemememeli", async () => {
    const res = await ctx.put(`${BASE_URL}/api/users/me`, {
      headers: await authHeader(userToken),
      data: { name: "Legit Update", role: "admin", isAdmin: true },
    });

    // Güncelleme başarılı olsa bile role değişmemiş olmalı
    if (res.status() === 200) {
      const body = await res.json();
      expect(body.role, "Mass assignment açığı! role admin'e yükseltildi").not.toBe("admin");
      expect(body.isAdmin, "Mass assignment açığı! isAdmin true yapıldı").not.toBe(true);
    } else {
      expect([400, 403]).toContain(res.status());
    }
  });

  test("TC-BOPLA-02 | Yanıtta hassas alanlar (password hash, internalNotes) olmamalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: await authHeader(userToken),
    });
    expect(res.status()).toBe(200);
    const body = await res.json();

    const forbiddenFields = ["password", "passwordHash", "internalNotes", "secretKey", "twoFactorSecret"];
    for (const field of forbiddenFields) {
      expect(body, `Excessive data exposure: '${field}' alanı response'da mevcut`).not.toHaveProperty(field);
    }
  });

  test("TC-BOPLA-03 | PATCH ile sadece izin verilen alanlar güncellenebilmeli", async () => {
    const res = await ctx.patch(`${BASE_URL}/api/users/me`, {
      headers: await authHeader(userToken),
      data: { email: "newemail@test.com", verified: true, credits: 99999 },
    });

    if (res.status() === 200) {
      const body = await res.json();
      expect(body.credits, "Mass assignment: credits manipüle edildi").not.toBe(99999);
      expect(body.verified, "Mass assignment: verified flag manipüle edildi").not.toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// API4 – Unrestricted Resource Consumption
// ---------------------------------------------------------------------------

test.describe("API4 – Unrestricted Resource Consumption", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-CONS-01 | Çok büyük payload gönderildiğinde 413 dönmeli", async () => {
    const hugePayload = { data: "x".repeat(10 * 1024 * 1024) }; // 10 MB
    const res = await ctx.post(`${BASE_URL}/api/data`, {
      headers: await authHeader(userToken),
      data: hugePayload,
    });
    expect(
      [400, 413, 422],
      `Büyük payload kabul edildi! HTTP ${res.status()}`
    ).toContain(res.status());
  });

  test("TC-CONS-02 | Sayfalama parametresi limit=10000 olduğunda throttle edilmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users?limit=10000&page=1`, {
      headers: await authHeader(userToken),
    });

    if (res.status() === 200) {
      const body = await res.json();
      const returned = Array.isArray(body.data) ? body.data.length : body.length;
      expect(
        returned,
        `Limit kontrolü yok! 10000 kayıt döndü`
      ).toBeLessThanOrEqual(100);
    } else {
      expect([400, 429]).toContain(res.status());
    }
  });

  test("TC-CONS-03 | Paralel 20 istek — rate limit devreye girmeli", async () => {
    const hdrs = await authHeader(userToken);
    const requests = Array.from({ length: 20 }, () =>
      ctx.get(`${BASE_URL}/api/users/me`, {
        headers: hdrs,
      })
    );
    const results = await Promise.all(requests);
    const statuses = results.map((r) => r.status());
    const rateLimited = statuses.filter((s) => s === 429);

    expect(
      rateLimited.length,
      `Rate limiting yok! 20 paralel isteğin tamamı kabul edildi`
    ).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// API5 – Broken Function Level Authorization
// ---------------------------------------------------------------------------

test.describe("API5 – Broken Function Level Authorization", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-BFLA-01 | Normal kullanıcı admin endpoint'e erişememeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/admin/users`, {
      headers: await authHeader(userToken),
    });
    expect([403, 404]).toContain(res.status());
  });

  test("TC-BFLA-02 | Normal kullanıcı admin ile kullanıcı silememeli", async () => {
    const res = await ctx.delete(`${BASE_URL}/api/admin/users/1`, {
      headers: await authHeader(userToken),
    });
    expect([403, 404]).toContain(res.status());
  });

  test("TC-BFLA-03 | Normal kullanıcı HTTP method değiştirerek erişim sağlayamamalı", async () => {
    // Bazı API'lar GET'i kısıtlar ama POST/PUT'u kısıtlamaz
    const methods = ["POST", "PUT", "PATCH"] as const;

    for (const method of methods) {
      const res = await ctx.fetch(`${BASE_URL}/api/admin/config`, {
        method,
        headers: await authHeader(userToken),
        data: {},
      });
      expect(
        [403, 404, 405],
        `BFLA: ${method} /admin/config → HTTP ${res.status()}`
      ).toContain(res.status());
    }
  });
});

// ---------------------------------------------------------------------------
// API6 – Unrestricted Access to Sensitive Business Flows
// ---------------------------------------------------------------------------

test.describe("API6 – Unrestricted Access to Sensitive Business Flows", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-FLOW-01 | Aynı ürün için paralel 10 satın alma isteği — sadece 1 başarılı olmalı", async () => {
    const LIMITED_PRODUCT_ID = "promo-item-001";

    const hdrs = await authHeader(userToken);
    const purchases = Array.from({ length: 10 }, () =>
      ctx.post(`${BASE_URL}/api/orders`, {
        headers: hdrs,
        data: { productId: LIMITED_PRODUCT_ID, quantity: 1 },
      })
    );

    const results = await Promise.all(purchases);
    const successful = results.filter((r) => r.status() === 201);

    expect(
      successful.length,
      `Race condition açığı! ${successful.length} paralel sipariş oluşturuldu`
    ).toBeLessThanOrEqual(1);
  });

  test("TC-FLOW-02 | Referral kodu kendi kendine uygulanamaz (self-referral)", async () => {
    // Kullanıcının kendi referral kodunu kullanması engellenmeli
    const profileRes = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: await authHeader(userToken),
    });
    const profile = await profileRes.json();

    const res = await ctx.post(`${BASE_URL}/api/referrals/apply`, {
      headers: await authHeader(userToken),
      data: { code: profile.referralCode },
    });

    expect([400, 403, 422]).toContain(res.status());
  });

  test("TC-FLOW-03 | Negatif miktar ile sipariş verilememeli", async () => {
    const res = await ctx.post(`${BASE_URL}/api/orders`, {
      headers: await authHeader(userToken),
      data: { productId: "product-001", quantity: -1 },
    });
    expect([400, 422]).toContain(res.status());
  });
});

// ---------------------------------------------------------------------------
// API7 – Server Side Request Forgery (SSRF)
// ---------------------------------------------------------------------------

test.describe("API7 – Server Side Request Forgery (SSRF)", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  const ssrfPayloads = [
    "http://169.254.169.254/latest/meta-data/",          // AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/", // GCP metadata
    "http://localhost:8080/admin",                         // Internal service
    "http://127.0.0.1:22",                                // SSH port
    "file:///etc/passwd",                                  // Local file
    "http://[::1]/admin",                                  // IPv6 loopback
  ];

  for (const payload of ssrfPayloads) {
    test(`TC-SSRF | SSRF payload reddedilmeli: ${payload}`, async () => {
      const res = await ctx.post(`${BASE_URL}/api/webhooks`, {
        headers: await authHeader(userToken),
        data: { url: payload },
      });

      expect(
        [400, 403, 422],
        `SSRF açığı! Payload kabul edildi: ${payload}`
      ).toContain(res.status());

      // Yanıt body'de internal bilgi olmamalı
      const text = await res.text();
      expect(text).not.toMatch(/root:/);
      expect(text).not.toMatch(/ami-id/);
      expect(text).not.toMatch(/computeMetadata/);
    });
  }
});

// ---------------------------------------------------------------------------
// API8 – Security Misconfiguration
// ---------------------------------------------------------------------------

test.describe("API8 – Security Misconfiguration", () => {
  let ctx: APIRequestContext;

  test.beforeAll(async () => {
    ctx = await request.newContext();
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-MISCONF-01 | Güvenlik HTTP header'ları mevcut olmalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/health`);
    const headers = res.headers();

    const requiredHeaders: Record<string, RegExp> = {
      "x-content-type-options": /nosniff/i,
      "x-frame-options": /deny|sameorigin/i,
      "strict-transport-security": /max-age/i,
    };

    for (const [header, pattern] of Object.entries(requiredHeaders)) {
      expect(
        headers[header],
        `Güvenlik header'ı eksik veya yanlış: ${header}`
      ).toMatch(pattern);
    }
  });

  test("TC-MISCONF-02 | Hata yanıtı stack trace sızdırmamalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/INVALID_ID_FORMAT`);
    const text = await res.text();

    expect(text).not.toMatch(/at Object\./);
    expect(text).not.toMatch(/Error:/);
    expect(text).not.toMatch(/\.js:\d+/);
  });

  test("TC-MISCONF-03 | Debug / swagger endpoint production'da kapalı olmalı", async () => {
    const sensitiveRoutes = [
      "/swagger",
      "/swagger-ui",
      "/api-docs",
      "/graphql-playground",
      "/__debug",
      "/actuator",
      "/metrics",
    ];

    for (const route of sensitiveRoutes) {
      const res = await ctx.get(`${BASE_URL}${route}`);
      expect(
        [401, 403, 404],
        `Hassas endpoint açık: ${route} → HTTP ${res.status()}`
      ).toContain(res.status());
    }
  });

  test("TC-MISCONF-04 | CORS wildcard (*) hassas endpointlerde olmamalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/me`, {
      headers: { Origin: "https://evil.com" },
    });
    const acao = res.headers()["access-control-allow-origin"];

    expect(
      acao,
      "CORS wildcard açığı! Tüm originlere izin veriliyor"
    ).not.toBe("*");
  });
});

// ---------------------------------------------------------------------------
// API9 – Improper Inventory Management
// ---------------------------------------------------------------------------

test.describe("API9 – Improper Inventory Management", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-INV-01 | Eski API versiyonu (v1) production'da aktif olmamalı veya deprecated header dönmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/v1/users/me`, {
      headers: await authHeader(userToken),
    });

    if (res.status() === 200) {
      const headers = res.headers();
      // En azından deprecated uyarısı dönmeli
      const deprecationHeaders = ["deprecation", "sunset", "warning"];
      const hasDeprecationNotice = deprecationHeaders.some((h) => headers[h]);
      expect(
        hasDeprecationNotice,
        "Eski API v1 aktif ama deprecated/sunset header yok"
      ).toBe(true);
    } else {
      expect([404, 410]).toContain(res.status());
    }
  });

  test("TC-INV-02 | Dokümante edilmemiş endpoint — /api/internal erişilebilir olmamalı", async () => {
    const internalRoutes = [
      "/api/internal",
      "/api/internal/users",
      "/api/v0/users",
      "/api/beta/admin",
    ];

    for (const route of internalRoutes) {
      const res = await ctx.get(`${BASE_URL}${route}`, {
        headers: await authHeader(userToken),
      });
      expect(
        [401, 403, 404],
        `Gizli endpoint erişilebilir: ${route} → HTTP ${res.status()}`
      ).toContain(res.status());
    }
  });
});

// ---------------------------------------------------------------------------
// API10 – Unsafe Consumption of APIs
// ---------------------------------------------------------------------------

test.describe("API10 – Unsafe Consumption of APIs", () => {
  let ctx: APIRequestContext;
  let userToken: string;

  test.beforeAll(async () => {
    ctx = await request.newContext();
    userToken = await login(ctx, "user_a@test.com", "Password123!");
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  test("TC-UNSAFE-01 | Üçüncü taraf webhook URL'i whitelist dışındaysa reddedilmeli", async () => {
    const untrustedUrls = [
      "http://attacker.com/hook",
      "http://169.254.169.254",
      "http://localhost/hook",
    ];

    for (const url of untrustedUrls) {
      const res = await ctx.post(`${BASE_URL}/api/integrations/webhook`, {
        headers: await authHeader(userToken),
        data: { callbackUrl: url },
      });
      expect(
        [400, 403, 422],
        `Güvensiz URL kabul edildi: ${url}`
      ).toContain(res.status());
    }
  });

  test("TC-UNSAFE-02 | Üçüncü taraf API'den gelen XSS payload store edilip servis edilmemeli", async () => {
    // API, dış kaynaktan veri çekip saklıyorsa XSS sanitization kontrolü
    const xssPayload = "<script>alert('xss')</script>";

    const res = await ctx.post(`${BASE_URL}/api/products/import`, {
      headers: await authHeader(userToken),
      data: { name: xssPayload, source: "external" },
    });

    if (res.status() === 200 || res.status() === 201) {
      const body = await res.json();
      const bodyStr = JSON.stringify(body);
      expect(bodyStr).not.toContain("<script>");
      expect(bodyStr).not.toContain("alert(");
    }
  });

  test("TC-UNSAFE-03 | Redirect zinciri — open redirect olmamalı", async () => {
    const res = await ctx.get(
      `${BASE_URL}/api/auth/callback?redirect=http://evil.com`,
      {
        headers: await authHeader(userToken),
      }
    );

    if ([301, 302, 307, 308].includes(res.status())) {
      const location = res.headers()["location"] ?? "";
      expect(
        location,
        `Open redirect açığı! Dış URL'e yönlendirme: ${location}`
      ).not.toMatch(/^https?:\/\/(?!localhost|127\.0\.0\.1)/);
    }
  });
});

import { test, expect, APIRequestContext, request } from "@playwright/test";

/**
 * BOLA (Broken Object Level Authorization) Security Tests
 * OWASP API Security Top 10 - API1:2023
 *
 * Senaryo:
 *  - user_a kendi kaynağına erişebilmeli
 *  - user_b, user_a'nın kaynağına erişememeli (BOLA açığı yoksa 403/404 dönmeli)
 *  - Authenticated ama yetkisiz erişim → exploit tespiti
 */

// ---------------------------------------------------------------------------
// Test fixtures & helpers
// ---------------------------------------------------------------------------

const BASE_URL = process.env.API_BASE_URL ?? "http://localhost:3000";

interface AuthTokens {
  userA: string;
  userB: string;
  admin: string;
}

interface UserProfile {
  id: string;
  email: string;
  role: string;
}

/** Login helper — returns JWT bearer token */
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

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

test.describe("BOLA – Broken Object Level Authorization", () => {
  let tokens: AuthTokens;
  let userAProfile: UserProfile;
  let userBProfile: UserProfile;
  let ctx: APIRequestContext;

  // ── Setup ────────────────────────────────────────────────────────────────

  test.beforeAll(async () => {
    ctx = await request.newContext();

    // Her kullanıcı için token al
    const [tokenA, tokenB, tokenAdmin] = await Promise.all([
      login(ctx, "user_a@test.com", "Password123!"),
      login(ctx, "user_b@test.com", "Password123!"),
      login(ctx, "admin@test.com", "AdminPass123!"),
    ]);

    tokens = { userA: tokenA, userB: tokenB, admin: tokenAdmin };

    // Profil bilgilerini çek (ID'ler sonraki testlerde kullanılacak)
    const [resA, resB] = await Promise.all([
      ctx.get(`${BASE_URL}/api/users/me`, {
        headers: { Authorization: `Bearer ${tokenA}` },
      }),
      ctx.get(`${BASE_URL}/api/users/me`, {
        headers: { Authorization: `Bearer ${tokenB}` },
      }),
    ]);

    userAProfile = await resA.json();
    userBProfile = await resB.json();
  });

  test.afterAll(async () => {
    await ctx.dispose();
  });

  // ── 1. Baseline: meşru erişimler ─────────────────────────────────────────

  test("TC-BOLA-01 | User A kendi profiline erişebilmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userA}` },
    });

    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.id).toBe(userAProfile.id);
  });

  test("TC-BOLA-02 | User B kendi profiline erişebilmeli", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userBProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userB}` },
    });

    expect(res.status()).toBe(200);
  });

  // ── 2. BOLA exploits: yatay yetki yükseltme ─────────────────────────────

  test("TC-BOLA-03 | [EXPLOIT] User B, User A'nın profilini GET ile okuyamamalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userB}` },
    });

    // Beklenen: 403 Forbidden veya 404 Not Found
    expect(
      [403, 404],
      `BOLA AÇIĞI! User B, User A'nın (id=${userAProfile.id}) profilini okudu. HTTP ${res.status()}`
    ).toContain(res.status());
  });

  test("TC-BOLA-04 | [EXPLOIT] User B, User A'nın profilini PUT ile değiştiremememeli", async () => {
    const res = await ctx.put(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userB}` },
      data: { email: "hacked@evil.com" },
    });

    expect(
      [403, 404],
      `BOLA AÇIĞI! User B, User A'nın profilini güncelledi. HTTP ${res.status()}`
    ).toContain(res.status());
  });

  test("TC-BOLA-05 | [EXPLOIT] User B, User A'nın profilini DELETE ile silememeli", async () => {
    const res = await ctx.delete(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userB}` },
    });

    expect(
      [403, 404],
      `BOLA AÇIĞI! User B, User A'nın hesabını sildi. HTTP ${res.status()}`
    ).toContain(res.status());
  });

  // ── 3. BOLA – Sipariş / kaynak tabanlı ──────────────────────────────────

  test("TC-BOLA-06 | [EXPLOIT] User B, User A'ya ait siparişi okuyamamalı", async () => {
    // Önce User A'nın bir siparişi olduğunu varsayıyoruz
    // (fixture veya beforeAll ile oluşturulmuş olabilir)
    const ordersRes = await ctx.get(`${BASE_URL}/api/orders`, {
      headers: { Authorization: `Bearer ${tokens.userA}` },
    });
    expect(ordersRes.status()).toBe(200);

    const orders = await ordersRes.json();
    if (!orders.length) {
      test.skip(); // Sipariş yoksa testi atla
      return;
    }

    const firstOrderId = orders[0].id;

    // User B bu siparişe erişmeye çalışıyor
    const attackRes = await ctx.get(
      `${BASE_URL}/api/orders/${firstOrderId}`,
      {
        headers: { Authorization: `Bearer ${tokens.userB}` },
      }
    );

    expect(
      [403, 404],
      `BOLA AÇIĞI! User B, User A'nın sipariş (id=${firstOrderId}) detayını okudu.`
    ).toContain(attackRes.status());
  });

  // ── 4. IDOR via GUID enumeration ─────────────────────────────────────────

  test("TC-BOLA-07 | [EXPLOIT] Sıralı ID brute-force — 10 farklı ID denenecek", async () => {
    /**
     * Gerçek dünya senaryosu: saldırgan integer ID'leri tahmin eder.
     * Test, yetkisiz erişim başarı oranını ölçer.
     */
    const baseId = parseInt(userAProfile.id, 10);
    const attempts = Array.from({ length: 10 }, (_, i) => baseId - 5 + i).filter(
      (id) => id > 0 && id.toString() !== userBProfile.id
    );

    const results = await Promise.all(
      attempts.map((id) =>
        ctx
          .get(`${BASE_URL}/api/users/${id}`, {
            headers: { Authorization: `Bearer ${tokens.userB}` },
          })
          .then((r) => ({ id, status: r.status() }))
      )
    );

    const leaks = results.filter((r) => r.status === 200);

    expect(
      leaks,
      `BOLA AÇIĞI! User B, ${leaks.length} farklı kullanıcı profiline erişebildi: ${JSON.stringify(leaks)}`
    ).toHaveLength(0);
  });

  // ── 5. Unauthenticated erişim ────────────────────────────────────────────

  test("TC-BOLA-08 | Token olmadan kaynaklara erişim engellenmiş olmalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userAProfile.id}`);

    expect(
      [401, 403],
      `Auth middleware eksik! HTTP ${res.status()}`
    ).toContain(res.status());
  });

  // ── 6. Admin meşru erişim ────────────────────────────────────────────────

  test("TC-BOLA-09 | Admin her kullanıcıya erişebilmeli (pozitif kontrol)", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.admin}` },
    });

    // Admin için 200 bekleniyor
    expect(res.status()).toBe(200);
  });

  // ── 7. Response body sızıntı kontrolü ───────────────────────────────────

  test("TC-BOLA-10 | Hata yanıtı hassas veri sızdırmamalı", async () => {
    const res = await ctx.get(`${BASE_URL}/api/users/${userAProfile.id}`, {
      headers: { Authorization: `Bearer ${tokens.userB}` },
    });

    const text = await res.text();
    const sensitivePatterns = [
      /password/i,
      /secret/i,
      /token/i,
      /internal server error/i,
      /stack trace/i,
      /sql/i,
    ];

    for (const pattern of sensitivePatterns) {
      expect(
        text,
        `Hata yanıtı hassas veri içeriyor: ${pattern}`
      ).not.toMatch(pattern);
    }
  });
});

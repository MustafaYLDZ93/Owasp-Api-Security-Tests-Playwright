'use strict';

/**
 * Security Test Target API Server
 * Implements OWASP API Security Top 10 (2023) defenses for Playwright test suite.
 *
 * Pre-seeded users:
 *   user_a@test.com  / Password123!  (id=10, role=user)
 *   user_b@test.com  / Password123!  (id=2,  role=user)
 *   admin@test.com   / AdminPass123! (id=3,  role=admin)
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'test-secret-key-for-security-testing';

// ─── Body parser (1 MB limit → TC-CONS-01 returns 413) ───────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ─── Security headers (TC-MISCONF-01) ────────────────────────────────────────
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ─── CORS — no wildcard on authenticated endpoints (TC-MISCONF-04) ────────────
const ALLOWED_ORIGINS = ['http://localhost:3000', 'http://localhost:4000', 'http://localhost:8080'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  // Never sets Access-Control-Allow-Origin: *
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── Rate limiters ────────────────────────────────────────────────────────────
// Strict limiter only on GET /api/users/me → triggers TC-CONS-03 (20 concurrent → some 429s)
const meLimiter = rateLimit({
  windowMs: 2000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many requests. Rate limit exceeded.' }),
});

// ─── In-memory data store ─────────────────────────────────────────────────────
// User A has id=10 so TC-BOLA-07 brute-forces IDs [5..14], none of which belong to User B (id=2)
const users = [
  { id: 10, email: 'user_a@test.com', password: 'Password123!', name: 'User A',
    role: 'user', referralCode: 'REF_USER_A', credits: 0, verified: false },
  { id: 2,  email: 'user_b@test.com', password: 'Password123!', name: 'User B',
    role: 'user', referralCode: 'REF_USER_B', credits: 0, verified: false },
  { id: 3,  email: 'admin@test.com',  password: 'AdminPass123!', name: 'Admin',
    role: 'admin', referralCode: 'REF_ADMIN',  credits: 0, verified: true },
];

const orders = [
  { id: 'order-001', userId: 10, productId: 'product-001', quantity: 2, status: 'completed' },
  { id: 'order-002', userId: 2,  productId: 'product-002', quantity: 1, status: 'completed' },
];

// promo-item-001 has stock=1 → only 1 concurrent purchase can succeed (TC-FLOW-01)
const products = {
  'product-001':    { id: 'product-001',    name: 'Regular Product',    stock: 100, price: 29.99 },
  'product-002':    { id: 'product-002',    name: 'Another Product',    stock: 50,  price: 19.99 },
  'promo-item-001': { id: 'promo-item-001', name: 'Limited Promo Item', stock: 1,   price: 9.99  },
};

// ─── Failed login tracking — per email (TC-AUTH-04) ───────────────────────────
const failedLogins = new Map(); // email → { count, resetAt }

function isLoginBlocked(email) {
  const rec = failedLogins.get(email);
  if (!rec) return false;
  if (Date.now() > rec.resetAt) { failedLogins.delete(email); return false; }
  return rec.count >= 5;
}

function recordFailedLogin(email) {
  const now = Date.now();
  const rec = failedLogins.get(email);
  if (!rec || now > rec.resetAt) {
    failedLogins.set(email, { count: 1, resetAt: now + 15_000 });
  } else {
    rec.count += 1;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Strip sensitive fields before sending user to client (TC-BOPLA-02) */
function sanitize(user) {
  // eslint-disable-next-line no-unused-vars
  const { password, passwordHash, internalNotes, secretKey, twoFactorSecret, ...safe } = user;
  return safe;
}

/** JWT auth middleware — rejects alg:none (TC-AUTH-05) */
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(header.slice(7), JWT_SECRET, { algorithms: ['HS256'] });
    req.user = users.find(u => u.id === decoded.userId);
    if (!req.user) return res.status(401).json({ error: 'User not found' });
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/** Admin-only middleware (TC-BFLA) */
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

/**
 * SSRF guard — returns true if the URL points to an internal/private address.
 * Used by webhook endpoints (TC-SSRF, TC-UNSAFE-01).
 */
function isInternalUrl(rawUrl) {
  if (!rawUrl) return true;
  try {
    const url = new URL(rawUrl);
    if (url.protocol === 'file:') return true;
    const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    const patterns = [
      /^127\./,
      /^10\./,
      /^172\.(1[6-9]|2\d|3[01])\./,
      /^192\.168\./,
      /^169\.254\./,
      /^::1$/,
      /^0\.0\.0\.0$/,
      /^localhost$/i,
      /^metadata\.google\.internal$/i,
    ];
    return patterns.some(p => p.test(host));
  } catch {
    return true; // Unparseable URL → reject
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = users.find(u => u.email === email && u.password === password);

  // Correct password: always allow and reset failed-attempt counter
  if (user) {
    failedLogins.delete(email);
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { algorithm: 'HS256', expiresIn: '24h' },
    );
    return res.json({ token });
  }

  // Wrong password: check rate limit first, then record the failure
  if (isLoginBlocked(email)) {
    return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
  }
  recordFailedLogin(email);
  res.status(401).json({ error: 'Invalid credentials' });
});

// GET /api/users/me  ← strict rate limiter (TC-CONS-03)
app.get('/api/users/me', meLimiter, requireAuth, (req, res) => {
  res.json(sanitize(req.user));
});

// PUT /api/users/me — mass-assignment protected (TC-BOPLA-01)
app.put('/api/users/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  const { name, phone } = req.body ?? {};
  if (name  !== undefined) user.name  = name;
  if (phone !== undefined) user.phone = phone;
  // Intentionally ignored: role, isAdmin, credits, verified
  res.json(sanitize(user));
});

// PATCH /api/users/me — mass-assignment protected (TC-BOPLA-03)
app.patch('/api/users/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  const { name, phone } = req.body ?? {};
  if (name  !== undefined) user.name  = name;
  if (phone !== undefined) user.phone = phone;
  // Ignored: email, credits, verified, role
  res.json(sanitize(user));
});

// GET /api/users?limit&page — pagination capped at 100 (TC-CONS-02)
app.get('/api/users', requireAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 20, 100);
  const page  = Math.max(parseInt(req.query.page,  10) || 1,  1);
  const start = (page - 1) * limit;
  const data  = users.slice(start, start + limit).map(sanitize);
  res.json({ data, total: users.length, page, limit });
});

// GET /api/users/:id — BOLA protected (TC-BOLA-03, TC-BOLA-07, TC-BOLA-08, TC-BOLA-09, TC-BOLA-10)
app.get('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = users.find(u => u.id === id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' }); // No sensitive data in error (TC-BOLA-10)
  }
  res.json(sanitize(target));
});

// PUT /api/users/:id — BOLA protected (TC-BOLA-04)
app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const { name, phone } = req.body ?? {};
  if (name  !== undefined) user.name  = name;
  if (phone !== undefined) user.phone = phone;
  res.json(sanitize(user));
});

// DELETE /api/users/:id — BOLA protected (TC-BOLA-05)
app.delete('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (req.user.role !== 'admin' && req.user.id !== id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  users.splice(idx, 1);
  res.sendStatus(204);
});

// GET /api/orders — user sees only own orders (TC-BOLA-06)
app.get('/api/orders', requireAuth, (req, res) => {
  res.json(orders.filter(o => o.userId === req.user.id));
});

// GET /api/orders/:id — BOLA protected (TC-BOLA-06)
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  if (req.user.role !== 'admin' && order.userId !== req.user.id) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json(order);
});

// POST /api/orders — negative quantity check + limited stock (TC-FLOW-01, TC-FLOW-03)
app.post('/api/orders', requireAuth, (req, res) => {
  const { productId, quantity } = req.body ?? {};
  if (!quantity || quantity < 1) {
    return res.status(400).json({ error: 'Invalid quantity' });
  }
  const product = products[productId];
  if (!product) return res.status(404).json({ error: 'Product not found' });

  // Synchronous stock check (Node.js single-thread) prevents race condition (TC-FLOW-01)
  if (product.stock < quantity) {
    return res.status(409).json({ error: 'Insufficient stock' });
  }
  product.stock -= quantity;

  const order = {
    id: `order-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    userId: req.user.id,
    productId,
    quantity,
    status: 'created',
  };
  orders.push(order);
  res.status(201).json(order);
});

// GET /api/admin/users — admin only (TC-BFLA-01)
app.get('/api/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.json(users.map(sanitize));
});

// DELETE /api/admin/users/:id — admin only (TC-BFLA-02)
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, (req, res) => {
  const id  = parseInt(req.params.id, 10);
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  users.splice(idx, 1);
  res.sendStatus(204);
});

// ALL /api/admin/config — admin only, non-mutating methods only (TC-BFLA-03)
app.all('/api/admin/config', requireAuth, requireAdmin, (req, res) => {
  if (!['GET', 'HEAD'].includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  res.json({ config: 'admin-only-settings' });
});

// POST /api/referrals/apply — self-referral prevention (TC-FLOW-02)
app.post('/api/referrals/apply', requireAuth, (req, res) => {
  const { code } = req.body ?? {};
  if (!code) return res.status(400).json({ error: 'Referral code required' });
  if (req.user.referralCode === code) {
    return res.status(400).json({ error: 'Cannot use your own referral code' });
  }
  const referrer = users.find(u => u.referralCode === code);
  if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });
  res.json({ message: 'Referral applied' });
});

// POST /api/products/import — XSS sanitization (TC-UNSAFE-02)
app.post('/api/products/import', requireAuth, (req, res) => {
  const { name, source } = req.body ?? {};
  const safe = (name ?? '')
    // Remove entire <script>...</script> blocks including content
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    // Strip all remaining HTML/XML tags
    .replace(/<[^>]*>/g, '')
    // Encode remaining angle brackets
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
  res.status(201).json({ id: `product-${Date.now()}`, name: safe, source: source ?? 'internal' });
});

// POST /api/data — large payload endpoint (TC-CONS-01 → 413 from body limit)
app.post('/api/data', requireAuth, (req, res) => {
  res.json({ received: true });
});

// POST /api/webhooks — SSRF protection (TC-SSRF)
app.post('/api/webhooks', requireAuth, (req, res) => {
  const { url } = req.body ?? {};
  if (isInternalUrl(url)) {
    return res.status(400).json({ error: 'URL not allowed: internal/private addresses are blocked' });
  }
  res.json({ message: 'Webhook registered', url });
});

// POST /api/integrations/webhook — explicit domain allowlist (TC-UNSAFE-01)
const INTEGRATION_ALLOWLIST = ['example.com', 'hooks.trusted.com', 'api.example.com', 'webhook.site'];

app.post('/api/integrations/webhook', requireAuth, (req, res) => {
  const { callbackUrl } = req.body ?? {};
  if (!callbackUrl) return res.status(400).json({ error: 'callbackUrl required' });
  if (isInternalUrl(callbackUrl)) return res.status(400).json({ error: 'URL not allowed' });
  let parsedUrl;
  try { parsedUrl = new URL(callbackUrl); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  const host = parsedUrl.hostname.toLowerCase();
  const allowed = INTEGRATION_ALLOWLIST.some(d => host === d || host.endsWith(`.${d}`));
  if (!allowed) return res.status(403).json({ error: 'Domain not in allowlist' });
  res.json({ message: 'Webhook integration configured' });
});

// GET /api/auth/callback — open redirect prevention (TC-UNSAFE-03)
app.get('/api/auth/callback', (req, res) => {
  const { redirect } = req.query;
  if (!redirect) return res.status(200).json({ message: 'ok' });
  try {
    const url = new URL(redirect);
    if (!['localhost', '127.0.0.1'].includes(url.hostname)) {
      return res.status(400).json({ error: 'Invalid redirect: external URLs not allowed' });
    }
    return res.redirect(redirect);
  } catch {
    // Relative URL is safe
    return res.redirect(String(redirect));
  }
});

// GET /api/health — used by Playwright webServer probe + security header check (TC-MISCONF-01)
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

// GET /api/v1/* — deprecated (TC-INV-01)
app.all('/api/v1/*', (_req, res) => {
  res.status(410).json({ error: 'API v1 is deprecated. Please use the current API.' });
});

// Block undocumented internal routes (TC-INV-02)
app.all(['/api/internal', '/api/internal/*', '/api/v0', '/api/v0/*', '/api/beta', '/api/beta/*'],
  (_req, res) => res.status(404).end());

// Block debug/swagger endpoints (TC-MISCONF-03)
['/swagger', '/swagger-ui', '/api-docs', '/graphql-playground', '/__debug', '/actuator', '/metrics']
  .forEach(path => app.all([path, `${path}/*`], (_req, res) => res.status(404).end()));

// ─── Error handler — no stack traces (TC-MISCONF-02) ─────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  if (err.type === 'entity.too.large' || err.status === 413) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  console.error('[Server]', err.message); // Internal log only
  res.status(err.status || 500).json({ error: 'Internal server error' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Security test API running on http://localhost:${PORT}`);
    console.log('Pre-seeded users:');
    console.log('  user_a@test.com  / Password123!  (id=10, role=user)');
    console.log('  user_b@test.com  / Password123!  (id=2,  role=user)');
    console.log('  admin@test.com   / AdminPass123! (id=3,  role=admin)');
  });
}

module.exports = app;

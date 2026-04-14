'use strict';

/**
 * VULNERABLE Target API Server
 * Intentionally insecure — used to demonstrate that the security test suite
 * correctly detects OWASP API Top 10 vulnerabilities.
 *
 * Run against this server:  API_BASE_URL=http://localhost:3001 npx playwright test
 * Expected result:          most security tests FAIL (vulnerabilities detected)
 *
 * Intentional vulnerabilities:
 *  API1  – BOLA          : no object-level authorization checks
 *  API2  – Broken Auth   : accepts alg:none JWT, no brute-force protection
 *  API3  – Mass Assign   : role/credits/verified freely updated via PUT/PATCH
 *  API4  – Consumption   : no payload limit, no rate limiting, no pagination cap
 *  API5  – BFLA          : admin endpoints accessible to any authenticated user
 *  API6  – Business Flow : race condition on stock, self-referral allowed, negative qty
 *  API7  – SSRF          : webhook accepts any URL including internal addresses
 *  API8  – Misconfig     : no security headers, CORS wildcard, stack traces exposed
 *  API9  – Inventory     : v1 API active without deprecation notice, internal routes exposed
 *  API10 – Unsafe Consump: no URL allowlist, XSS not sanitized, open redirect
 */

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'weak-secret';

// ─── No body size limit (TC-CONS-01 will pass payload → test FAILS) ──────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── VULNERABILITY: CORS wildcard (TC-MISCONF-04 test FAILS) ─────────────────
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // wildcard!
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (_req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
// NOTE: No security headers (X-Frame-Options, HSTS, X-Content-Type-Options) → TC-MISCONF-01 FAILS

// ─── In-memory data ───────────────────────────────────────────────────────────
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

const products = {
  'product-001':    { id: 'product-001',    name: 'Regular Product',    stock: 100, price: 29.99 },
  'product-002':    { id: 'product-002',    name: 'Another Product',    stock: 50,  price: 19.99 },
  'promo-item-001': { id: 'promo-item-001', name: 'Limited Promo Item', stock: 1,   price: 9.99  },
};

// ─── VULNERABILITY: accepts any JWT including alg:none (TC-AUTH-05 FAILS) ────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const token = header.slice(7);
  try {
    // BUG: algorithms not restricted → alg:none accepted
    const decoded = jwt.decode(token); // no verification!
    if (!decoded) return res.status(401).json({ error: 'Bad token' });
    req.user = users.find(u => u.id === decoded.userId) || { id: decoded.sub, role: decoded.role ?? 'user' };
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/auth/login — VULNERABILITY: no rate limiting (TC-AUTH-04 FAILS)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '24h' },
  );
  res.json({ token });
});

// GET /api/users/me
app.get('/api/users/me', requireAuth, (req, res) => {
  // VULNERABILITY: returns ALL fields including password (TC-BOPLA-02 FAILS)
  const user = users.find(u => u.id === req.user.id) ?? req.user;
  res.json(user); // includes password, passwordHash etc.
});

// PUT /api/users/me — VULNERABILITY: mass assignment (TC-BOPLA-01, TC-BOPLA-03 FAIL)
app.put('/api/users/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  Object.assign(user, req.body); // BUG: merges everything including role, isAdmin, credits
  res.json(user);
});

// PATCH /api/users/me — VULNERABILITY: mass assignment
app.patch('/api/users/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  Object.assign(user, req.body); // BUG: no field filtering
  res.json(user);
});

// GET /api/users — VULNERABILITY: no pagination cap (TC-CONS-02 FAILS)
app.get('/api/users', requireAuth, (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 20; // BUG: no max cap
  const page  = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const start = (page - 1) * limit;
  const data  = users.slice(start, start + limit); // returns all fields
  res.json({ data, total: users.length, page, limit });
});

// GET /api/users/:id — VULNERABILITY: no BOLA check (TC-BOLA-03,07,08 FAIL)
app.get('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const target = users.find(u => u.id === id);
  if (!target) return res.status(404).json({ error: 'Not found' });
  res.json(target); // BUG: any authenticated user can read any profile
});

// PUT /api/users/:id — VULNERABILITY: no BOLA check (TC-BOLA-04 FAILS)
app.put('/api/users/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const user = users.find(u => u.id === id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  Object.assign(user, req.body); // BUG: any user can update any profile
  res.json(user);
});

// DELETE /api/users/:id — VULNERABILITY: no BOLA check (TC-BOLA-05 FAILS)
app.delete('/api/users/:id', requireAuth, (req, res) => {
  const id  = parseInt(req.params.id, 10);
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  users.splice(idx, 1); // BUG: any user can delete any account
  res.sendStatus(204);
});

// GET /api/orders
app.get('/api/orders', requireAuth, (req, res) => {
  res.json(orders.filter(o => o.userId === req.user.id));
});

// GET /api/orders/:id — VULNERABILITY: no BOLA check (TC-BOLA-06 FAILS)
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'Not found' });
  res.json(order); // BUG: any user can read any order
});

// POST /api/orders — VULNERABILITY: no negative quantity check, no race protection
app.post('/api/orders', requireAuth, (req, res) => {
  const { productId, quantity } = req.body ?? {};
  // BUG: negative quantity not validated (TC-FLOW-03 FAILS)
  const product = products[productId];
  if (!product) return res.status(404).json({ error: 'Product not found' });
  // BUG: async-style stock check with artificial delay creates race condition (TC-FLOW-01 FAILS)
  setTimeout(() => {
    product.stock -= (quantity || 1);
    const order = {
      id: `order-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      userId: req.user.id, productId, quantity, status: 'created',
    };
    orders.push(order);
    res.status(201).json(order);
  }, 5);
});

// GET /api/admin/users — VULNERABILITY: no admin check (TC-BFLA-01 FAILS)
app.get('/api/admin/users', requireAuth, (req, res) => {
  res.json(users); // BUG: accessible to any authenticated user
});

// DELETE /api/admin/users/:id — VULNERABILITY: no admin check (TC-BFLA-02 FAILS)
app.delete('/api/admin/users/:id', requireAuth, (req, res) => {
  const id  = parseInt(req.params.id, 10);
  const idx = users.findIndex(u => u.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  users.splice(idx, 1);
  res.sendStatus(204);
});

// ALL /api/admin/config — VULNERABILITY: no admin check (TC-BFLA-03 FAILS)
app.all('/api/admin/config', requireAuth, (req, res) => {
  res.json({ config: 'all-settings-exposed' });
});

// POST /api/referrals/apply — VULNERABILITY: self-referral allowed (TC-FLOW-02 FAILS)
app.post('/api/referrals/apply', requireAuth, (req, res) => {
  const { code } = req.body ?? {};
  const referrer = users.find(u => u.referralCode === code);
  if (!referrer) return res.status(404).json({ error: 'Invalid referral code' });
  res.json({ message: 'Referral applied' }); // BUG: no self-referral check
});

// POST /api/products/import — VULNERABILITY: XSS not sanitized (TC-UNSAFE-02 FAILS)
app.post('/api/products/import', requireAuth, (req, res) => {
  const { name, source } = req.body ?? {};
  res.status(201).json({ id: `product-${Date.now()}`, name, source }); // BUG: raw XSS payload stored
});

// POST /api/data — VULNERABILITY: accepts unlimited payload (TC-CONS-01 FAILS)
app.post('/api/data', requireAuth, (req, res) => {
  res.json({ received: true });
});

// POST /api/webhooks — VULNERABILITY: no SSRF protection (TC-SSRF tests FAIL)
app.post('/api/webhooks', requireAuth, (req, res) => {
  const { url } = req.body ?? {};
  res.json({ message: 'Webhook registered', url }); // BUG: any URL accepted
});

// POST /api/integrations/webhook — VULNERABILITY: no allowlist (TC-UNSAFE-01 FAILS)
app.post('/api/integrations/webhook', requireAuth, (req, res) => {
  const { callbackUrl } = req.body ?? {};
  res.json({ message: 'Integration configured', callbackUrl }); // BUG: no validation
});

// GET /api/auth/callback — VULNERABILITY: open redirect (TC-UNSAFE-03 FAILS)
app.get('/api/auth/callback', (req, res) => {
  const { redirect } = req.query;
  if (redirect) return res.redirect(String(redirect)); // BUG: no URL validation
  res.status(200).json({ message: 'ok' });
});

// GET /api/health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok' });
  // BUG: no security headers → TC-MISCONF-01 FAILS
});

// GET /api/v1/* — VULNERABILITY: active without deprecation notice (TC-INV-01 FAILS)
app.get('/api/v1/users/me', requireAuth, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  res.json(user ?? {}); // BUG: returns 200 with no Deprecation header
});

// VULNERABILITY: internal routes accessible (TC-INV-02 FAILS)
app.get('/api/internal/users', requireAuth, (req, res) => res.json(users));
app.get('/api/v0/users', requireAuth, (req, res) => res.json(users));
app.get('/api/beta/admin', requireAuth, (req, res) => res.json({ admin: true }));

// VULNERABILITY: swagger/debug routes open (TC-MISCONF-03 FAILS)
app.get('/swagger', (_req, res) => res.json({ swagger: '2.0', info: { title: 'API' } }));
app.get('/api-docs', (_req, res) => res.json({ openapi: '3.0' }));
app.get('/__debug', (_req, res) => res.json({ debug: true, env: process.env }));
app.get('/metrics', (_req, res) => res.send('# metrics\nhttp_requests_total 42\n'));

// VULNERABILITY: error handler exposes stack traces (TC-MISCONF-02 FAILS)
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  res.status(err.status || 500).json({
    error: err.message,
    stack: err.stack, // BUG: stack trace exposed
    'Error:': err.toString(),
  });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n⚠️  VULNERABLE test API running on http://localhost:${PORT}`);
    console.log('⚠️  DO NOT use in production — intentionally insecure!\n');
    console.log('Pre-seeded users:');
    console.log('  user_a@test.com  / Password123!  (id=10)');
    console.log('  user_b@test.com  / Password123!  (id=2)');
    console.log('  admin@test.com   / AdminPass123! (id=3)\n');
  });
}

module.exports = app;

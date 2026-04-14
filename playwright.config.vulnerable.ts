/**
 * Vulnerable API configuration — runs the test suite against the intentionally
 * insecure server. Most security tests should FAIL, proving the suite detects
 * real vulnerabilities.
 *
 * Usage:
 *   npx playwright test --config=playwright.config.vulnerable.ts
 */
import { defineConfig } from '@playwright/test';

// Tell test files to use port 3001 (vulnerable server)
process.env.API_BASE_URL = 'http://localhost:3001';

export default defineConfig({
  testDir: './',
  testMatch: ['**/*.security.spec.ts'],
  workers: 1,
  fullyParallel: false,
  timeout: 30_000,
  expect: { timeout: 10_000 },

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report-vulnerable', open: 'never' }],
  ],

  use: {
    baseURL: process.env.API_BASE_URL ?? 'http://localhost:3001',
    extraHTTPHeaders: { 'Content-Type': 'application/json' },
  },

  webServer: {
    command: 'node api-server/server-vulnerable.js',
    url: 'http://localhost:3001/api/health',
    reuseExistingServer: true,
    timeout: 10_000,
    env: { PORT: '3001', JWT_SECRET: 'weak-secret' },
  },
});

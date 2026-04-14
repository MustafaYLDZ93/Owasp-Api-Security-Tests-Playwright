import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './',
  testMatch: ['**/*.security.spec.ts'],

  // globalSetup starts the API server before tests and stops it after.
  // Works with both `npx playwright test` and the VS Code green-button runner.
  globalSetup:    './global-setup.ts',
  globalTeardown: './global-teardown.ts',

  // Sequential execution prevents cross-spec rate-limit interference
  workers: 1,
  fullyParallel: false,

  timeout: 30_000,
  expect: { timeout: 10_000 },

  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],

  use: {
    baseURL: process.env.API_BASE_URL ?? 'http://localhost:3000',
    extraHTTPHeaders: { 'Content-Type': 'application/json' },
  },
});

import { defineConfig } from '@playwright/test';

// E2E + visual checks of the deployed Vercel site at laptop size only (no local server):
//   SITE_URL=https://zerohour-pi.vercel.app npx playwright test -c site.config.ts
export default defineConfig({
  testDir: './site',
  workers: 1,
  retries: 0,
  timeout: 90_000,
  outputDir: 'artifacts/site-results',
  reporter: [['list'], ['html', { outputFolder: 'artifacts/site-report', open: 'never' }]],
  use: { baseURL: process.env.SITE_URL || 'https://zerohour-pi.vercel.app', viewport: { width: 1440, height: 900 }, trace: 'on',
    // A protected preview URL: pass the local dev OIDC token (vercel env pull) as the Trusted Sources header.
    extraHTTPHeaders: process.env.VERCEL_OIDC_TOKEN ? { 'x-vercel-trusted-oidc-idp-token': process.env.VERCEL_OIDC_TOKEN } : undefined },
});

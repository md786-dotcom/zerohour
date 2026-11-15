import { defineConfig } from '@playwright/test';

// E2E of the deployed Vercel site (no local server): SITE_URL=https://zerohour-pi.vercel.app npx playwright test -c site.config.ts
export default defineConfig({
  testDir: './site',
  workers: 1,
  retries: 0,
  timeout: 60_000,
  outputDir: 'artifacts/site-results',
  reporter: [['list'], ['html', { outputFolder: 'artifacts/site-report', open: 'never' }]],
  use: { baseURL: process.env.SITE_URL || 'https://zerohour-pi.vercel.app', trace: 'on', screenshot: 'on' },
});

import { test, expect } from '@playwright/test';

// A page the browser opens again (Back, a restored tab) must come from the server, not from a copy
// the browser kept: else a new deploy shows only after the next click. vercel.json sends no-store.
test('back to a page loads it fresh from the server', async ({ page }) => {
  await page.goto('/');
  await page.evaluate(() => ((window as any).__old = true));  // only a kept copy of this page still has it
  await page.getByRole('link', { name: 'Live capture' }).click();
  await page.waitForURL('**/live');
  await page.goBack();
  await page.waitForLoadState('load');
  const r = await page.evaluate(() => {
    const nav = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    return { kept: !!(window as any).__old, type: nav.type, bytes: nav.transferSize };
  });
  expect(r.kept, 'restored from the back/forward cache').toBe(false);
  expect(r.type).toBe('back_forward');
  expect(r.bytes, 'HTML came from the browser cache, not the server').toBeGreaterThan(0);
});

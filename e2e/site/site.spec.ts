import { test, expect } from '@playwright/test';

// The deployed site, end to end: live console, server-side chain verify, lab replay, Wireshark evidence, and the
// before/after page in a new window. Full-page screenshots land in artifacts/site-*.png.

test('console: live data from the backend, decisions under the 4 ms budget', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#live-text')).toContainText('Live', { timeout: 15_000 });
  await expect(page.locator('#clients tr')).toHaveCount(32);
  await expect(page.locator('#events tr').first()).toBeVisible();
  const p99 = parseFloat(await page.getByTestId('k-lat').innerText());
  expect(p99).toBeGreaterThan(0);
  expect(p99).toBeLessThan(4000);  // microseconds
  const plan = page.waitForRequest(r => r.url().includes('/api/live?method=plan'));
  await page.getByRole('button', { name: 'Plan method' }).click();
  await plan;
  await page.screenshot({ path: 'artifacts/site-console.png', fullPage: true });
});

test('evidence log: the server finds an edited record', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#log tr').first()).toBeVisible({ timeout: 15_000 });
  await page.getByTestId('verify').click();
  await expect(page.getByTestId('verify-result')).toContainText('Chain intact');
  await page.getByTestId('tamper').click();
  await expect(page.getByTestId('verify-result')).toContainText('Chain broken at record');
});

test('lab replay: many benign changes clear with the tuned method, attack alerts with both', async ({ page }) => {
  await page.goto('/#lab');
  await expect(page.locator('#lab-verdict')).toContainText('Plan: Alert after 3 sites · Tuned: Alert after 3 sites');
  await page.getByRole('tab', { name: 'Many changes' }).click();
  await expect(page.locator('#lab-verdict')).toContainText('Plan: No decision · Tuned: Clear after 3 sites');
  await expect(page.locator('#lab-rows tr')).toHaveCount(8);
});

test('packet evidence: Wireshark shows the forged issuer', async ({ page }) => {
  await page.goto('/#evidence');
  await expect(page.locator('#pkts td.cert-int').first()).toContainText('Interceptor CA');
  await expect(page.locator('#tree mark').first()).toHaveText('Interceptor CA');
  await page.getByRole('tab', { name: 'learn.pcap' }).click();
  await expect(page.locator('#pkts td.cert-int')).toHaveCount(0);
  await expect(page.locator('#ev-download')).toHaveAttribute('href', '/pcaps/learn.pcap');
});

test('before vs after opens in a new window and shows both constraints', async ({ page, context }) => {
  await page.goto('/');
  const [cmp] = await Promise.all([context.waitForEvent('page'), page.getByTestId('open-compare').click()]);
  await cmp.waitForLoadState();
  expect(new URL(cmp.url()).pathname).toBe('/compare');
  await expect(cmp.locator('#rt-before')).toContainText(/µs|ms/);
  await expect(cmp.locator('#fp-before')).toContainText('%', { timeout: 30_000 });
  await expect(cmp.locator('#fp-table tr')).toHaveCount(4);
  await expect(cmp.locator('#cases tr')).toHaveCount(8);
  const before = parseFloat(await cmp.locator('#fp-before').innerText()), after = parseFloat(await cmp.locator('#fp-after').innerText());
  expect(after).toBeLessThan(before);
  await cmp.screenshot({ path: 'artifacts/site-compare.png', fullPage: true });
});

test('phone width: no horizontal page scroll', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 800 });
  for (const path of ['/', '/compare']) {
    await page.goto(path);
    await page.waitForTimeout(1500);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(375);
  }
});

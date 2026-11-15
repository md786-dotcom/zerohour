import { test, expect, Page } from '@playwright/test';

// The deployed site at laptop size (1440 x 900). Every tab must fit one screen: no page scroll.
// Screenshots of every tab land in artifacts/laptop-*.png for a visual check.

async function fitsOneScreen(page: Page, name: string) {
  await page.waitForTimeout(400);  // let charts draw at their final size
  const { sh, ih } = await page.evaluate(() => ({ sh: document.documentElement.scrollHeight, ih: innerHeight }));
  expect(sh, `${name}: page scrolls`).toBeLessThanOrEqual(ih + 1);
  await page.screenshot({ path: `artifacts/laptop-${name}.png` });
}

test('live replay: run, stop, reset; the tuned method alerts only on the two intercepted clients', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByTestId('tile')).toHaveCount(8, { timeout: 20_000 });  // first call can hit a cold function
  await expect(page.getByTestId('progress')).toHaveText('0 of 128 handshakes');
  await expect(page.getByTestId('k-time')).toHaveText('—');  // nothing measured before Run
  await fitsOneScreen(page, 'live-start');

  await page.getByTestId('run').click();
  await expect(page.getByTestId('stop')).toBeEnabled();
  await expect(page.getByTestId('k-time')).toHaveText(/^\d+\.\d\dms$/, { timeout: 15_000 });  // measured while it runs
  await page.waitForTimeout(800);
  await page.getByTestId('stop').click();
  const stopped = await page.getByTestId('progress').innerText();
  expect(parseInt(stopped)).toBeGreaterThan(0);
  await page.waitForTimeout(1200);
  await expect(page.getByTestId('progress')).toHaveText(stopped);  // Stop holds the replay

  await page.getByTestId('run').click();
  await expect(page.getByTestId('progress')).toHaveText('128 of 128 handshakes', { timeout: 90_000 });
  const alerts = page.locator('[data-testid=tile][data-verdict=alert]');
  await expect(alerts).toHaveCount(2);
  for (const ip of ['10.0.1.13', '10.0.1.16']) await expect(page.locator(`[data-testid=tile][data-ip="${ip}"]`)).toHaveAttribute('data-verdict', 'alert');
  await expect(page.getByTestId('k-fp')).toHaveText('0');
  await expect(page.getByTestId('k-caught')).toContainText('2');
  await expect(page.locator('#k-time-foot')).toContainText('Mean');  // p99 is the big number, the mean is under it
  expect(parseFloat(await page.getByTestId('k-time').innerText())).toBeLessThan(4);  // tuned: p99 within the 4 ms budget
  await fitsOneScreen(page, 'live-done');

  await page.getByRole('button', { name: 'Plan', exact: true }).click();
  await expect(page.getByTestId('k-fp')).toHaveText('1');  // the plan method on the same capture: one clean client alerted
  await page.getByTestId('reset').click();
  await expect(page.getByTestId('progress')).toHaveText('0 of 128 handshakes');
  await expect(page.getByTestId('k-time')).toHaveText('—');
});

test('lab scenarios: many normal changes clear with the tuned method; the attack alerts with both', async ({ page }) => {
  await page.goto('/#lab');
  await expect(page.getByTestId('lab-verdict')).toHaveText('Plan: Alert after 3 sites · Tuned: Alert after 3 sites');
  await fitsOneScreen(page, 'lab');
  await page.getByRole('button', { name: 'Many changes' }).click();
  await expect(page.getByTestId('lab-verdict')).toContainText('Plan: No decision · Tuned: Clear');
});

test('wireshark: the forged issuer shows in the attack capture only', async ({ page }) => {
  await page.goto('/#wireshark');
  await expect(page.locator('#pkts td.forged').first()).toHaveText('Interceptor CA');
  await expect(page.locator('#tree mark').first()).toHaveText('Interceptor CA');
  await fitsOneScreen(page, 'wireshark');
  await page.getByRole('button', { name: 'learn.pcap' }).click();
  await expect(page.locator('#pkts td.forged')).toHaveCount(0);
});

test('evidence log: the server finds a changed record', async ({ page }) => {
  await page.goto('/');
  await page.getByTestId('run').click();
  await expect(page.getByTestId('progress')).toHaveText(/^([4-9]\d|1[0-2]\d) of 128/, { timeout: 40_000 });
  await page.getByTestId('stop').click();
  await page.getByRole('tab', { name: 'Evidence log' }).click();
  const rows = await page.locator('#log tr[data-seq]').count();
  expect(rows).toBeGreaterThan(10);  // every record, not only the last 10
  await page.getByTestId('verify').click();
  await expect(page.getByTestId('verify-result')).toContainText('Computing BLAKE2b-256 of record');  // computed live, record by record
  await expect(page.getByTestId('verify-result')).toContainText('Log is correct', { timeout: 30_000 });
  await expect(page.getByTestId('verify-result')).toContainText('The server agrees');
  await expect(page.getByTestId('check').filter({ hasText: '✓ Matches' })).toHaveCount(rows);
  await fitsOneScreen(page, 'log');
  await page.getByTestId('tamper').click();
  await expect(page.getByTestId('verify-result')).toContainText('is incorrect', { timeout: 30_000 });
  await expect(page.getByTestId('verify-result')).toContainText('The server agrees');
  await expect(page.locator('tr.edited [data-testid=check]')).toContainText('Hash does not match');
  await expect(page.getByTestId('check').filter({ hasText: '✗' })).toHaveCount(1);
  await fitsOneScreen(page, 'log-tampered');
});

test('how we tuned it: four steps, each on one screen', async ({ page }) => {
  await page.goto('/tuning');
  await expect(page.locator('#rates .bar')).toHaveCount(6, { timeout: 30_000 });
  await fitsOneScreen(page, 'tuning-measure');
  for (const [tab, name] of [['2 · Weigh', 'weigh'], ['3 · Cap', 'cap'], ['4 · Result', 'result']] as const) {
    await page.getByRole('tab', { name: tab }).click();
    await fitsOneScreen(page, `tuning-${name}`);
  }
  await expect(page.locator('#sweep tr.sel')).toContainText('chosen');
  await expect(page.locator('#r-real .after .big')).toHaveText('0');
});

test('before vs after opens in a new window; both constraints on one screen each', async ({ page, context }) => {
  await page.goto('/');
  const [cmp] = await Promise.all([context.waitForEvent('page'), page.getByTestId('open-compare').click()]);
  await cmp.setViewportSize({ width: 1440, height: 900 });
  await cmp.waitForLoadState();
  expect(new URL(cmp.url()).pathname).toBe('/compare');
  await expect(cmp.locator('#rt-vs .after .badge')).toHaveText('In budget');
  await expect(cmp.locator('#rt-vs .before .badge')).toHaveText('Over budget');
  await fitsOneScreen(cmp, 'compare-runtime');
  await cmp.getByRole('tab', { name: /Fewer false alerts/ }).click();
  await expect(cmp.locator('.formula-card.before')).toContainText('+2.08');
  await expect(cmp.locator('.formula-card.after')).toContainText('clip');
  await expect(cmp.locator('#fp-table tr')).toHaveCount(4, { timeout: 60_000 });
  const before = parseFloat(await cmp.locator('#fp-vs .before .big').innerText()), after = parseFloat(await cmp.locator('#fp-vs .after .big').innerText());
  expect(after).toBeLessThan(before);
  await fitsOneScreen(cmp, 'compare-alerts');
});

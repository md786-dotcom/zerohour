import { test, expect, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The live page on real traffic: one VM, step 1 learns 5 real sites, then three tests on the same baseline:
// direct, one site through mitmproxy (one change), all sites through mitmproxy (many changes). Then the VM's log.
// The sites are real, so only the shape of each result is fixed. The PCAPs and screenshots are the run's artifacts.

async function fitsOneScreen(page: Page, name: string) {
  await page.waitForTimeout(400);  // let charts draw at their final size
  const { sh, ih } = await page.evaluate(() => ({ sh: document.documentElement.scrollHeight, ih: innerHeight }));
  expect(sh, `${name}: page scrolls`).toBeLessThanOrEqual(ih + 1);
  await page.screenshot({ path: `artifacts/laptop-${name}.png` });
}
async function savePcap(page: Page, link: string, file: string) {
  const [dl] = await Promise.all([page.waitForEvent('download'), page.locator(link).click()]);
  await dl.saveAs(file);
  const b = readFileSync(file);
  expect(b.readUInt32LE(0), `${file} is a pcap`).toBe(0xa1b2c3d4);
  expect(b.length).toBeGreaterThan(5_000);
}
async function runTest(page: Page) {
  await page.getByTestId('test-run').click();
  await expect(page.getByTestId('t-state')).toHaveText(/^Done in/, { timeout: 60_000 });
  await expect(page.getByTestId('t-n')).toHaveText('5of 5');
}

test('live page: learn, then test direct, one change, many changes; the log verifies', async ({ page }) => {
  test.setTimeout(240_000);
  await page.goto('/live');

  await test.step('step 1: learn 5 real sites', async () => {
    await expect(page.getByTestId('test-run')).toBeDisabled();  // no test before a baseline
    await page.getByTestId('learn-run').click();
    await expect(page.getByTestId('l-state')).toHaveText(/^Visiting/, { timeout: 30_000 });  // the stream shows progress
    await expect(page.getByTestId('l-state')).toHaveText(/^Done in/, { timeout: 60_000 });
    await expect(page.getByTestId('l-learned')).toHaveText('5of 5');
    await expect(page.locator('#learn-rows .pill.clear')).toHaveCount(5);
    await savePcap(page, '#learn-dl', 'artifacts/live-learn.pcap');
    await fitsOneScreen(page, 'live-learn');
  });

  await test.step('step 2a: direct, no alert', async () => {
    await page.getByTestId('to-test').click();
    await runTest(page);
    await expect(page.locator('#test-rows .pill', { hasText: 'mitmproxy' })).toHaveCount(0);
    await expect(page.getByTestId('t-decision')).not.toHaveText('Alert');
    await expect(page.getByTestId('t-time')).toHaveText(/ms$/);
    expect(parseFloat(await page.getByTestId('t-time').innerText())).toBeLessThan(4);  // engine-only p99, under the 4 ms budget
    await savePcap(page, '#test-dl', 'artifacts/live-test-direct.pcap');
    await fitsOneScreen(page, 'live-test-direct');
  });

  await test.step('step 2b: one site through mitmproxy, one change, no alert', async () => {
    await page.getByRole('button', { name: 'Through mitmproxy' }).click();
    for (const host of ['example.com', 'wikipedia.org', 'cloudflare.com', '1.1.1.1']) await page.locator(`.pick[data-host="${host}"]`).click();
    await runTest(page);
    await expect(page.locator('#test-rows .pill', { hasText: 'mitmproxy' })).toHaveCount(1);
    await expect(page.locator('#test-rows tr[data-site="github.com"] .chip.bad')).not.toHaveCount(0);  // the one change is seen
    await expect(page.getByTestId('t-decision')).not.toHaveText('Alert');
    await fitsOneScreen(page, 'live-test-one');
  });

  await test.step('step 2c: all sites through mitmproxy, many changes, alert after 3 sites', async () => {
    for (const host of ['example.com', 'wikipedia.org', 'cloudflare.com', '1.1.1.1']) await page.locator(`.pick[data-host="${host}"]`).click();
    await runTest(page);
    await expect(page.locator('#test-rows .pill', { hasText: 'mitmproxy' })).toHaveCount(5);
    await expect(page.getByTestId('t-decision')).toHaveText('Alert');
    await expect(page.locator('#t-dec-foot')).toHaveText(/^Alert after 3 sites \(handshake 3\)/);
    expect(parseFloat(await page.getByTestId('t-score').innerText())).toBeGreaterThan(4.6);
    await savePcap(page, '#test-dl', 'artifacts/live-test-mitm.pcap');
    await fitsOneScreen(page, 'live-test-many');
  });

  await test.step('evidence log of the VM: verify, then a changed record is found', async () => {
    await page.getByRole('tab', { name: 'Evidence log' }).click();
    await expect(page.locator('#log tr')).not.toHaveCount(0);
    await page.getByTestId('verify').click();
    await expect(page.getByTestId('verify-result')).toContainText('Log is correct', { timeout: 60_000 });
    await expect(page.getByTestId('verify-result')).toContainText('The server agrees');
    await fitsOneScreen(page, 'live-log');
    await page.getByTestId('tamper').click();
    await expect(page.getByTestId('verify-result')).toContainText('is incorrect', { timeout: 60_000 });
  });
});

test('live page: fewer than 3 sites is refused', async ({ page }) => {
  await page.goto('/live');
  await page.getByTestId('sites').fill('example.com, github.com');
  await page.getByTestId('learn-run').click();
  await expect(page.getByTestId('l-state')).toHaveText(/^Error: Give at least 3 different sites/);
});

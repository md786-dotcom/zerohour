import { test, expect, Page } from '@playwright/test';
import { readFileSync } from 'node:fs';

// The live page on real traffic: one VM, step 1 learns 5 real sites, then four tests on the same baseline:
// direct normal / one change / many changes, then mitmproxy attack. Then the VM's log.
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

test('live page: learn, then the direct and mitmproxy scenarios; the log verifies', async ({ page }) => {
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

  const scenario = async (pathLabel: string, scen: string) => {
    await page.getByRole('button', { name: pathLabel, exact: true }).click();
    await page.locator('#scen button', { hasText: scen }).click();
    await runTest(page);
  };
  const changed = (label: string) => page.locator('#test-rows .pill', { hasText: label });

  await test.step('direct, normal: no site changed, no alert', async () => {
    await page.getByTestId('to-test').click();
    await scenario('Direct', 'Normal');
    await expect(changed('same as step 1')).toHaveCount(5);
    await expect(page.getByTestId('t-decision')).not.toHaveText('Alert');
    await expect(page.getByTestId('t-time')).toHaveText(/ms$/);
    expect(parseFloat(await page.getByTestId('t-time').innerText())).toBeLessThan(4);  // engine-only p99, under the 4 ms budget
    await savePcap(page, '#test-dl', 'artifacts/live-test-direct.pcap');
    await fitsOneScreen(page, 'live-direct-normal');
  });

  await test.step('direct, one change: a new route on one site is seen (D), no alert', async () => {
    await scenario('Direct', 'One change');
    await expect(changed('new route')).toHaveCount(1);
    await expect(page.locator('#test-rows tr', { hasText: 'new route' }).locator('.chip.bad', { hasText: 'D' })).toHaveCount(1);
    await expect(page.getByTestId('t-decision')).not.toHaveText('Alert');
    await fitsOneScreen(page, 'live-direct-one');
  });

  await test.step('direct, many changes: four normal changes, the tuned method does not alert', async () => {
    await scenario('Direct', 'Many changes');
    await expect(page.locator('#test-rows .pill', { hasText: /new route|new TLS/ })).toHaveCount(4);
    await expect(page.getByTestId('t-decision')).not.toHaveText('Alert');
    await expect(page.locator('#t-chart path')).toHaveCount(1);  // one score line
    await fitsOneScreen(page, 'live-direct-many');
  });

  await test.step('mitmproxy, attack: every site intercepted, alert after 3 sites', async () => {
    await scenario('Through mitmproxy', 'Attack');
    await expect(changed('mitmproxy')).toHaveCount(5);
    await expect(page.getByTestId('t-decision')).toHaveText('Alert');
    await expect(page.locator('#t-dec-foot')).toHaveText(/^Alert after 3 sites \(handshake 3\)/);
    expect(parseFloat(await page.getByTestId('t-score').innerText())).toBeGreaterThan(4.6);
    await expect(page.locator('#t-chart path')).toHaveCount(1);
    await savePcap(page, '#test-dl', 'artifacts/live-test-mitm.pcap');
    await fitsOneScreen(page, 'live-mitm-attack');
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
  await page.goto('/');  // pagehide: the page asks the server to stop its VM
});

test('live page: fewer than 3 sites is refused', async ({ page }) => {
  await page.goto('/live');
  await page.getByTestId('sites').fill('example.com, github.com');
  await page.getByTestId('learn-run').click();
  await expect(page.getByTestId('l-state')).toHaveText(/^Error: Give at least 3 different sites/);
});

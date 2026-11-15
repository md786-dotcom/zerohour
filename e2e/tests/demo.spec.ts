import { test, expect, Page } from '@playwright/test';

// The plan's demo (section "Demo"), driven through the dashboard. Expected numbers come from the plan:
// mismatch +2.08, match -1.50, thresholds +-4.60; alert after 3 sites, clear after 4, one change -> clear after 6.

test.describe.configure({ mode: 'serial' });

let page: Page;

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
  await page.goto('/');
  await page.getByTestId('reset').click();
  await expect(page.getByTestId('baseline-count')).toHaveText('0');
});

test.afterAll(async () => {
  await page.close();
});

const rows = () => page.getByTestId('event-row');

test('running before learning shows an error, not a verdict', async () => {
  await page.getByTestId('step-normal').click();
  await expect(page.getByTestId('error')).toContainText('no baseline');
});

test('1. learn: the sensor records a baseline for 8 sites', async () => {
  await page.getByTestId('step-learn').click();
  await expect(page.getByTestId('baseline-count')).toHaveText('8');
  await expect(page.getByTestId('error')).toBeHidden();
});

test('2. normal: matches walk the score down, clear after 4 sites', async () => {
  await page.getByTestId('step-normal').click();
  await expect(page.getByTestId('verdict')).toHaveText('Clear');
  await expect(page.getByTestId('verdict-detail')).toContainText('4 sites');
  await expect(rows()).toHaveCount(8);
  for (let i = 0; i < 8; i++) await expect(rows().nth(i)).toHaveAttribute('data-result', 'match');
  const scores = ['-1.50', '-3.01', '-4.51', '-6.02'];
  for (let i = 0; i < 4; i++) await expect(rows().nth(i)).toHaveAttribute('data-score', scores[i]);
  await expect(page.getByTestId('run-normal')).toContainText('Clear');
});

test('3. one change: one renewed certificate gives one notice and no alert', async () => {
  await page.getByTestId('step-onechange').click();
  await expect(page.getByTestId('verdict')).toHaveText('Clear');
  await expect(page.getByTestId('verdict-detail')).toContainText('6 sites');
  const mismatches = page.locator('[data-testid="event-row"][data-result="mismatch"]');
  await expect(mismatches).toHaveCount(1);
  await expect(mismatches).toContainText('site3.lab');
  await expect(rows().nth(2)).toHaveAttribute('data-score', '-0.93');
  await expect(rows().nth(5)).toHaveAttribute('data-score', '-5.44');
  await expect(page.getByTestId('run-onechange')).toContainText('Clear');
});

test('3b. many changes: four benign changes, one site with two (A + D), stay below the alert threshold', async () => {
  await page.getByTestId('step-multichange').click();
  await expect(page.getByTestId('verdict')).toHaveText('Pending');
  const mismatches = page.locator('[data-testid="event-row"][data-result="mismatch"]');
  await expect(mismatches).toHaveCount(4);
  const scores = ['-1.50', '0.58', '2.65', '1.15', '-0.35', '1.73', '3.81', '2.30'];
  for (const [i, s] of scores.entries()) await expect(rows().nth(i)).toHaveAttribute('data-score', s);
  await expect(page.getByTestId('run-multichange')).toContainText('Pending');
});

test('4. attack: the interceptor changes every site, alert after 3 sites', async () => {
  await page.getByTestId('step-attack').click();
  await expect(page.getByTestId('verdict')).toHaveText('Alert');
  await expect(page.getByTestId('verdict-detail')).toContainText('3 sites');
  await expect(page.getByTestId('verdict-detail')).toContainText('6.24');
  for (const [i, s] of ['2.08', '4.16', '6.24'].entries()) {
    await expect(rows().nth(i)).toHaveAttribute('data-result', 'mismatch');
    await expect(rows().nth(i)).toHaveAttribute('data-score', s);
  }
  await expect(page.getByTestId('run-attack')).toContainText('Alert');
  for (const s of ['normal', 'onechange', 'attack'])
    await expect(page.locator(`[data-testid="score-chart"] path[data-scenario="${s}"]`)).toHaveCount(1);
});

test('before/after: every site matches before, every site changes after', async () => {
  const before = page.getByTestId('compare-before').getByTestId('compare-row');
  const after = page.getByTestId('compare-after').getByTestId('compare-row');
  await expect(before).toHaveCount(8);
  await expect(after).toHaveCount(8);
  for (let i = 0; i < 8; i++) {
    await expect(before.nth(i)).toHaveAttribute('data-mismatch', 'false');
    await expect(after.nth(i)).toHaveAttribute('data-mismatch', 'true');
  }
  await page.getByTestId('tab-compare').click();
  await expect(page.getByTestId('compare-after')).toBeVisible();
  await page.screenshot({ path: 'artifacts/before-after.png', fullPage: true });
  for (const p of ['model', 'baseline', 'run', 'log', 'arch']) {
    await page.getByTestId(`tab-${p}`).click();
    await page.screenshot({ path: `artifacts/page-${p}.png`, fullPage: true });
  }
});

test('5. tamper: the intact chain verifies, an edited record is found', async () => {
  await page.getByTestId('step-verify').click();
  await expect(page.getByTestId('verify-result')).toContainText('Chain intact');
  await page.getByTestId('step-tamper').click();
  await page.getByTestId('step-verify').click();
  await expect(page.getByTestId('verify-result')).toHaveText('Broken at record 1');
});

test('architecture: every component has an explanation', async () => {
  await page.getByTestId('tab-arch').click();
  const nodes = page.getByTestId('arch-node');
  await expect(nodes).toHaveCount(10);
  for (let i = 0; i < 10; i++) await expect(nodes.nth(i).locator('.ste')).not.toBeEmpty();
});

test('mobile width: no horizontal scroll', async ({ browser }) => {
  const phone = await browser.newPage({ viewport: { width: 390, height: 844 } });
  await phone.goto('/');
  const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  await phone.close();
});

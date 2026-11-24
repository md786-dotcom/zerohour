import { test, expect, Page } from '@playwright/test';

// The deployed site on a phone (390 x 844) and a tablet (768 x 1024). The page may scroll down,
// but never sideways, and every nav link, tab and button is at least 44px tall.
// Full-page screenshots land in artifacts/phone-*.png and artifacts/tablet-*.png for a visual check.

async function check(page: Page, name: string) {
  await page.waitForTimeout(400);  // let charts draw at their final size
  const { sw, iw, small } = await page.evaluate(() => ({
    sw: document.documentElement.scrollWidth, iw: innerWidth,
    small: [...document.querySelectorAll('.topbar nav a, [role="tab"], .btn, .seg button')]
      .filter(e => e.checkVisibility() && e.getBoundingClientRect().height < 44)
      .map(e => `${e.textContent!.trim()} ${Math.round(e.getBoundingClientRect().height)}px`),
  }));
  expect(sw, `${name}: page scrolls sideways`).toBeLessThanOrEqual(iw);
  expect(small, `${name}: tap targets under 44px`).toEqual([]);
  await page.screenshot({ path: `artifacts/${name}.png`, fullPage: true });
}

const pages = [
  { path: '/', ready: '[data-testid="tile"]', tabs: ['Live replay', 'Lab scenarios', 'Wireshark', 'Evidence log'] },
  { path: '/live', ready: '#sites', tabs: ['1 · Learn', '2 · Test', 'Evidence log'] },
  { path: '/how-live', ready: '.flow', tabs: ['1 · Data path', '2 · Tools', '3 · Changes'] },
  { path: '/tuning', ready: '#rates .bar', tabs: ['1 · Measure', '2 · Weigh', '3 · Cap', '4 · Result'] },
  { path: '/compare', ready: '#rt-vs .badge', tabs: ['Constraint 1 · Time under 4 ms', 'Constraint 2 · Fewer false alerts'] },
];

for (const [device, viewport] of [['phone', { width: 390, height: 844 }], ['tablet', { width: 768, height: 1024 }]] as const) {
  test.describe(device, () => {
    test.use({ viewport });
    for (const p of pages) {
      test(`${p.path}: no sideways scroll, 44px tap targets, every tab`, async ({ page }) => {
        await page.goto(p.path);
        await expect(page.locator(p.ready).first()).toBeVisible({ timeout: 30_000 });  // first call can hit a cold function
        for (const tab of p.tabs) {
          await page.getByRole('tab', { name: tab, exact: true }).click();
          await check(page, `${device}${p.path === '/' ? '-demo' : p.path.replace('/', '-')}-${tab.replace(/\W+/g, '-').replace(/-+$/, '').toLowerCase()}`);
        }
      });
    }
    test('demo: a run fills the tiles and the feed', async ({ page }) => {
      await page.goto('/');
      await expect(page.getByTestId('tile')).toHaveCount(8, { timeout: 30_000 });
      await page.getByTestId('run').click();
      await expect(page.getByTestId('k-time')).toHaveText(/^\d+\.\d\dms$/, { timeout: 15_000 });
      await page.waitForTimeout(1500);
      await page.getByTestId('stop').click();
      await check(page, `${device}-demo-run`);
    });
  });
}

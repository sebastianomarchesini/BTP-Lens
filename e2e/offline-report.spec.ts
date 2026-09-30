import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { type BrowserContext, type Page, expect, test } from '@playwright/test';

/**
 * The HTML report must open from disk with no network access (docs/data-sources.md §5).
 * `npm run sample` writes it from the fixture snapshot with the real CLI and template.
 */
const REPORT = pathToFileURL(
  resolve(import.meta.dirname, '../reports/sample/btp-lens-report.html'),
).href;

const LOCAL = /^(file|data|blob):/;

/** Blocks every non-local request and records it, so the test can fail on any. */
async function isolate(context: BrowserContext, page: Page) {
  const external: string[] = [];
  const errors: string[] = [];
  await context.route('**/*', (route) => {
    const url = route.request().url();
    if (LOCAL.test(url)) return route.continue();
    external.push(url);
    return route.abort('internetdisconnected');
  });
  await context.setOffline(true);
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  return { external, errors };
}

async function background(page: Page): Promise<string> {
  return page.evaluate(() => getComputedStyle(document.body).backgroundColor);
}

test('the report works from disk with networking disabled', async ({ page, context }) => {
  const { external, errors } = await isolate(context, page);
  await page.goto(REPORT);

  const kpis = page.getByRole('region', { name: 'Key figures' });
  await expect(kpis.getByText('8', { exact: true })).toBeVisible();
  await expect(page.getByText('Top risky apps')).toBeVisible();

  await page.getByRole('tab', { name: 'Findings' }).click();
  await expect(page).toHaveURL(/#\/findings$/);
  await expect(page.getByRole('article')).toHaveCount(3);

  await page.getByRole('tab', { name: 'Apps' }).click();
  await expect(page).toHaveURL(/#\/apps$/);
  await expect(page.getByRole('gridcell', { name: 'legacy-reporting', exact: true })).toBeVisible();

  // The embedded "72" font loaded from the file itself.
  expect(await page.evaluate(() => document.fonts.check('16px "72"'))).toBe(true);
  expect(external, 'requests that left the machine').toEqual([]);
  expect(errors, 'console and page errors').toEqual([]);
});

test('carries a Content Security Policy that blocks connections and unbundled scripts', async ({
  page,
  context,
}) => {
  const { errors } = await isolate(context, page);
  await page.goto(REPORT);
  await expect(page.getByText('Top risky apps')).toBeVisible();

  const policy = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute('content');
  expect(policy).toContain("connect-src 'none'");
  expect(policy).toContain("default-src 'none'");
  expect(policy).toMatch(/script-src 'sha256-[A-Za-z0-9+/=]+'/);
  expect(policy).not.toMatch(/script-src[^;]*'unsafe-inline'/); // scripts are never unsafe-inline

  // A script injected at runtime (what an XSS would do) must not execute.
  const ran = await page.evaluate(() => {
    const script = document.createElement('script');
    script.textContent = '(window as unknown as { pwned?: boolean }).pwned = true;'.replace(
      / as unknown as \{ pwned\?: boolean \}/,
      '',
    );
    document.body.append(script);
    return (window as unknown as { pwned?: boolean }).pwned === true;
  });
  expect(ran).toBe(false);
  // The CSP violation report is expected; anything else is not.
  expect(errors.filter((e) => !/Content Security Policy/.test(e))).toEqual([]);
});

test('follows the OS color scheme with the Horizon themes', async ({ page, context }) => {
  const { external } = await isolate(context, page);
  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto(REPORT);
  await expect(page.getByText('Top risky apps')).toBeVisible();
  const light = await background(page);

  await page.emulateMedia({ colorScheme: 'dark' });
  await expect.poll(() => background(page)).not.toBe(light);
  const dark = await background(page);
  const luminance = (rgb: string) =>
    (rgb.match(/\d+/g) ?? []).slice(0, 3).reduce((sum, n) => sum + Number(n), 0);
  expect(luminance(dark)).toBeLessThan(luminance(light));
  expect(external).toEqual([]);
});

test('is usable at phone width without horizontal page scrolling', async ({ page, context }) => {
  await isolate(context, page);
  await page.setViewportSize({ width: 375, height: 812 });
  for (const hash of ['#/', '#/apps', '#/findings']) {
    await page.goto(`${REPORT}${hash}`);
    await expect(page.getByRole('main')).toBeVisible();
    await page.waitForTimeout(300);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow, `horizontal overflow on ${hash}`).toBeLessThanOrEqual(0);
  }
});

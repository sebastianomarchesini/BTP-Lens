// Renders README screenshots of the sample report (synthetic acme data).
// Usage: npm run sample && node scripts/screenshots.mjs
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from '@playwright/test';

const report = pathToFileURL(
  resolve(import.meta.dirname, '../reports/sample/btp-lens-report.html'),
).href;
const out = (name) => resolve(import.meta.dirname, `../docs/images/${name}.png`);

const shots = [
  { name: 'report-overview-light', scheme: 'light', width: 1280, height: 860, hash: '#/' },
  { name: 'report-overview-dark', scheme: 'dark', width: 1280, height: 860, hash: '#/' },
  { name: 'report-apps-light', scheme: 'light', width: 1280, height: 700, hash: '#/apps' },
  { name: 'report-findings-dark', scheme: 'dark', width: 1280, height: 900, hash: '#/findings' },
  { name: 'report-overview-phone', scheme: 'light', width: 375, height: 812, hash: '#/' },
];

const browser = await chromium.launch(
  process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
);
for (const shot of shots) {
  const context = await browser.newContext({
    viewport: { width: shot.width, height: shot.height },
    colorScheme: shot.scheme,
    deviceScaleFactor: 1,
  });
  await context.route('**/*', (route) =>
    /^(file|data|blob):/.test(route.request().url()) ? route.continue() : route.abort(),
  );
  const page = await context.newPage();
  await page.goto(`${report}${shot.hash}`);
  await page.getByRole('main').waitFor();
  await page.waitForTimeout(800);
  await page.screenshot({ path: out(shot.name), fullPage: shot.width < 600 });
  await context.close();
  console.log(`wrote docs/images/${shot.name}.png`);
}
await browser.close();

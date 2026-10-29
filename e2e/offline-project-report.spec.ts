import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, test } from '@playwright/test';
import { isolate } from './isolate.js';

/**
 * The report of a project scan (`btp-lens project`) must open from disk with
 * no network access, like the Cloud Foundry one. `npm run sample` writes it
 * from the acme-incidents fixture snapshot with the real CLI and template.
 */
const REPORT = pathToFileURL(
  resolve(import.meta.dirname, '../reports/sample-project/btp-lens-report.html'),
).href;

test('the project report works from disk with networking disabled', async ({ page, context }) => {
  const { external, errors } = await isolate(context, page);
  await page.goto(REPORT);

  const kpis = page.getByRole('region', { name: 'Key figures' });
  await expect(kpis.locator('ui5-card[accessible-name="Projects scanned: 1"]')).toBeVisible();
  await expect(page.getByText('Top risks')).toBeVisible();
  await expect(page).toHaveTitle('Overview · BTP Lens report');
  await expect(
    page.getByRole('heading', { level: 1, name: 'Overview · acme-incidents' }),
  ).toBeAttached();
  await expect(page.getByText(/The project acme-incidents was scanned on/)).toBeVisible();

  await page.getByRole('tab', { name: 'Findings' }).click();
  await expect(page).toHaveURL(/#\/findings$/);
  await expect(page.getByRole('article')).toHaveCount(17);
  // A finding with a known line renders as file:line under the project name.
  await expect(
    page.locator('code.finding-location', { hasText: 'srv/services.cds:4' }),
  ).toBeVisible();
  await expect(
    page.locator(
      'ui5-panel[header-text="Service is open to every authenticated user (1) · OWASP A01:2025"]',
    ),
  ).toBeAttached();

  await page.getByRole('tab', { name: 'Projects' }).click();
  await expect(page).toHaveURL(/#\/apps$/);
  await expect(page.getByRole('gridcell', { name: 'acme-incidents', exact: true })).toBeVisible();
  await expect(
    page.getByRole('heading', { level: 1, name: 'Projects · acme-incidents' }),
  ).toBeAttached();

  expect(external, 'requests that left the machine').toEqual([]);
  expect(errors, 'console and page errors').toEqual([]);
});

test('the project report is usable at phone width without horizontal page scrolling', async ({
  page,
  context,
}) => {
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

  // The single project row grows when Org, Space and Last deploy pop in; the table body
  // must grow with it so the severity status is not clipped out of the 44px body.
  await page.goto(`${REPORT}#/apps`);
  const row = page.getByRole('row').filter({ hasText: 'acme-incidents' });
  const status = row.locator('[data-component-name="ObjectStatus"]', { hasText: 'Critical' });
  await expect(status).toBeVisible();
  await expect(status).toBeInViewport({ ratio: 1 });
  const space = row.locator('[data-column-id-cell-text="space"]', { hasText: 'project' });
  await expect(space).toBeInViewport({ ratio: 1 });
});

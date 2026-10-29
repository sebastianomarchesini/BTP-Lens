import type { BrowserContext, Page } from '@playwright/test';

const LOCAL = /^(file|data|blob):/;

/**
 * Blocks every non-local request and records it, so a test can fail on any
 * request that would leave the machine, and collects page and console errors.
 */
export async function isolate(context: BrowserContext, page: Page) {
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

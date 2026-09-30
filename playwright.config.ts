import { defineConfig, devices } from '@playwright/test';

// PW_CHROMIUM_PATH lets sandboxes with a preinstalled Chromium skip the download.
const executablePath = process.env.PW_CHROMIUM_PATH;

export default defineConfig({
  testDir: 'e2e',
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    ...devices['Desktop Chrome'],
    ...(executablePath ? { launchOptions: { executablePath } } : {}),
  },
});

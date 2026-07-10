import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/visual',
  outputDir: '../../../../output/playwright/test-results',
  snapshotPathTemplate: '{testDir}/__screenshots__/{arg}{ext}',
  fullyParallel: false,
  retries: process.env.CI ? 2 : 0,
  reporter: [['list'], ['html', { outputFolder: '../../../../output/playwright/report', open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:5174',
    browserName: 'chromium',
    channel: 'chromium',
    colorScheme: 'light',
    locale: 'en-US',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure'
  },
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1 --port 5174',
    url: 'http://127.0.0.1:5174',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});

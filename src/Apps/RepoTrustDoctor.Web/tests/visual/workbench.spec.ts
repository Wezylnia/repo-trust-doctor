import { expect, test } from '@playwright/test';

test('scan workspace keeps a balanced desktop hierarchy', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');

  await expect(page.getByRole('heading', { name: /Know whether to use/ })).toBeVisible();
  await expect(page).toHaveScreenshot('scan-desktop.png', {
    animations: 'disabled',
    maxDiffPixelRatio: 0.03
  });
});

test('report content uses the full width below its summary band', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await page.getByRole('button', { name: /Explore a demo report/i }).click();

  const header = page.locator('.report-header-grid');
  const scores = page.locator('.area-score-panel');
  await expect(header).toBeVisible();
  await expect(scores).toBeVisible();
  const headerBox = await header.boundingBox();
  const scoreBox = await scores.boundingBox();
  expect(headerBox).not.toBeNull();
  expect(scoreBox).not.toBeNull();
  expect(Math.abs(scoreBox!.x - headerBox!.x)).toBeLessThanOrEqual(2);
  expect(Math.abs(scoreBox!.width - headerBox!.width)).toBeLessThanOrEqual(2);

  await expect(page).toHaveScreenshot('report-desktop.png', {
    animations: 'disabled',
    maxDiffPixelRatio: 0.03
  });
  await page.getByText('Technical details', { exact: true }).click();
  await expect(page.getByText('Analyzer modules (7)')).toBeVisible();
});

test('report summary stacks cleanly on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.getByRole('button', { name: /Explore a demo report/i }).click();

  await expect(page.locator('.report-header-grid')).toBeVisible();
  await expect(page).toHaveScreenshot('report-mobile.png', {
    animations: 'disabled',
    maxDiffPixelRatio: 0.03
  });
});

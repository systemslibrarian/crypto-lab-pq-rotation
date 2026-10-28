import { test, expect } from '@playwright/test';
test('source policy distinguishes scope and purpose without applying OMB to NSS or private assets', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#us-federal-target')).toContainText('No deadline assigned');
  await page.selectOption('#us-federal-scope', 'prioritized_non_nss');
  await expect(page.locator('#us-federal-target')).toContainText('2030-12-31');
  await page.selectOption('#us-federal-use', 'digital_signature');
  await expect(page.locator('#us-federal-target')).toContainText('2031-12-31');
  await page.selectOption('#us-federal-scope', 'nss');
  await expect(page.locator('#us-federal-target')).toContainText('CNSA/NSS');
  await expect(page.locator('#us-federal-target')).not.toContainText('2031-12-31');
  await page.selectOption('#us-federal-scope', 'outside_federal');
  await expect(page.locator('#us-federal-target')).toContainText('not an already-effective blanket contractor mandate');
  await expect(page.locator('#us-non-nss-profile')).toContainText('2026-10-22');
  await expect(page.locator('#us-non-nss-profile')).toContainText('final report (27 October 2026)');
  await expect(page.locator('#us-non-nss-profile a[href="https://csrc.nist.gov/pubs/ir/8547/final"]')).toBeVisible();
  await expect(page.locator('#us-non-nss-profile')).toContainText('does not establish a universal private-sector deadline');
  await expect(page.locator('#us-non-nss-profile')).not.toContainText('initial public draft');
});

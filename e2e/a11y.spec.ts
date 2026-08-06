import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate for the PQ-Rotation migration planner.
 *
 * This lab is dark-only by design: there is no `[data-theme="light"]` CSS, so
 * the shared header's toggle flips the attribute but nothing about the page's
 * own styling changes. We therefore scan only the default (dark) theme — there
 * is no meaningful second visual state to assert.
 *
 * The whole dashboard is a single scrolling page (no <details>), but every live
 * exhibit is DRIVEN before scanning so the dynamically-injected result regions
 * (rotation log, verification checklist, tamper verdicts) are in the DOM when
 * axe runs. Any class-toggled / [hidden] panels are also force-revealed.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

// Neutralize animation/transition/opacity so mid-flight reveal states can't hide
// text from the contrast checker (panels animate in with `reveal`).
async function killMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;scroll-behavior:auto!important;
    }`,
  });
}

// Force-reveal any class-toggled / [hidden] / display:none collapsibles so their
// content is scannable, and open every <details> (none today, cheap insurance).
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const d of document.querySelectorAll('details')) (d as HTMLDetailsElement).open = true;
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) el.removeAttribute('hidden');
  });
}

// Drive every interactive exhibit so injected output regions exist during scan.
async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — load an inventory preset.
  await page.locator('button[data-action="demo"][data-demo="finance"]').click();

  // Exhibit 3 — cycle certificate views and run every tamper mode so both the
  // good and bad verdict regions are exercised.
  await page.locator('button[data-action="cert-view"][data-view="hybrid"]').click();
  await page.locator('button[data-action="cert-tamper"][data-tamper="classical"]').click();
  await expect(page.locator('.tamper-verdict')).toBeVisible();
  await page.locator('button[data-action="cert-tamper"][data-tamper="none"]').click();

  // Exhibit 4 — run a rotation with a failure injected so the error/status
  // channels render.
  await page.locator('#failureStep').selectOption('rotate_50');
  await page.locator('button[data-action="run-rotation"]').click();
  await expect(page.locator('#rotation .log-list li').first()).toBeVisible();

  // Exhibit 7 — run the full cryptographic self-test suite.
  await page.locator('button[data-action="run-verify"]').click();
  await expect(page.locator('#verify .checklist')).toBeVisible({ timeout: 30_000 });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#cl-theme-toggle')).toBeVisible();
  await expect(page.locator('#inventory')).toBeVisible();
  await killMotion(page);
});

test('no WCAG A/AA violations in dark theme (all exhibits driven)', async ({ page }) => {
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await driveDemos(page);
  await killMotion(page);
  await revealAll(page);
  await scan(page);
});

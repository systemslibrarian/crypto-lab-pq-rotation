import { expect, test, type Page } from '@playwright/test';

/**
 * Functional regression gate for the PQ-Rotation migration planner.
 *
 * The a11y spec proves the page is reachable and scannable; this one proves the
 * page is *right*. Nothing here is compared against a remembered constant that
 * the page could drift away from silently: every expected value is either
 * recomputed from other values the page itself rendered (the milestone dates
 * drive the Doom Meter, the form values drive the rotation duration, the size
 * segments drive the size totals) or cross-checked against a second place the
 * page states the same fact. A wrong number therefore has to be wrong
 * *consistently, everywhere*, to pass.
 *
 * What is pinned:
 *
 *   1. Inventory & Mosca — the summary tiles are the table they summarise
 *      (endpoint total = the Count column; HNDL score = exposed/catalogued), and
 *      the worked example really is X + Y > Z evaluated at the slider settings.
 *   2. The hybrid certificate's size story — each bar's total is the sum of its
 *      own segments, the three bars share one byte scale (the README's
 *      "to-scale" claim, checked against the rendered widths), and the
 *      multiplier and 55x crypto-material ratio in the prose are the ones the
 *      measured bytes imply. ML-DSA-65's FIPS 204 sizes (1,952 / 3,309 B) are
 *      pinned because the whole size lesson collapses if the primitive changes.
 *   3. The tamper lab, all four states — untampered, forged classical, forged
 *      PQ, altered body. Each asserts the verdict, the trust chain diagram, the
 *      three signature indicators AND the real flipped byte agree with each
 *      other, so "Rejected" can never be printed over a certificate the page
 *      just computed as valid (and vice versa). The single-bit signature flips
 *      are verified as single-bit by XOR-ing the before/after hex on screen.
 *   4. The timeline — every phase bar's count, percentage and 16-cell glyph bar
 *      agree, and the Doom Meter's three figures are recomputed here from the
 *      milestone dates rendered above it, for two different frameworks.
 *   5. Fleet rotation — the happy path's headline duration and step count are
 *      recomputed from the form values; the metric tiles partition the fleet to
 *      100%; and EVERY failure path (all four injection points, plus all three
 *      input-validation refusals) is driven and asserted to reach the failure
 *      state *and name its cause*.
 *   6. Stale state — a changed CRQC year, a swapped inventory, a swapped
 *      framework and a re-issued certificate must not leave the previous
 *      verdict, count or forged-signature banner standing.
 *
 * Two regressions found while writing this are pinned explicitly and marked
 * `Regression:` below: the rotation form silently reverting to its defaults on
 * every re-render, and the rollback caption blaming the canary for failures
 * that happened after the canary had already been promoted.
 */

const MS_PER_MONTH = 30 * 24 * 60 * 60 * 1000;
const MS_PER_YEAR = 365.25 * 24 * 60 * 60 * 1000;

/** ML-DSA-65 is fixed by FIPS 204; the size lesson is meaningless if it drifts. */
const ML_DSA_65_PUBKEY_BYTES = 1_952;
const ML_DSA_65_SIG_BYTES = 3_309;

/** Whitespace-normalised text of the first match, so prose is easy to assert on. */
async function text(page: Page, selector: string): Promise<string> {
  return ((await page.locator(selector).first().textContent()) ?? '').replace(/\s+/g, ' ').trim();
}

/** "6,127" / "1,197 B total" / "11.1%" -> 6127 / 1197 / 11.1 */
function num(raw: string): number {
  const match = /-?[\d,]*\.?\d+/.exec(raw.replace(/\s/g, ''));
  expect(match, `no number in ${JSON.stringify(raw)}`).not.toBeNull();
  return Number(match![0].replace(/,/g, ''));
}

function allNums(raw: string): number[] {
  return [...raw.matchAll(/-?[\d,]*\.?\d+/g)].map((m) => Number(m[0].replace(/,/g, '')));
}

/** The page formats every percentage with exactly one decimal. */
function pct(value: number): string {
  return `${value.toFixed(1)}%`;
}

/** The state word each block of the trust-chain diagram is showing. */
async function chainStates(page: Page): Promise<string[]> {
  return (await page.locator('.cs-block .cs-state').allTextContents()).map((s) => s.trim());
}

/** Whether each trust-chain block is flagged bad, in diagram order. */
async function chainBad(page: Page): Promise<boolean[]> {
  return (await page.locator('.cs-block').evaluateAll((els) => els.map((el) => el.classList.contains('bad'))));
}

async function sigStates(page: Page): Promise<string[]> {
  return (await page.locator('.sig-indicator strong').allTextContents()).map((s) => s.trim());
}

/**
 * The verdict banner, the trust-chain diagram and the three signature
 * indicators are three renderings of one computed verification result. Assert
 * they cannot disagree — that is the only way "Rejected" over a valid cert (or
 * "Trusted" over a forged one) gets caught rather than read past.
 */
async function expectVerdictMatchesChain(page: Page): Promise<void> {
  const [chain, sigs, bad] = [await chainStates(page), await sigStates(page), await chainBad(page)];
  const verdictTone = (await page.locator('.tamper-verdict').getAttribute('class')) ?? '';
  const trusted = chain[4] === 'TRUSTED';

  expect(chain[2]).toBe(sigs[0]); // classical, diagram vs indicator
  expect(chain[3]).toBe(sigs[1]); // post-quantum, diagram vs indicator
  expect(sigs[2]).toBe(trusted ? 'VALID' : 'FORGED'); // overall
  expect(bad[4]).toBe(!trusted);
  // Trust holds exactly when both signature branches hold — the composite rule.
  expect(trusted).toBe(chain[2] === 'VALID' && chain[3] === 'VALID');
  expect(verdictTone.includes('good')).toBe(trusted);
  expect(verdictTone.includes('bad')).toBe(!trusted);
  await expect(page.locator('.tamper-verdict strong')).toHaveText(
    trusted ? /^Trusted/ : /^Rejected/,
  );
}

/** Read the four rotation controls as the operator sees them. */
async function rotationForm(page: Page): Promise<[string, string, string, string]> {
  return [
    await page.locator('#canaryPercent').inputValue(),
    await page.locator('#monitorHours').inputValue(),
    await page.locator('#rolloutStages').inputValue(),
    await page.locator('#failureStep').inputValue(),
  ];
}

/**
 * Click Run Rotation and wait for the simulation to finish. The run issues 1,247
 * real hybrid certificates on the main thread, so it is slow; completion is
 * detected by the log actually changing, not by a sleep.
 */
async function runRotation(page: Page): Promise<void> {
  const button = page.locator('button[data-action="run-rotation"]');
  const previousLog = (await page.locator('#rotation .log-list').textContent()) ?? '';
  await button.click();
  await expect(button).toBeEnabled({ timeout: 180_000 });
  await expect(button).toHaveText('Run Rotation');
  await expect
    .poll(async () => (await page.locator('#rotation .log-list').textContent()) ?? '', { timeout: 180_000 })
    .not.toBe(previousLog);
}

// Uncaught page exceptions fail the test that provoked them. Reset per test;
// a worker only ever runs one test at a time, so this stays test-scoped.
let pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto('.');
  // The certificate is issued with real ECDSA + ML-DSA keys before the first
  // paint, so the dashboard existing means the crypto already ran.
  await expect(page.locator('#inventory')).toBeVisible();
});

test.afterEach(() => {
  expect(pageErrors).toEqual([]);
});

/* ------------------------------------------------------------------ *
 * 1. Inventory and Mosca's inequality
 * ------------------------------------------------------------------ */

test('the inventory tiles are exactly the table and the verdict they summarise', async ({ page }) => {
  const counts = await page.locator('#inventory tbody tr td:nth-child(3)').allTextContents();
  expect(counts.length).toBeGreaterThan(0);
  const tableTotal = counts.reduce((sum, cell) => sum + num(cell), 0);

  const tiles = await page.locator('#inventory .metrics div').allTextContents();
  expect(tiles).toHaveLength(3);

  // "Catalogued Endpoints" is the Count column added up, not a separate figure.
  expect(num(tiles[0].replace('Catalogued Endpoints', ''))).toBe(tableTotal);

  // "Quantum-Vulnerable Systems n/m": n <= m, and m is the catalogued item count
  // the timeline section independently states.
  const [vulnerable, catalogued] = allNums(tiles[1].replace('Quantum-Vulnerable Systems', ''));
  expect(vulnerable).toBeLessThanOrEqual(catalogued);
  expect(catalogued).toBe(num(/of the (\d+) catalogued systems/.exec(await text(page, '#timeline .small-note'))![1]));

  // The Mosca verdict counts and the HNDL score are one computation shown twice:
  // score = round(exposed / catalogued * 100), and the band is that score's band.
  const verdict = await text(page, '.mosca-verdict');
  const [exposed, verdictVulnerable] = allNums(verdict);
  expect(verdict).toContain('already past the line');
  expect(verdictVulnerable).toBe(vulnerable);
  expect(exposed).toBeLessThanOrEqual(vulnerable);

  const scoreTile = tiles[2].replace('HNDL Score (already exposed)', '');
  const score = num(scoreTile);
  expect(score).toBe(Math.round((exposed / catalogued) * 100));
  expect(scoreTile).toContain(score >= 60 ? 'HIGH' : score >= 30 ? 'ELEVATED' : 'MODERATE');

  // Colour is not the only carrier: the verdict's tone class tracks the count.
  await expect(page.locator('.mosca-verdict')).toHaveClass(exposed > 0 ? /bad/ : /good/);
});

test("the worked example is Mosca's inequality evaluated at the slider settings", async ({ page }) => {
  const crqcYear = num(await text(page, 'label[for="crqc-slider"] strong'));
  expect(String(crqcYear)).toBe(await page.locator('#crqc-slider').inputValue());
  const migrationYears = num(await text(page, 'label[for="migration-slider"] strong'));
  expect(String(migrationYears)).toBe(await page.locator('#migration-slider').inputValue());

  // Z is printed next to the slider and is years-until-CRQC from today.
  const z = num(/Z = (\d+) yrs/.exec(await text(page, 'label[for="crqc-slider"]'))![1]);
  expect(z).toBe(Math.max(0, crqcYear - new Date().getUTCFullYear()));

  const example = await text(page, '.mosca-example');
  const parsed = /X=(\d+) \+ Y=(\d+) = (\d+) vs Z=(\d+)/.exec(example);
  expect(parsed, `unparsable worked example: ${example}`).not.toBeNull();
  const [x, y, sum, exampleZ] = parsed!.slice(1).map(Number);

  // The arithmetic on screen is the arithmetic: X + Y really is the sum shown,
  // Y is the migration slider, Z is the same Z the slider label printed.
  expect(y).toBe(migrationYears);
  expect(exampleZ).toBe(z);
  expect(sum).toBe(x + y);

  // And the conclusion is the sign of (X + Y) - Z, with the magnitude stated.
  const margin = sum - z;
  if (margin > 0) {
    expect(example).toContain(`Exposed by ${margin} year(s)`);
  } else {
    expect(example).toContain(`Buffer of ${Math.abs(margin)} year(s)`);
  }

  // The named worst case really is the worst: no HNDL row can exceed its shelf
  // life, since the example is chosen by largest margin and Y and Z are shared.
  for (const row of await page.locator('#inventory .alert li').allTextContents()) {
    const shelf = /its (\d+)-year sensitivity window/.exec(row);
    if (shelf) expect(Number(shelf[1])).toBeLessThanOrEqual(x);
  }
});

test('each HNDL row states the exposure its own numbers imply', async ({ page }) => {
  const z = num(/Z = (\d+) yrs/.exec(await text(page, 'label[for="crqc-slider"]'))![1]);
  const crqcYear = num(await text(page, 'label[for="crqc-slider"] strong'));

  const rows = await page.locator('#inventory .alert li').allTextContents();
  expect(rows.length).toBeGreaterThan(0);
  for (const row of rows) {
    const parsed = /its (\d+)-year sensitivity window extends (\d+) year\(s\) past a (\d+) CRQC scenario/.exec(row);
    expect(parsed, `unparsable HNDL row: ${row}`).not.toBeNull();
    const [shelfLife, overhang, statedYear] = parsed!.slice(1).map(Number);
    // exposure = shelf life minus the years left before the CRQC the slider set.
    expect(overhang).toBe(Math.max(0, shelfLife - z));
    expect(overhang).toBeGreaterThan(0); // only at-risk systems are listed here
    expect(statedYear).toBe(crqcYear);
  }
});

test('moving the CRQC slider re-derives every dependent number, leaving none stale', async ({ page }) => {
  const before = {
    verdict: await text(page, '.mosca-verdict'),
    score: await text(page, '#inventory .metrics div:nth-child(3)'),
    rows: await page.locator('#inventory .alert li').allTextContents(),
  };
  const beforeExposed = allNums(before.verdict)[0];

  await page.locator('#crqc-slider').fill('2045');

  // Z moves with the slider, and every figure derived from it moves with Z.
  await expect(page.locator('label[for="crqc-slider"] strong')).toHaveText('2045');
  const z = num(/Z = (\d+) yrs/.exec(await text(page, 'label[for="crqc-slider"]'))![1]);
  expect(z).toBe(2045 - new Date().getUTCFullYear());

  const afterVerdict = await text(page, '.mosca-verdict');
  const [afterExposed, vulnerable] = allNums(afterVerdict);
  // A later CRQC cannot expose MORE systems — the verdict is not a random number.
  expect(afterExposed).toBeLessThan(beforeExposed);
  expect(num(await text(page, '#inventory .metrics div:nth-child(3)'))).toBe(
    Math.round((afterExposed / vulnerable) * 100),
  );

  // No stale CRQC year survives in the HNDL explanations, and every row is
  // recomputed against the new Z rather than the old one.
  const afterRows = await page.locator('#inventory .alert li').allTextContents();
  expect(afterRows).not.toEqual(before.rows);
  for (const row of afterRows) {
    expect(row).toContain('2045 CRQC scenario');
    const parsed = /its (\d+)-year sensitivity window extends (\d+) year\(s\)/.exec(row)!;
    expect(Number(parsed[2])).toBe(Number(parsed[1]) - z);
  }
  expect(await text(page, '.mosca-example')).toContain(`vs Z=${z}`);
});

test('switching the inventory demo replaces every figure derived from it', async ({ page }) => {
  const govTotal = num(await text(page, '#inventory .metrics div:nth-child(1)'));
  const govItems = allNums(await text(page, '#inventory .metrics div:nth-child(2)'))[1];
  const govWorstCase = await text(page, '.mosca-example');

  await page.locator('button[data-action="demo"][data-demo="small"]').click();

  // Exactly one preset is pressed at a time.
  await expect(page.locator('button[data-demo="small"]')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('button[data-demo="gov"]')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('button[data-demo="finance"]')).toHaveAttribute('aria-pressed', 'false');

  // The tiles are the NEW table, not the old one.
  const counts = await page.locator('#inventory tbody tr td:nth-child(3)').allTextContents();
  const total = counts.reduce((sum, cell) => sum + num(cell), 0);
  expect(num(await text(page, '#inventory .metrics div:nth-child(1)'))).toBe(total);
  expect(total).not.toBe(govTotal);

  // …and so is every downstream count, including the timeline's item count.
  const items = allNums(await text(page, '#inventory .metrics div:nth-child(2)'))[1];
  expect(items).not.toBe(govItems);
  expect(await text(page, '.mosca-example')).not.toBe(govWorstCase);
  expect(num(/of the (\d+) catalogued systems/.exec(await text(page, '#timeline .small-note'))![1])).toBe(items);
  for (const row of await page.locator('.phase-row em').allTextContents()) {
    expect(num(/\d+\/(\d+) items/.exec(row)![1])).toBe(items);
  }
});

/* ------------------------------------------------------------------ *
 * 2. The hybrid certificate's measured size story
 * ------------------------------------------------------------------ */

interface Bar {
  title: string;
  total: number;
  segments: Array<{ label: string; bytes: number; widthPercent: number }>;
}

async function readBars(page: Page): Promise<Bar[]> {
  return page.locator('.cert-bar-row').evaluateAll((rows) =>
    rows.map((row) => ({
      title: (row.querySelector('.cert-bar-head strong')?.textContent ?? '').trim(),
      total: Number((row.querySelector('.cert-bar-total')?.textContent ?? '').replace(/[^\d]/g, '')),
      segments: [...row.querySelectorAll<HTMLElement>('.cert-seg')].map((seg) => ({
        label: (seg.getAttribute('title') ?? '').split(':')[0],
        bytes: Number((seg.getAttribute('title') ?? '').replace(/^[^:]*:\s*/, '').replace(/[^\d]/g, '')),
        widthPercent: Number.parseFloat(seg.style.width),
      })),
    })),
  );
}

test('every size bar totals its own segments, and all three share one byte scale', async ({ page }) => {
  const bars = await readBars(page);
  expect(bars).toHaveLength(3);
  const [classical, hybrid, purePq] = bars;

  // Each bar's printed total is the sum of the segments drawn inside it, and its
  // aria-label repeats the same figures for a screen reader.
  for (const [index, bar] of bars.entries()) {
    expect(bar.segments.reduce((sum, seg) => sum + seg.bytes, 0)).toBe(bar.total);
    const label = (await page.locator('.cert-bar').nth(index).getAttribute('aria-label')) ?? '';
    expect(label).toContain(`${bar.total.toLocaleString('en-US')} bytes total`);
    for (const seg of bar.segments) {
      expect(label).toContain(`${seg.label} ${seg.bytes.toLocaleString('en-US')} bytes`);
    }
  }

  const bytesOf = (bar: Bar, label: string): number =>
    bar.segments.find((seg) => seg.label === label)?.bytes ?? -1;

  // The variants are the same parts recombined: hybrid is classical plus the two
  // PQ pieces, and pure-PQ is hybrid minus the two classical pieces.
  const envelope = bytesOf(classical, 'X.509 envelope');
  const classicalPub = bytesOf(classical, 'ECDSA pubkey');
  const classicalSig = bytesOf(classical, 'ECDSA sig');
  const pqPub = bytesOf(hybrid, 'ML-DSA pubkey');
  const pqSig = bytesOf(hybrid, 'ML-DSA sig');
  expect(bytesOf(hybrid, 'X.509 envelope')).toBe(envelope);
  expect(bytesOf(purePq, 'X.509 envelope')).toBe(envelope);
  expect(hybrid.total).toBe(classical.total + pqPub + pqSig);
  expect(purePq.total).toBe(hybrid.total - classicalPub - classicalSig);

  // The measured primitives are the real ones: P-256 compressed key + compact
  // signature, ML-DSA-65 at its FIPS 204 fixed sizes.
  expect(classicalPub).toBe(33);
  expect(classicalSig).toBe(64);
  expect(pqPub).toBe(ML_DSA_65_PUBKEY_BYTES);
  expect(pqSig).toBe(ML_DSA_65_SIG_BYTES);

  // README: the bars are "to scale" against one shared maximum. Every segment's
  // rendered width is its byte share of the widest bar, so the eye comparison is
  // honest and the ML-DSA signature really is the widest single block.
  const scaleMax = Math.max(...bars.map((bar) => bar.total));
  for (const bar of bars) {
    for (const seg of bar.segments) {
      expect(seg.widthPercent).toBeCloseTo((seg.bytes / scaleMax) * 100, 2);
    }
  }
  const widest = hybrid.segments.reduce((best, seg) => (seg.bytes > best.bytes ? seg : best));
  expect(widest.label).toBe('ML-DSA sig');
  expect(pqSig).toBeGreaterThan(classical.total);
});

test('the size prose quotes the ratios the measured bytes imply', async ({ page }) => {
  const [classical, hybrid, purePq] = await readBars(page);
  const bytesOf = (bar: Bar, label: string): number => bar.segments.find((seg) => seg.label === label)!.bytes;

  const multiplier = Number((hybrid.total / classical.total).toFixed(1));
  // The multiplier appears in the bar's own heading and again in the prose.
  expect(hybrid.title).toContain(`(${multiplier}× larger)`);

  const note = await text(page, '.cert-bars .small-note:last-of-type');
  expect(note).toContain(
    `grows ${multiplier}× (${classical.total.toLocaleString('en-US')} → ${hybrid.total.toLocaleString('en-US')} B)`,
  );
  expect(note).toContain(`The pure-PQ leaf (${purePq.total.toLocaleString('en-US')} B)`);

  // The "roughly 55x" crypto-material claim, recomputed: public key + signature
  // only, with the shared envelope excluded from both sides.
  const classicalMaterial = bytesOf(classical, 'ECDSA pubkey') + bytesOf(classical, 'ECDSA sig');
  const hybridMaterial = hybrid.total - bytesOf(hybrid, 'X.509 envelope');
  expect(note).toContain(`roughly ${Math.round(hybridMaterial / classicalMaterial)}×`);

  // The headline byte figure in the intro note is the ML-DSA signature segment.
  expect(await text(page, '.cert-bars .small-note')).toContain(
    `(${bytesOf(hybrid, 'ML-DSA sig').toLocaleString('en-US')} B)`,
  );
});

test('the certificate view buttons focus exactly one bar each', async ({ page }) => {
  for (const [view, index] of [['classical', 0], ['hybrid', 1], ['pure_pq', 2]] as const) {
    await page.locator(`button[data-action="cert-view"][data-view="${view}"]`).click();
    await expect(page.locator(`button[data-view="${view}"]`)).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.cert-bar-row.focus')).toHaveCount(1);
    await expect(page.locator('.cert-bar-row').nth(index)).toHaveClass(/focus/);
    // No second chip claims to be pressed.
    await expect(page.locator('button[data-action="cert-view"][aria-pressed="true"]')).toHaveCount(1);
  }
});

/* ------------------------------------------------------------------ *
 * 3. The tamper lab — every state it can reach
 * ------------------------------------------------------------------ */

test('an untampered certificate is trusted, with the whole chain intact', async ({ page }) => {
  expect(await chainStates(page)).toEqual(['intact', 'matches', 'VALID', 'VALID', 'TRUSTED']);
  expect(await chainBad(page)).toEqual([false, false, false, false, false]);
  expect(await sigStates(page)).toEqual(['VALID', 'VALID', 'VALID']);
  await expectVerdictMatchesChain(page);
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Trusted — both signatures verify');
  await expect(page.locator('.flip-line')).toHaveText(/No byte flipped/);
  await expect(page.locator('button[data-tamper="none"]')).toHaveAttribute('aria-pressed', 'true');
});

test('forging the classical signature fails only that branch, and names the flipped bit', async ({ page }) => {
  await page.locator('button[data-action="cert-tamper"][data-tamper="classical"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Rejected — classical signature forged');

  // The PQ branch is untouched and still verifies — that is the entire point of
  // the composite construction, so it is asserted, not assumed.
  expect(await chainStates(page)).toEqual(['intact', 'matches', 'FORGED', 'VALID', 'FORGED']);
  expect(await chainBad(page)).toEqual([false, false, true, false, true]);
  expect(await sigStates(page)).toEqual(['FORGED', 'VALID', 'FORGED']);
  await expectVerdictMatchesChain(page);
  await expect(page.locator('.tamper-verdict p')).toContainText('ML-DSA-65 still does');

  // The cause is named, and the byte on screen really is a one-bit flip.
  await expect(page.locator('.flip-line strong')).toHaveText('ECDSA-P256 signature, byte 0');
  const before = Number.parseInt((await text(page, '.hex-before')).replace('0x', ''), 16);
  const after = Number.parseInt((await text(page, '.hex-after')).replace('0x', ''), 16);
  expect(before ^ after).toBe(1);
});

test('forging the PQ signature fails only that branch, and names the flipped bit', async ({ page }) => {
  await page.locator('button[data-action="cert-tamper"][data-tamper="pq"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Rejected — PQ signature forged');

  expect(await chainStates(page)).toEqual(['intact', 'matches', 'VALID', 'FORGED', 'FORGED']);
  expect(await chainBad(page)).toEqual([false, false, false, true, true]);
  expect(await sigStates(page)).toEqual(['VALID', 'FORGED', 'FORGED']);
  await expectVerdictMatchesChain(page);
  await expect(page.locator('.tamper-verdict p')).toContainText('classical ECDSA still does');

  await expect(page.locator('.flip-line strong')).toHaveText('ML-DSA-65 signature, byte 0');
  const before = Number.parseInt((await text(page, '.hex-before')).replace('0x', ''), 16);
  const after = Number.parseInt((await text(page, '.hex-after')).replace('0x', ''), 16);
  expect(before ^ after).toBe(1);
});

test('altering the body breaks the hash and both signatures at once', async ({ page }) => {
  await page.locator('button[data-action="cert-tamper"][data-tamper="body"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Rejected — certificate contents altered');

  // Body -> hash -> both signatures: the failure propagates down the whole chain,
  // which is the causal story the diagram exists to tell.
  expect(await chainStates(page)).toEqual(['ALTERED', 'MISMATCH', 'FORGED', 'FORGED', 'FORGED']);
  expect(await chainBad(page)).toEqual([true, true, true, true, true]);
  expect(await sigStates(page)).toEqual(['FORGED', 'FORGED', 'FORGED']);
  await expectVerdictMatchesChain(page);
  await expect(page.locator('.tamper-verdict p')).toContainText('SHA-256 hash no longer matches');

  // A changed body rehashes wholesale — this is NOT a one-bit flip, and the page
  // shows the real recomputed hash byte rather than a prop.
  await expect(page.locator('.flip-line strong')).toHaveText('certificate body → SHA-256 hash, byte 0');
  const before = await text(page, '.hex-before');
  const after = await text(page, '.hex-after');
  expect(after).not.toBe(before);
  expect(after).toMatch(/^0x[0-9A-F]{2}$/);
});

test('reset re-issues a certificate and retracts every forged verdict', async ({ page }) => {
  await page.locator('button[data-action="cert-tamper"][data-tamper="body"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText(/^Rejected/);
  const forgedHex = await text(page, '.hex-after');

  await page.locator('button[data-action="cert-tamper"][data-tamper="none"]').click();

  // No stale FORGED anywhere: verdict, diagram, indicators and flip line all go
  // back to the trusted state, and only the reset chip reads as pressed.
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Trusted — both signatures verify');
  expect(await chainStates(page)).toEqual(['intact', 'matches', 'VALID', 'VALID', 'TRUSTED']);
  expect(await sigStates(page)).toEqual(['VALID', 'VALID', 'VALID']);
  await expectVerdictMatchesChain(page);
  await expect(page.locator('.flip-line')).toHaveText(/No byte flipped/);
  await expect(page.locator('.hex-after')).toHaveCount(0);
  expect(forgedHex).not.toBe('');
  await expect(page.locator('button[data-action="cert-tamper"][aria-pressed="true"]')).toHaveCount(1);
  await expect(page.locator('button[data-tamper="none"]')).toHaveAttribute('aria-pressed', 'true');

  // And the tamper lab still works on the newly issued certificate — the reset
  // does not leave a dead control behind.
  await page.locator('button[data-action="cert-tamper"][data-tamper="classical"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Rejected — classical signature forged');
});

/* ------------------------------------------------------------------ *
 * 4. Regulatory timeline and the Doom Meter
 * ------------------------------------------------------------------ */

test('every phase bar agrees with its own count, percentage and glyph bar', async ({ page }) => {
  const rows = page.locator('.phase-row');
  await expect(rows).toHaveCount(5);
  const items = num(/of the (\d+) catalogued systems/.exec(await text(page, '#timeline .small-note'))![1]);

  for (let index = 0; index < 5; index += 1) {
    const row = rows.nth(index);
    const headline = (await row.locator('em').textContent())!.replace(/\s+/g, ' ');
    const parsed = /Phase (\d) (.+) — (\d+)\/(\d+) items due by today \(([\d.]+)%\)/.exec(headline);
    expect(parsed, `unparsable phase row: ${headline}`).not.toBeNull();
    const [phase, , done, total, percent] = parsed!.slice(1);

    expect(Number(phase)).toBe(index + 1);
    // Every phase plans one action per catalogued item, so the denominators all
    // match the inventory — a phase quietly covering fewer items would show here.
    expect(Number(total)).toBe(items);
    expect(Number(done)).toBeLessThanOrEqual(Number(total));
    expect(percent).toBe(((Number(done) / Number(total)) * 100).toFixed(1));

    // The 16-cell glyph bar is that percentage, not a decoration.
    const glyphs = (await row.locator('.phase-bar').textContent())!;
    expect(glyphs).toHaveLength(16);
    expect([...glyphs].filter((glyph) => glyph === '█')).toHaveLength(
      Math.round((Number(percent) / 100) * 16),
    );

    // The sentence under the bar restates the same two counts and the phase.
    const detail = (await row.locator('.phase-detail').textContent())!.replace(/\s+/g, ' ');
    expect(detail).toContain(`${done} of ${total} planned Phase ${phase} actions`);
    if (Number(done) === Number(total)) {
      expect(detail).toContain('already past-due today');
    } else {
      // The named example is a real future date, later than today.
      const date = /scheduled (\d{4}-\d{2}-\d{2})/.exec(detail);
      expect(date, `no example date in: ${detail}`).not.toBeNull();
      expect(new Date(`${date![1]}T00:00:00.000Z`).getTime()).toBeGreaterThan(Date.now());
    }
  }
});

/** Recompute the Doom Meter from the milestone dates the page is showing. */
async function expectDoomMatchesMilestones(page: Page): Promise<void> {
  const dates = (await page.locator('.milestone strong').allTextContents()).map((value) =>
    new Date(`${value.trim()}T00:00:00.000Z`).getTime(),
  );
  expect(dates).toHaveLength(4); // planning, pilot, high_risk, full_migration
  const now = Date.now();

  const expectedFirstHybrid = Math.max(1, Math.round((dates[1] - now) / MS_PER_MONTH));
  const expectedHalfCoverage = Math.max(expectedFirstHybrid + 6, Math.round((dates[2] - now) / MS_PER_MONTH));
  const expectedFullYears = (dates[3] - now) / MS_PER_YEAR;

  const summary = await text(page, '.doom p:nth-of-type(2)');
  const parsed = /first hybrid deployment in (\d+) months .*50% hybrid in (\d+) months .*full migration in ([\d.]+) years/.exec(summary);
  expect(parsed, `unparsable Doom Meter: ${summary}`).not.toBeNull();
  const [firstHybrid, halfCoverage, fullYears] = parsed!.slice(1).map(Number);

  expect(firstHybrid).toBe(expectedFirstHybrid);
  expect(halfCoverage).toBe(expectedHalfCoverage);
  expect(fullYears).toBeCloseTo(expectedFullYears, 1);
  // The milestones are in chronological order, so the meter's own figures are too.
  expect(halfCoverage).toBeGreaterThanOrEqual(firstHybrid);

  // The warning sentence is the branch those three figures select, not a mood.
  const expectedWarning =
    halfCoverage > 30
      ? '50% hybrid coverage lands dangerously close to high-risk mandates.'
      : firstHybrid > 9
        ? 'Late hybrid start pushes emergency cutover risk toward regulatory deadlines.'
        : 'On schedule with focused execution.';
  expect(await text(page, '.doom p:nth-of-type(3)')).toBe(expectedWarning);
}

test('the Doom Meter is derived from the milestone dates rendered above it', async ({ page }) => {
  await expectDoomMatchesMilestones(page);
});

test('switching framework re-derives the milestones and the Doom Meter, leaving none stale', async ({ page }) => {
  const euDates = await page.locator('.milestone strong').allTextContents();
  const euDoom = await text(page, '.doom p:nth-of-type(2)');
  await expect(page.locator('#timeline .small-note').first()).toContainText('EU NIS');

  await page.locator('input[data-action="framework"][value="CNSA_2.0"]').check();

  const cnsaDates = await page.locator('.milestone strong').allTextContents();
  expect(cnsaDates).not.toEqual(euDates);
  expect(await text(page, '.doom p:nth-of-type(2)')).not.toBe(euDoom);
  await expect(page.locator('#timeline .small-note').first()).toContainText('CNSA 2.0');
  await expect(page.locator('#timeline .small-note').first()).not.toContainText('EU NIS');
  await expectDoomMatchesMilestones(page);

  // A second switch, to a framework whose deadlines are much closer, must move
  // the numbers again rather than keeping the previous framework's answer.
  await page.locator('input[data-action="framework"][value="Australia_ASD"]').check();
  expect(await page.locator('.milestone strong').allTextContents()).not.toEqual(cnsaDates);
  await expectDoomMatchesMilestones(page);
  // Milestone descriptions come from the selected framework too.
  await expect(page.locator('.milestone').last()).toContainText('ASD policy');
});

/* ------------------------------------------------------------------ *
 * 5. Fleet rotation — the happy path, and every way it can fail
 * ------------------------------------------------------------------ */

/** The four metric tiles, as {label: percent}. */
async function fleetMetrics(page: Page): Promise<Record<string, number>> {
  const entries = await page.locator('#rotation .metrics div').evaluateAll((els) =>
    els.map((el) => [
      (el.querySelector('span')?.textContent ?? '').trim(),
      Number.parseFloat((el.querySelector('strong')?.textContent ?? '').replace('%', '')),
    ] as [string, number]),
  );
  return Object.fromEntries(entries);
}

test('a clean rotation ends on hybrid, with a duration and step count the form implies', async ({ page }) => {
  test.setTimeout(240_000);

  // Before any run the fleet is entirely classical and the tiles say so.
  expect(await fleetMetrics(page)).toEqual({
    'Classical Only': 100,
    Hybrid: 0,
    'Pure PQ': 0,
    'Traffic on Hybrid or PQ': 0,
  });
  await expect(page.locator('.fleet-card .small-note')).toContainText('Fleet before rotation');
  await expect(page.locator('#rotation .log-list li')).toHaveText(['No simulation run yet.']);

  const [, monitorHours, stages] = await rotationForm(page);
  await runRotation(page);

  // The tiles partition the fleet: the three status shares sum to 100%.
  const metrics = await fleetMetrics(page);
  expect(metrics['Classical Only'] + metrics.Hybrid + metrics['Pure PQ']).toBeCloseTo(100, 1);
  expect(metrics.Hybrid).toBe(100);
  expect(metrics['Traffic on Hybrid or PQ']).toBeCloseTo(100, 1);

  // The headline is recomputed from the form values, not remembered:
  //   issue(1) + canary deploy(1) + canary monitor(M) + promote(0.25)
  //   + per stage (rotate 1 + monitor 2M) + retire(1)
  const stageList = stages.split(',').map((value) => Number(value.trim()));
  const monitor = Number(monitorHours);
  const expectedDuration = 3.25 + monitor + stageList.length * (1 + 2 * monitor);
  const expectedSteps = 4 + 2 * stageList.length + 1;

  const summary = await text(page, '#rotation .card[role="status"] p');
  const [duration, steps, readiness] = allNums(summary);
  expect(duration).toBeCloseTo(expectedDuration, 2);
  expect(steps).toBe(expectedSteps);
  // Readiness in the sentence is the Hybrid tile above it.
  expect(pct(readiness)).toBe(pct(metrics.Hybrid));
  await expect(page.locator('.status-message')).toHaveText('Rotation completed with phase gates satisfied.');
  await expect(page.locator('.status-message')).toHaveClass(/info/);

  // The log is the canary-first order the README promises, with the stages in
  // the order the form listed them.
  const logs = await page.locator('#rotation .log-list li').allTextContents();
  expect(logs.at(-1)).toContain('retire_old_cert');
  const rolloutStages = logs
    .filter((entry) => entry.includes('Rolled hybrid certificates to the'))
    .map((entry) => num(/to the ([\d]+)% fleet stage/.exec(entry)![1]));
  expect(rolloutStages).toEqual(stageList.slice(-rolloutStages.length));
  for (const entry of logs.filter((line) => line.includes('% rollout for'))) {
    // Each stage is watched for twice the canary window.
    expect(num(/for (\d+) simulated/.exec(entry)![1])).toBe(monitor * 2);
  }

  // Exactly one dot is the canary, every sampled dot is hybrid, and the caption
  // says which way round the rollout went.
  const dots = page.locator('.fleet-grid .fleet-dot');
  await expect(page.locator('.fleet-grid .is-canary')).toHaveCount(1);
  await expect(page.locator('.fleet-grid .dot-classical')).toHaveCount(0);
  await expect(page.locator('.fleet-grid .dot-hybrid')).toHaveCount(await dots.count());
  await expect(page.locator('.fleet-grid .is-canary')).toHaveAttribute('aria-label', /, canary$/);
  await expect(page.locator('.fleet-card .small-note')).toContainText('After rotation: servers recoloured to hybrid');
});

test('every injected failure rolls back, and the page names the gate that failed', async ({ page }) => {
  test.setTimeout(600_000);

  for (const [option, expectedStage] of [
    ['rotate_10', 10],
    ['monitor_10', 10],
    ['rotate_50', 50],
    ['rotate_100', 100],
  ] as const) {
    await page.locator('#failureStep').selectOption(option);
    await runRotation(page);

    // Regression: the form used to reset to "No failure" on the re-render that
    // followed the run, so the control contradicted the result printed beside it.
    expect(await page.locator('#failureStep').inputValue()).toBe(option);

    // The fleet really is back where it started — no partial rollout survives.
    const metrics = await fleetMetrics(page);
    expect(metrics).toEqual({ 'Classical Only': 100, Hybrid: 0, 'Pure PQ': 0, 'Traffic on Hybrid or PQ': 0 });
    await expect(page.locator('.fleet-grid .dot-hybrid')).toHaveCount(0);
    await expect(page.locator('.fleet-grid .dot-classical')).toHaveCount(
      await page.locator('.fleet-grid .fleet-dot').count(),
    );

    // The failure is announced on the alert channel, not just styled red.
    await expect(page.locator('.status-message')).toHaveText('Rotation failed a phase gate and rolled back safely.');
    await expect(page.locator('.status-message')).toHaveClass(/error/);
    await expect(page.locator('.status-message')).toHaveAttribute('role', 'alert');
    expect(await text(page, '#rotation .card[role="status"] p')).toContain('halted and rolled back');

    // The log ends with the failed gate followed by the automatic rollback, and
    // the failed line names the stage the form asked to break.
    const logs = await page.locator('#rotation .log-list li').allTextContents();
    expect(logs.at(-1)).toContain('rollback');
    const failedLine = logs.at(-2)!;
    expect(num(/(\d+)%/.exec(failedLine)![1])).toBe(expectedStage);
    expect(failedLine).toMatch(option.startsWith('rotate') ? /Injected .* failure/ : /Observed/);

    // Regression: the fleet caption used to blame the canary for EVERY rollback,
    // contradicting the log directly below it — by the 50% stage the canary had
    // long since been monitored and promoted. It must name the real stage.
    const caption = await text(page, '.fleet-card .small-note');
    expect(caption).toContain('After rollback');
    expect(caption).toContain(`the ${expectedStage}% rollout stage failed its gate`);
    expect(caption).not.toContain('the canary (★) failed its gate');
  }
});

test('the rotation form survives re-renders and the run honours what it says', async ({ page }) => {
  test.setTimeout(240_000);

  await page.locator('#canaryPercent').fill('15');
  await page.locator('#monitorHours').fill('2');
  await page.locator('#rolloutStages').fill('25,75');
  await page.locator('#failureStep').selectOption('rotate_50');

  // Regression: every one of these re-renders the whole dashboard from state, and
  // each used to silently reset all four controls back to 10 / 24 / 10,50,100 /
  // none, discarding what the operator had entered.
  await page.locator('button[data-action="cert-tamper"][data-tamper="pq"]').click();
  await expect(page.locator('.tamper-verdict strong')).toHaveText('Rejected — PQ signature forged');
  expect(await rotationForm(page)).toEqual(['15', '2', '25,75', 'rotate_50']);

  await page.locator('#crqc-slider').fill('2040');
  await expect(page.locator('label[for="crqc-slider"] strong')).toHaveText('2040');
  expect(await rotationForm(page)).toEqual(['15', '2', '25,75', 'rotate_50']);

  await page.locator('button[data-action="demo"][data-demo="finance"]').click();
  await expect(page.locator('button[data-demo="finance"]')).toHaveAttribute('aria-pressed', 'true');
  expect(await rotationForm(page)).toEqual(['15', '2', '25,75', 'rotate_50']);

  // A stage list that is not the default is actually what gets simulated…
  await page.locator('#failureStep').selectOption('none');
  await runRotation(page);
  expect(await rotationForm(page)).toEqual(['15', '2', '25,75', 'none']);

  const logs = await page.locator('#rotation .log-list li').allTextContents();
  const stages = logs
    .filter((entry) => entry.includes('Rolled hybrid certificates to the'))
    .map((entry) => num(/to the (\d+)% fleet stage/.exec(entry)![1]));
  expect(stages).toEqual([25, 75]);
  expect(logs.some((entry) => entry.includes('Observed the canary for 2 simulated hour(s)'))).toBe(true);

  // …and the shortened schedule shows up in the headline duration and step count.
  const [duration, steps] = allNums(await text(page, '#rotation .card[role="status"] p'));
  expect(duration).toBeCloseTo(3.25 + 2 + 2 * (1 + 4), 2);
  expect(steps).toBe(4 + 2 * 2 + 1);
});

test('each out-of-range rotation input is refused by name, and the button stays alive', async ({ page }) => {
  test.setTimeout(240_000);

  for (const [selector, value, valid, message] of [
    ['#canaryPercent', '99', '10', 'Canary percent must be between 1 and 20.'],
    ['#monitorHours', '999', '24', 'Monitoring hours must be between 1 and 72.'],
    ['#rolloutStages', 'not-a-stage-list', '10,50,100', 'Rollout stages must include values between 1 and 100, for example: 10,50,100.'],
  ] as const) {
    await page.locator(selector).fill(value);
    await page.locator('button[data-action="run-rotation"]').click();

    // Named cause, on the alert channel, with nothing simulated.
    await expect(page.locator('.status-message')).toHaveText(message);
    await expect(page.locator('.status-message')).toHaveAttribute('role', 'alert');
    await expect(page.locator('#rotation .log-list li')).toHaveText(['No simulation run yet.']);
    // The control is not left dead: it is enabled and back to its idle label.
    await expect(page.locator('button[data-action="run-rotation"]')).toBeEnabled();
    await expect(page.locator('button[data-action="run-rotation"]')).toHaveText('Run Rotation');
    // The rejected value is still on screen, so the user can see what to fix.
    expect(await page.locator(selector).inputValue()).toBe(value);
    // Restore this field before testing the next one, so each refusal is
    // provoked by exactly one bad field rather than a leftover from the last.
    await page.locator(selector).fill(valid);
  }

  // After fixing every field the simulator runs normally — the refusals did not
  // wedge it.
  await page.locator('#canaryPercent').fill('10');
  await page.locator('#monitorHours').fill('1');
  await page.locator('#rolloutStages').fill('50,100');
  await runRotation(page);
  await expect(page.locator('.status-message')).toHaveText('Rotation completed with phase gates satisfied.');
  expect((await fleetMetrics(page)).Hybrid).toBe(100);
});

/* ------------------------------------------------------------------ *
 * 6. The in-browser self-test suite (README: "confirm none of the
 *    results are faked")
 * ------------------------------------------------------------------ */

test('the self-test suite runs every check and its headline matches the list', async ({ page }) => {
  test.setTimeout(120_000);

  await expect(page.locator('#verify .card h3')).toHaveText(/Run the suite/);
  await page.locator('button[data-action="run-verify"]').click();
  await expect(page.locator('#verify .checklist')).toBeVisible({ timeout: 90_000 });

  const items = page.locator('#verify .checklist li');
  const total = await items.count();
  expect(total).toBeGreaterThan(0);

  const marks = await items.locator('.check').allTextContents();
  const passed = marks.filter((mark) => mark.trim() === '[OK]').length;
  // The headline count is the list, counted — not a separate claim.
  await expect(page.locator('#verify .card h3')).toHaveText(`${passed}/${total} checks passed`);
  expect(marks).toHaveLength(total);
  // Every check the lab makes about its own cryptography must actually hold.
  expect(marks.filter((mark) => mark.trim() === '[FAIL]')).toEqual([]);
  expect(passed).toBe(total);

  // Each result is labelled in text, not by colour alone.
  for (const label of await items.locator('span:not(.check)').allTextContents()) {
    expect(label.trim().length).toBeGreaterThan(0);
  }

  // The suite is re-runnable — the button is not consumed by the first run.
  await expect(page.locator('button[data-action="run-verify"]')).toBeEnabled();
  await expect(page.locator('button[data-action="run-verify"]')).toHaveText('Run verification suite');
});

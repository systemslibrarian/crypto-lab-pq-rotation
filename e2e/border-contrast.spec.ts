import { expect, test } from '@playwright/test';

type Rgb = [number, number, number];

function luminance(color: Rgb): number {
  const channels = color.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(first: Rgb, second: Rgb): number {
  const lighter = Math.max(luminance(first), luminance(second));
  const darker = Math.min(luminance(first), luminance(second));
  return (lighter + 0.05) / (darker + 0.05);
}

test('dark form controls retain 3:1 boundary contrast', async ({ page }) => {
  await page.goto('.');
  const controls = page.locator('input:not([type="range"]), select');
  await expect(controls.first()).toBeVisible();

  for (const control of await controls.all()) {
    const colors = await control.evaluate((element) => {
      type Rgba = [number, number, number, number];
      const parse = (value: string): Rgba => {
        const values = value.match(/[\d.]+/g)?.map(Number) ?? [];
        return [values[0], values[1], values[2], values[3] ?? 1];
      };
      const composite = (front: Rgba, back: Rgba): Rgba => {
        const alpha = front[3] + back[3] * (1 - front[3]);
        return [
          (front[0] * front[3] + back[0] * back[3] * (1 - front[3])) / alpha,
          (front[1] * front[3] + back[1] * back[3] * (1 - front[3])) / alpha,
          (front[2] * front[3] + back[2] * back[3] * (1 - front[3])) / alpha,
          alpha,
        ];
      };

      const root = getComputedStyle(document.documentElement);
      const baseHex = root.getPropertyValue('--bg-1').trim().slice(1);
      let background: Rgba = [
        Number.parseInt(baseHex.slice(0, 2), 16),
        Number.parseInt(baseHex.slice(2, 4), 16),
        Number.parseInt(baseHex.slice(4, 6), 16),
        1,
      ];
      const layers: Rgba[] = [];
      for (let node: Element | null = element; node; node = node.parentElement) {
        layers.push(parse(getComputedStyle(node).backgroundColor));
      }
      for (const layer of layers.reverse()) background = composite(layer, background);

      const border = parse(getComputedStyle(element).borderTopColor);
      return { border: border.slice(0, 3) as Rgb, background: background.slice(0, 3) as Rgb };
    });
    expect(contrast(colors.border, colors.background)).toBeGreaterThanOrEqual(3);
  }
});

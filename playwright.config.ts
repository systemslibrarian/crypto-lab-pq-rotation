import { defineConfig } from '@playwright/test';

/**
 * Strict accessibility (axe-core) gate. Runs the built app under `vite preview`
 * on a unique port and scans it with a single headless Chromium project.
 */
const PORT = 4282;
const BASE = '/crypto-lab-pq-rotation/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    port: PORT,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});

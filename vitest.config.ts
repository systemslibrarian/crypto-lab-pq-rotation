import { defineConfig } from 'vitest/config';

// Node-environment unit tests for the real cryptographic primitives and the
// migration/rotation engines. The Playwright accessibility suite lives in
// `e2e/` and is intentionally excluded here so `npm test` never tries to drive
// a browser — that gate runs separately via `npm run test:a11y`.
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
});

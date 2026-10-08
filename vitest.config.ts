import { defineConfig } from 'vitest/config';

// Flow tests: the handstamp binary (built by globalSetup) against the dev Postgres.
export default defineConfig({
  test: {
    include: ['tests/*.test.ts', 'apps/*/src/**/*.test.ts', 'examples/*/src/**/*.test.ts'],
    // Browser tests need a built UI and Chromium: `pnpm e2e`.
    exclude: ['**/node_modules/**', 'tests/e2e/**'],
    globalSetup: ['tests/global-setup.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});

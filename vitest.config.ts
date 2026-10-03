import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/*.test.ts', 'apps/*/src/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    // Browser tests need a built UI and Chromium: `pnpm e2e`.
    exclude: ['**/node_modules/**', 'apps/*/test/e2e/**'],
  },
});

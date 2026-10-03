import { defineConfig } from 'vitest/config';

// Real Chromium with a virtual WebAuthn authenticator against the built UI. Run with `pnpm e2e`.
export default defineConfig({
  test: { include: ['apps/*/test/e2e/**/*.test.ts'], testTimeout: 60_000, hookTimeout: 60_000 },
});

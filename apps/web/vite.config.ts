import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const { version } = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url), 'utf8'),
);

// Served by the Fastify server: built files in production, middleware mode in development.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  define: { __HANDSTAMP_VERSION__: JSON.stringify(version) },
  build: { outDir: 'dist', assetsDir: 'assets', emptyOutDir: true },
});

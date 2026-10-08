// `pnpm dev`: the Rust server and the Vite dev server as one origin (docs/PLAN.md §1.2).
// Vite owns the public port and serves the UI with hot reload; protocol and API paths go to the
// Rust server, so cookies, WebAuthn and redirects behave as in production.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const root = fileURLToPath(new URL('..', import.meta.url));
if (existsSync(`${root}.env`)) process.loadEnvFile(`${root}.env`);

const port = Number(process.env.PORT || 3000);
const apiPort = Number(process.env.API_PORT || port + 1);
const origin = process.env.HANDSTAMP_ISSUER || `http://localhost:${port}`;
const backend = `http://127.0.0.1:${apiPort}`;

execFileSync('cargo', ['build', '--manifest-path', 'backend/Cargo.toml'], {
  cwd: root,
  stdio: 'inherit',
});

const server = spawn(`${root}backend/target/debug/handstamp`, ['serve'], {
  cwd: root,
  stdio: 'inherit',
  env: {
    ...process.env,
    HANDSTAMP_ISSUER: origin,
    HOST: '127.0.0.1',
    PORT: String(apiPort),
    // Server-rendered views (logout, errors) are drawn from Vite's index.html.
    HANDSTAMP_VITE_URL: `http://localhost:${port}`,
  },
});

// Everything the Rust server answers. The rest (the SPA, its assets, Vite itself) stays in Vite.
const toBackend = { target: backend, changeOrigin: false, xfwd: false };
const vite = await createServer({
  root: `${root}apps/web`,
  configFile: `${root}apps/web/vite.config.ts`,
  server: {
    port,
    strictPort: true,
    proxy: {
      '^/(\\.well-known|jwks|auth|token|me|session|api|console|upstream|healthz|readyz)(/|$|\\?)':
        toBackend,
      '^/interaction/[^/]+/.+': toBackend,
    },
  },
});

async function close(code = 0) {
  server.kill('SIGTERM');
  await vite.close();
  process.exit(code);
}
server.once('exit', (code) => void close(code ?? 1));
for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => void close());

await vite.listen();
vite.printUrls();

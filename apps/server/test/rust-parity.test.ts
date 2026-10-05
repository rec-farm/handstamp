import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { TEST_DATABASE_URL, freePort } from './harness.ts';

// The Rust spike (backend/) shares the database with this server: the same migrations, sealed
// keys and published metadata. Each runtime boots on a database the other one created.
// Needs `pnpm backend:build`; skipped without the binary.
const root = fileURLToPath(new URL('../../../', import.meta.url));
const rustBin = process.env.HANDSTAMP_RUST_BIN ?? `${root}backend/target/release/handstamp-server`;
const webDist = `${root}apps/web/dist`;
const SECRET_KEY = Buffer.alloc(32, 9).toString('base64');

type Runtime = 'node' | 'rust';
const children: ChildProcess[] = [];
const databases: string[] = [];

async function admin<T>(fn: (client: pg.Client) => Promise<T>) {
  const client = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

async function freshDatabase(name: string) {
  await admin(async (client) => {
    await client.query(`DROP DATABASE IF EXISTS ${name}`);
    await client.query(`CREATE DATABASE ${name}`);
  });
  databases.push(name);
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${name}`;
  return url.toString();
}

async function start(runtime: Runtime, databaseUrl: string) {
  const port = await freePort();
  const env = {
    PATH: process.env.PATH,
    NODE_ENV: 'production',
    HOST: '127.0.0.1',
    PORT: String(port),
    HANDSTAMP_ISSUER: 'http://localhost:3990',
    DATABASE_URL: databaseUrl,
    HANDSTAMP_SECRET_KEY: SECRET_KEY,
    HANDSTAMP_WEB_DIST: webDist,
    LOG_LEVEL: 'error',
  };
  const child =
    runtime === 'rust'
      ? spawn(rustBin, [], { env, stdio: ['ignore', 'ignore', 'inherit'] })
      : spawn(process.execPath, ['--import', 'tsx', 'src/main.ts'], {
          cwd: `${root}apps/server`,
          env,
          stdio: ['ignore', 'ignore', 'inherit'],
        });
  children.push(child);
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 300; i++) {
    if (child.exitCode !== null) throw new Error(`${runtime} exited with ${child.exitCode}`);
    if (
      await fetch(`${base}/readyz`).then(
        (r) => r.ok,
        () => false,
      )
    )
      return base;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`${runtime} did not become ready`);
}

async function snapshot(base: string) {
  // Endpoint URLs follow the request's Host, so each runtime's own port is masked.
  const discovery = (
    await (await fetch(`${base}/.well-known/openid-configuration`)).text()
  ).replaceAll(base, 'BASE');
  const jwks = await (await fetch(`${base}/jwks`)).json();
  const setup = await fetch(`${base}/setup`);
  return {
    discovery: JSON.parse(discovery),
    jwks,
    csp: existsSync(webDist) ? setup.headers.get('content-security-policy') : 'no web build',
  };
}

afterAll(async () => {
  for (const child of children) child.kill('SIGTERM');
  await new Promise((resolve) => setTimeout(resolve, 300));
  await admin(async (client) => {
    for (const name of databases) await client.query(`DROP DATABASE IF EXISTS ${name}`);
  });
});

describe.skipIf(!existsSync(rustBin))('Rust spike parity', () => {
  for (const [first, second] of [
    ['rust', 'node'],
    ['node', 'rust'],
  ] as const) {
    it(`${second} runs on a database ${first} created`, async () => {
      const url = await freshDatabase(`hs_parity_${first}_first`);
      const a = await snapshot(await start(first, url));
      const b = await snapshot(await start(second, url));
      expect(b.jwks).toEqual(a.jwks);
      expect(a.jwks.keys).toHaveLength(1);
      expect(b.discovery).toEqual(a.discovery);
      expect(b.csp).toEqual(a.csp);
      const migrations = new pg.Client({ connectionString: url });
      await migrations.connect();
      const { rows } = await migrations.query(
        'SELECT count(*)::int AS n FROM handstamp_migrations',
      );
      await migrations.end();
      expect(rows[0].n).toBeGreaterThan(0);
    });
  }
});

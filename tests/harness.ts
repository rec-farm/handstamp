import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createServer as createHttpServer } from 'node:http';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import pg from 'pg';

// The server under test is the Rust binary (globalSetup builds it). HANDSTAMP_BIN overrides it.
export const BINARY =
  process.env.HANDSTAMP_BIN ??
  fileURLToPath(new URL('../backend/target/debug/handstamp', import.meta.url));
const WEB_DIST = fileURLToPath(new URL('../apps/web/dist/', import.meta.url));
const run = promisify(execFile);

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://handstamp:handstamp@127.0.0.1:5438/handstamp_test';

export const SECRETS = {
  RP_FIRST_SECRET: 'first-party-secret-0123456789abcdef0123',
  RP_THIRD_SECRET: 'third-party-secret-0123456789abcdef0123',
  RP_NOPKCE_SECRET: 'no-pkce-secret-0123456789abcdef01234567',
};

export const CLIENTS = [
  {
    clientId: 'rp-first',
    name: 'First Party',
    redirectUris: ['https://rp.example/cb'],
    postLogoutRedirectUris: ['https://rp.example/bye'],
    scopes: ['openid', 'profile', 'email', 'groups', 'offline_access'],
    firstParty: true,
    secretEnv: 'RP_FIRST_SECRET',
  },
  {
    clientId: 'rp-third',
    name: 'Third Party',
    redirectUris: ['https://third.example/cb'],
    scopes: ['openid', 'profile', 'email'],
    secretEnv: 'RP_THIRD_SECRET',
  },
  {
    clientId: 'rp-public',
    name: 'Public App',
    redirectUris: ['http://localhost:9999/cb'],
    tokenEndpointAuthMethod: 'none',
  },
  {
    clientId: 'rp-nopkce',
    name: 'Conformance Without PKCE',
    redirectUris: ['https://nopkce.example/cb'],
    requirePkce: false,
    secretEnv: 'RP_NOPKCE_SECRET',
  },
];

export async function freePort() {
  return new Promise<number>((resolve, reject) => {
    const server = createServer();
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as { port: number };
      server.close(() => resolve(port));
    });
    server.on('error', reject);
  });
}

// Each test file gets its own database so files can run in parallel.
async function resetDatabase(name: string) {
  const admin = new pg.Client({ connectionString: TEST_DATABASE_URL });
  await admin.connect();
  const database = `handstamp_test_${name}`;
  const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [database]);
  if (!exists.rowCount) await admin.query(`CREATE DATABASE ${database}`);
  await admin.end();
  const url = new URL(TEST_DATABASE_URL);
  url.pathname = `/${database}`;
  const client = new pg.Client({ connectionString: url.href });
  await client.connect();
  await client.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
  await client.end();
  return url.href;
}

export async function startTestServer(
  name: string,
  {
    env = {},
    clients = [],
    web = 'none',
    port: fixedPort,
  }: {
    env?: Record<string, string>;
    clients?: object[];
    web?: 'none' | 'static';
    port?: number; // when mocks need Handstamp's address before it starts
  } = {},
) {
  const databaseUrl = await resetDatabase(name);
  const port = fixedPort ?? (await freePort());
  const dir = mkdtempSync(join(tmpdir(), 'handstamp-test-'));
  const clientsFile = join(dir, 'clients.json');
  writeFileSync(clientsFile, JSON.stringify({ clients: [...CLIENTS, ...clients] }));
  const issuer = `http://localhost:${port}`;
  const serverEnv: Record<string, string> = {
    PATH: process.env.PATH ?? '',
    HANDSTAMP_ENV: 'test',
    DATABASE_URL: databaseUrl,
    HANDSTAMP_ISSUER: issuer,
    HANDSTAMP_SECRET_KEY: Buffer.alloc(32, 9).toString('base64'),
    HANDSTAMP_CLIENTS_FILE: clientsFile,
    HANDSTAMP_DEV_LOGIN: '1',
    HANDSTAMP_WEB_DIST: web === 'static' ? WEB_DIST : join(dir, 'no-ui'),
    HOST: '127.0.0.1',
    PORT: String(port),
    LOG_LEVEL: 'warn',
    ...SECRETS,
    ...env,
  };
  const processes: { kill(): void; exited: Promise<unknown> }[] = [];
  // Starts `handstamp serve` with this env on a port and waits until it answers /readyz.
  async function serve(env: Record<string, string>, listen: number) {
    const child = spawn(BINARY, ['serve'], {
      env: { ...env, PORT: String(listen) },
      stdio: ['ignore', 'ignore', 'inherit'],
    });
    const exited = new Promise<number | null>((resolve) => child.once('exit', resolve));
    processes.push({ kill: () => child.kill('SIGTERM'), exited });
    const origin = `http://localhost:${listen}`;
    for (let attempt = 0; ; attempt++) {
      if (child.exitCode !== null) throw new Error(`handstamp exited with ${child.exitCode}`);
      if (
        await fetch(`${origin}/readyz`).then(
          (r) => r.ok,
          () => false,
        )
      )
        break;
      if (attempt > 300) throw new Error('handstamp did not become ready');
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return origin;
  }
  await serve(serverEnv, port);
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 2 });
  // The operator CLI, against the same database (what `handstamp invite` and friends print).
  const cli = async (...args: string[]) => (await run(BINARY, args, { env: serverEnv })).stdout;
  return {
    issuer,
    async sql<T extends Record<string, unknown> = Record<string, unknown>>(
      text: string,
      values: unknown[] = [],
    ) {
      return (await pool.query(text, values)).rows as T[];
    },
    setup: {
      async issueCode() {
        return /Setup code \(60 minutes\): (\S+)/.exec(await cli('setup-code'))?.[1];
      },
    },
    enrollments: {
      async createInvite(_by?: unknown) {
        const link = /(http\S+#\S+)/.exec(await cli('invite'))![1];
        return { link, token: link.split('#')[1] };
      },
      async createRecovery(sub: string, { revokeOtherMethods }: { revokeOtherMethods: boolean }) {
        const out = await cli('recovery', sub, ...(revokeOtherMethods ? ['--revoke'] : []));
        const link = /(http\S+#\S+)/.exec(out)![1];
        return { link, token: link.split('#')[1] };
      },
    },
    keys: {
      async stage(_actor?: unknown) {
        return /Staged (\S+)\./.exec(await cli('keys', 'rotate'))![1];
      },
      async promote(_policy?: unknown, _actor?: unknown) {
        return /(\S+) is now signing/.exec(await cli('keys', 'promote'))?.[1];
      },
    },
    // A second process on the same database and issuer, as a second replica would be (R5).
    // Returns its own origin, to send requests to it directly.
    async replica() {
      return serve(serverEnv, await freePort());
    },
    // Every request reads the current key set from Postgres, so there is nothing to reload.
    async reloadKeys() {},
    async close() {
      for (const p of processes) p.kill();
      await Promise.all(processes.map((p) => p.exited));
      await pool.end();
    },
  };
}

type Cookie = { value: string; path: string };

// Just enough browser: path-scoped cookies, manual redirects, Origin on POSTs.
// A relying party's back-channel logout endpoint: records every logout_token POSTed to it, by path.
export async function backchannelReceiver() {
  const port = await freePort();
  const received: { path: string; token: string }[] = [];
  const server = createHttpServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      received.push({
        path: req.url ?? '',
        token: new URLSearchParams(body).get('logout_token') ?? '',
      });
      res.writeHead(200, { 'cache-control': 'no-store' }).end();
    });
  }).listen(port, '127.0.0.1');
  return {
    received,
    uri: (path: string) => `http://127.0.0.1:${port}${path}`,
    tokens: (path: string) => received.filter((r) => r.path === path).map((r) => r.token),
    close: () => server.close(),
  };
}

export class Browser {
  readonly cookies = new Map<string, Cookie>();

  constructor(readonly origin: string) {}

  #store(response: Response) {
    for (const line of response.headers.getSetCookie()) {
      const [pair, ...attributes] = line.split(';').map((part) => part.trim());
      const index = pair.indexOf('=');
      const name = pair.slice(0, index);
      const value = pair.slice(index + 1);
      const attr = (key: string) =>
        attributes.find((a) => a.toLowerCase().startsWith(`${key}=`))?.split('=')[1];
      const expired =
        attr('max-age') === '0' || (attr('expires') && new Date(attr('expires')!) < new Date());
      if (expired || value === '') this.cookies.delete(name);
      else this.cookies.set(name, { value, path: attr('path') ?? '/' });
    }
  }

  #cookieHeader(url: URL) {
    return [...this.cookies]
      .filter(
        ([, c]) =>
          url.pathname === c.path ||
          url.pathname.startsWith(c.path.endsWith('/') ? c.path : `${c.path}/`) ||
          c.path === '/',
      )
      .map(([name, c]) => `${name}=${c.value}`)
      .join('; ');
  }

  async request(target: string, init: RequestInit & { json?: unknown } = {}) {
    const url = new URL(target, this.origin);
    const headers = new Headers(init.headers);
    const cookie = this.#cookieHeader(url);
    if (cookie) headers.set('cookie', cookie);
    let body = init.body;
    if (init.json !== undefined) {
      headers.set('content-type', 'application/json');
      body = JSON.stringify(init.json);
    }
    if (init.method && init.method !== 'GET' && !headers.has('origin'))
      headers.set('origin', this.origin);
    const response = await fetch(url, { ...init, headers, body, redirect: 'manual' });
    this.#store(response);
    return response;
  }

  // Follows redirects that stay on the issuer; stops at the first one that leaves it.
  async follow(target: string) {
    let response = await this.request(target);
    for (let hop = 0; hop < 10 && [302, 303].includes(response.status); hop++) {
      const location = new URL(response.headers.get('location')!, this.origin);
      if (location.origin !== this.origin) return { response, location };
      response = await this.request(location.href);
    }
    return { response, location: undefined };
  }
}

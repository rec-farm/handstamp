import { join } from 'node:path';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import type Provider from 'oidc-provider';
import { sql } from 'drizzle-orm';
import cookie from '@fastify/cookie';
import { deriveKey, relyingParty } from '@handstamp/core';
import type { Database } from '@handstamp/db';
import type { Env } from './env.ts';
import type { ClientStore } from './clients.ts';
import type { KeyStore } from './keys.ts';
import { loggerOptions } from './log.ts';
import { createProvider } from './oidc/provider.ts';
import { applyRaw, baseHeaders, htmlCsp, type HeaderOptions } from './http/headers.ts';
import {
  createStaticShell,
  createViteShell,
  injectView,
  type ShellRenderer,
} from './http/shell.ts';
import { rateLimits } from './http/rate-limit.ts';
import { interactionRoutes } from './interaction/routes.ts';
import { consoleRoutes } from './console/routes.ts';
import { ConsoleCookies, consoleSecret } from './console/session.ts';
import { Enrollments } from './enrollment.ts';
import { SealedCookie } from './http/sealed-cookie.ts';
import { IdentityStore } from './identities.ts';
import { ProviderAdmin, ProviderStore } from './upstream/providers.ts';
import { adminRoutes } from './admin/routes.ts';
import { rotationPolicy } from './runtime.ts';
import { createUpstreamFlow, upstreamRoutes, type EnrollState } from './upstream/routes.ts';
import { PasskeyStore } from './passkeys.ts';
import { Sessions } from './sessions.ts';
import { Setup } from './setup.ts';

export type WebMode =
  { mode: 'static'; distDir: string } | { mode: 'vite'; root: string } | { mode: 'none' }; // tests: a bare shell that still carries the view data

export type AppDeps = {
  env: Env;
  db: Database;
  clients: ClientStore;
  keys: KeyStore;
  web: WebMode;
  testUserId?: string;
};

// Every path oidc-provider owns. Explicit, so a typo 404s instead of reaching the SPA.
export const OIDC_PATHS = [
  '/.well-known/openid-configuration',
  '/jwks',
  '/auth',
  '/auth/:uid',
  '/token',
  '/me',
  '/token/revocation',
  '/token/introspection',
  '/session/end',
  '/session/end/confirm',
  '/session/end/success',
];

// SPA routes that return index.html. Everything else under these prefixes is a 404.
export const UI_PATHS = [
  '/',
  '/interaction/:uid',
  '/setup',
  '/account',
  '/error',
  '/logout',
  '/signed-out',
  '/enroll',
  '/admin',
  '/admin/*',
];

const bareShell: ShellRenderer = {
  render: async (_url, view) =>
    injectView('<!doctype html><html lang="en"><body></body></html>', view),
  scriptHashes: () => [],
};

export async function buildApp(deps: AppDeps) {
  const { env } = deps;
  const app: FastifyInstance = Fastify({
    logger: loggerOptions(env.LOG_LEVEL),
    // Fastify accepts a hop count at runtime; its types only list the other forms.
    trustProxy: env.trustProxy as boolean | string[],
    // Long enough for consent and WebAuthn payloads, small enough to refuse junk.
    bodyLimit: 64 * 1024,
  });

  // ── web shell (prod: built files · dev: Vite in middleware mode · tests: bare) ──
  let shell = bareShell;
  if (deps.web.mode === 'static') {
    shell = await createStaticShell(join(deps.web.distDir, 'index.html'));
    await app.register((await import('@fastify/static')).default, {
      root: join(deps.web.distDir, 'assets'),
      prefix: '/assets/',
      immutable: true,
      maxAge: '365d',
      index: false,
    });
  } else if (deps.web.mode === 'vite') {
    const { createServer } = await import('vite');
    const vite = await createServer({
      root: deps.web.root,
      configFile: join(deps.web.root, 'vite.config.ts'),
      server: { middlewareMode: true, hmr: { server: app.server } },
      appType: 'custom',
    });
    await app.register((await import('@fastify/middie')).default);
    app.use(vite.middlewares);
    app.addHook('onClose', () => vite.close());
    shell = createViteShell(vite, join(deps.web.root, 'index.html'));
  }

  const headerOptions: HeaderOptions = {
    https: env.HANDSTAMP_ISSUER.protocol === 'https:',
    scriptHashes: shell.scriptHashes(),
    dev: deps.web.mode === 'vite',
  };
  const csp = htmlCsp(headerOptions);
  // Set on the raw response so it also covers replies oidc-provider writes itself.
  app.addHook('onRequest', async (_req, reply) => {
    applyRaw(reply.raw, baseHeaders(headerOptions));
    if (csp) reply.raw.setHeader('content-security-policy', csp);
  });

  await app.register(rateLimit, { global: false });
  await app.register(cookie);
  const limits = rateLimits(env.RATE_LIMIT_SCALE);
  const csrfKey = deriveKey(env.secretKey, 'csrf');
  const rp = relyingParty(env.HANDSTAMP_ISSUER, env.HANDSTAMP_INSTANCE_NAME);
  const passkeys = new PasskeyStore(deps.db);
  const setup = new Setup(deps.db, passkeys);

  // ── oidc-provider, swappable when signing keys change ──
  async function makeProvider() {
    return createProvider({
      env,
      db: deps.db,
      clients: deps.clients,
      jwks: await deps.keys.providerJwks(),
      cookieKeys: await deps.keys.cookieSecrets(),
      shell,
    });
  }
  let provider: Provider = await makeProvider();
  let handler = provider.callback();
  let jwksFingerprint = (await deps.keys.providerJwks()).fingerprint;

  provider.on('server_error', (_ctx, error) =>
    app.log.error({ err: error }, 'oidc-provider error'),
  );
  provider.on('backchannel.error', (_ctx, error, client) =>
    app.log.warn({ err: error, clientId: client.clientId }, 'back-channel logout failed'),
  );

  // Rebuilds the provider when the published key set changed. All provider state lives in
  // Postgres, so swapping instances drops nothing.
  async function reloadKeys(force = false) {
    const { fingerprint } = await deps.keys.providerJwks();
    if (!force && fingerprint === jwksFingerprint) return false;
    const next = await makeProvider();
    next.on('server_error', (_ctx, error) => app.log.error({ err: error }, 'oidc-provider error'));
    provider = next;
    handler = next.callback();
    jwksFingerprint = fingerprint;
    app.log.info({ keys: fingerprint }, 'signing keys reloaded');
    return true;
  }

  await app.register(async (scope) => {
    // oidc-provider parses its own bodies: leave the stream untouched.
    scope.removeAllContentTypeParsers();
    scope.addContentTypeParser('*', (_req, _payload, done) => done(null));
    for (const path of OIDC_PATHS) {
      const rateLimit =
        path === '/token'
          ? limits.token
          : path.startsWith('/auth')
            ? limits.authorization
            : undefined;
      scope.all(path, { config: rateLimit ? { rateLimit } : {} }, (req, reply) => {
        reply.hijack();
        handler(req.raw, reply.raw);
      });
    }
  });

  const sessions = new Sessions(deps.db, () => provider, app.log);
  const providers = new ProviderStore(deps.db, env.secretKey);
  const identities = new IdentityStore(deps.db);
  const enrollments = new Enrollments(deps.db, env.HANDSTAMP_ISSUER);
  const enrollCookie = new SealedCookie<EnrollState>(
    env.secretKey,
    env.HANDSTAMP_ISSUER,
    'hs_enroll',
    15 * 60,
  );
  const flow = createUpstreamFlow({
    issuer: env.HANDSTAMP_ISSUER,
    secretKey: env.secretKey,
    providers,
  });
  const consoleCookies = new ConsoleCookies(env.secretKey, env.HANDSTAMP_ISSUER);
  // The signed-in console session, if its SSO session still exists.
  const consoleSession = async (req: FastifyRequest) => {
    const session = consoleCookies.readSession(req);
    return session && (await sessions.exists(session.sub, session.uid)) ? session : undefined;
  };

  await app.register(interactionRoutes, {
    provider: () => provider,
    db: deps.db,
    issuer: env.HANDSTAMP_ISSUER,
    instanceName: env.HANDSTAMP_INSTANCE_NAME,
    csrfKey,
    testUserId: deps.testUserId,
    conformance: env.HANDSTAMP_CONFORMANCE_MODE,
    limits,
    rp,
    passkeys,
    setup,
    providers,
    enrollments,
    enrollCookie,
    sessions,
  });

  await app.register(upstreamRoutes, {
    provider: () => provider,
    db: deps.db,
    issuer: env.HANDSTAMP_ISSUER,
    secretKey: env.secretKey,
    providers,
    identities,
    enrollments,
    enrollCookie,
    sessions,
    limits,
    consoleSession,
    flow,
  });

  await app.register(adminRoutes, {
    db: deps.db,
    issuer: env.HANDSTAMP_ISSUER,
    secretKey: env.secretKey,
    csrfKey,
    sessions,
    passkeys,
    clients: deps.clients,
    providers: new ProviderAdmin(deps.db, env.secretKey),
    identities,
    enrollments,
    keys: deps.keys,
    rotation: rotationPolicy(env),
    reloadKeys: () => reloadKeys(true),
  });

  await app.register(consoleRoutes, {
    db: deps.db,
    issuer: env.HANDSTAMP_ISSUER,
    instanceName: env.HANDSTAMP_INSTANCE_NAME,
    secret: consoleSecret(env.secretKey),
    secretKey: env.secretKey,
    csrfKey,
    rp,
    passkeys,
    sessions,
    limits,
    identities,
    providers,
    flow,
  });

  // In conformance mode the interaction page is the plain form registered above.
  const uiPaths = env.HANDSTAMP_CONFORMANCE_MODE
    ? UI_PATHS.filter((p) => p !== '/interaction/:uid')
    : UI_PATHS;
  for (const path of uiPaths)
    app.get(path, async (req, reply) => {
      reply.header('cache-control', 'no-store').type('text/html; charset=utf-8');
      return shell.render(req.url);
    });

  app.get('/healthz', async () => ({ ok: true }));
  app.get('/readyz', async (_req, reply) => {
    try {
      await deps.db.execute(sql`select 1`);
      return { ok: true };
    } catch {
      return reply.code(503).send({ ok: false });
    }
  });

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: 'not_found' }));

  return {
    app,
    reloadKeys,
    provider: () => provider,
    sessions,
    setup,
    passkeys,
    identities,
    enrollments,
    providers,
  };
}

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as oidc from 'openid-client';
import { decodeJwt, decodeProtectedHeader } from './jwt.ts';
import { Browser, SECRETS, startTestServer } from './harness.ts';

let server: Awaited<ReturnType<typeof startTestServer>>;

beforeAll(async () => {
  server = await startTestServer('oidc');
});
afterAll(async () => {
  await server?.close();
});

async function relyingParty(clientId: string, secret?: string) {
  return oidc.discovery(
    new URL(server.issuer),
    clientId,
    secret,
    secret ? oidc.ClientSecretBasic(secret) : oidc.None(),
    { execute: [oidc.allowInsecureRequests] },
  );
}

// Runs the browser part of a sign-in: /auth → interaction → dev login → (consent) → RP callback.
async function signIn(
  browser: Browser,
  config: oidc.Configuration,
  params: Record<string, string>,
  { consent = false } = {},
) {
  const authUrl = oidc.buildAuthorizationUrl(config, params);
  const { response } = await browser.follow(authUrl.href);
  expect(response.status).toBe(200); // the sign-in page
  const uid = browser.cookies.get('hs_interaction')?.value;
  expect(uid).toBeTruthy();
  let details = await (await browser.request(`/interaction/${uid}/details`)).json();
  let landed: URL | undefined;
  if (details.prompt.name === 'login') {
    const login = await browser.request(`/interaction/${uid}/dev-login`, {
      method: 'POST',
      json: {},
      headers: { 'x-handstamp-csrf': details.csrf },
    });
    expect(login.status).toBe(200);
    landed = (await browser.follow((await login.json()).redirectTo)).location;
  }
  if (!landed && consent) {
    const nextUid = browser.cookies.get('hs_interaction')!.value;
    details = await (await browser.request(`/interaction/${nextUid}/details`)).json();
    expect(details.prompt.name).toBe('consent');
    const approved = await browser.request(`/interaction/${nextUid}/consent`, {
      method: 'POST',
      json: {},
      headers: { 'x-handstamp-csrf': details.csrf },
    });
    expect(approved.status).toBe(200);
    landed = (await browser.follow((await approved.json()).redirectTo)).location;
  }
  expect(landed, 'sign-in should end at the relying party').toBeDefined();
  return landed!;
}

const REDIRECTS: Record<string, string> = {
  'rp-first': 'https://rp.example/cb',
  'rp-third': 'https://third.example/cb',
  'rp-public': 'http://localhost:9999/cb',
};

async function codeFlow(clientId: string, secret: string | undefined, scope: string, options = {}) {
  const config = await relyingParty(clientId, secret);
  const browser = new Browser(server.issuer);
  const verifier = oidc.randomPKCECodeVerifier();
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const callback = await signIn(
    browser,
    config,
    {
      redirect_uri: REDIRECTS[clientId],
      scope,
      state,
      nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
    },
    options,
  );
  const tokens = await oidc.authorizationCodeGrant(config, callback, {
    pkceCodeVerifier: verifier,
    expectedState: state,
    expectedNonce: nonce,
  });
  return { config, browser, tokens, callback };
}

describe('discovery', () => {
  it('advertises a code-only, PKCE-S256, RS256 provider', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const meta = config.serverMetadata();
    expect(meta.issuer).toBe(server.issuer);
    expect(meta.response_types_supported).toEqual(['code']);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.id_token_signing_alg_values_supported).toEqual(['RS256']);
    expect(meta.scopes_supported).toEqual(
      expect.arrayContaining(['openid', 'groups', 'offline_access']),
    );
    expect(meta.end_session_endpoint).toBe(`${server.issuer}/session/end`);
    expect(meta.backchannel_logout_supported).toBe(true);
  });
});

describe('authorization code flow', () => {
  it('signs a first-party client in without consent; groups in the ID token, email in userinfo', async () => {
    const { tokens, config } = await codeFlow(
      'rp-first',
      SECRETS.RP_FIRST_SECRET,
      'openid profile email groups',
    );
    const claims = tokens.claims()!;
    expect(claims.iss).toBe(server.issuer);
    expect(claims.groups).toEqual([]);
    expect(claims.email).toBeUndefined(); // scope=email means userinfo access (OIDC Core 5.4)
    expect(tokens.refresh_token).toBeTruthy(); // session-bound: the client may refresh
    const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
    expect(userinfo.name).toBe('Test User');
    expect(userinfo.email).toBe('test@handstamp.test');
    expect(userinfo.email_verified).toBe(true);
    expect(userinfo.groups).toEqual([]);
  });

  it('asks a third-party client for consent first', async () => {
    const { tokens, config } = await codeFlow('rp-third', SECRETS.RP_THIRD_SECRET, 'openid email', {
      consent: true,
    });
    const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, tokens.claims()!.sub);
    expect(userinfo.email).toBe('test@handstamp.test');
    expect(tokens.claims()!.groups).toBeUndefined(); // groups scope not requested
    expect(tokens.refresh_token).toBeUndefined(); // not allowed offline_access, so no refresh grant
  });

  it('supports public clients with PKCE', async () => {
    const { tokens } = await codeFlow('rp-public', undefined, 'openid', { consent: true });
    expect(tokens.claims()!.sub).toBeTruthy();
  });

  it('refuses an authorization request without PKCE', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: 'https://rp.example/cb',
      scope: 'openid',
      state: 's',
    });
    const response = await new Browser(server.issuer).request(url.href);
    const location = new URL(response.headers.get('location')!);
    expect(location.origin).toBe('https://rp.example');
    expect(location.searchParams.get('error')).toBe('invalid_request');
    expect(location.searchParams.get('error_description')).toMatch(/PKCE/);
  });

  it('lets a client that opted out of PKCE sign in without it', async () => {
    const config = await relyingParty('rp-nopkce', SECRETS.RP_NOPKCE_SECRET);
    const browser = new Browser(server.issuer);
    const state = oidc.randomState();
    const callback = await signIn(
      browser,
      config,
      { redirect_uri: 'https://nopkce.example/cb', scope: 'openid', state },
      { consent: true },
    );
    const tokens = await oidc.authorizationCodeGrant(config, callback, { expectedState: state });
    expect(tokens.access_token).toBeTruthy();
  });

  it('refuses a redirect_uri that is not an exact match', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: 'https://rp.example/cb/../evil',
      scope: 'openid',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
    });
    const response = await new Browser(server.issuer).request(url.href);
    expect(response.status).toBe(400); // rendered error page, never a redirect
    expect(response.headers.get('location')).toBeNull();
  });

  it('refuses a code that is used twice', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const browser = new Browser(server.issuer);
    const verifier = oidc.randomPKCECodeVerifier();
    const callback = await signIn(browser, config, {
      redirect_uri: 'https://rp.example/cb',
      scope: 'openid',
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
    });
    await oidc.authorizationCodeGrant(config, callback, {
      pkceCodeVerifier: verifier,
      idTokenExpected: true,
    });
    await expect(
      oidc.authorizationCodeGrant(config, callback, { pkceCodeVerifier: verifier }),
    ).rejects.toMatchObject({ error: 'invalid_grant' });
  });
});

describe('refresh tokens', () => {
  it('rotates on every use and revokes the grant when an old one is replayed', async () => {
    // offline_access without prompt=consent is dropped (OIDC Core §11), so this one is session-bound.
    const { config, tokens } = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    const first = tokens.refresh_token!;
    expect(first).toBeTruthy();
    const rotated = await oidc.refreshTokenGrant(config, first);
    expect(rotated.refresh_token).toBeTruthy();
    expect(rotated.refresh_token).not.toBe(first);

    await expect(oidc.refreshTokenGrant(config, first)).rejects.toThrow();
    // The replay killed the whole grant, including the token that was still valid.
    await expect(oidc.refreshTokenGrant(config, rotated.refresh_token!)).rejects.toThrow();
  });
});

describe('interaction API', () => {
  it('rejects a cross-origin POST even with a valid token', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const browser = new Browser(server.issuer);
    await browser.follow(
      oidc.buildAuthorizationUrl(config, {
        redirect_uri: 'https://rp.example/cb',
        scope: 'openid',
        code_challenge: 'x'.repeat(43),
        code_challenge_method: 'S256',
      }).href,
    );
    const uid = browser.cookies.get('hs_interaction')!.value;
    const { csrf } = await (await browser.request(`/interaction/${uid}/details`)).json();
    const forged = await browser.request(`/interaction/${uid}/dev-login`, {
      method: 'POST',
      json: {},
      headers: { origin: 'https://evil.example', 'x-handstamp-csrf': csrf },
    });
    expect(forged.status).toBe(403);
    const noToken = await browser.request(`/interaction/${uid}/dev-login`, {
      method: 'POST',
      json: {},
    });
    expect(noToken.status).toBe(403);
  });

  it('refuses an interaction uid that does not match the browser cookie', async () => {
    const response = await new Browser(server.issuer).request('/interaction/not-mine/details');
    expect(response.status).toBe(410);
  });
});

describe('logout', () => {
  it('shows the confirm view and redirects to the registered post-logout URI', async () => {
    const { tokens, browser } = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const endSession = oidc.buildEndSessionUrl(config, {
      id_token_hint: tokens.id_token!,
      post_logout_redirect_uri: 'https://rp.example/bye',
      state: 'bye-state',
    });
    const confirm = await browser.request(endSession.href);
    expect(confirm.status).toBe(200);
    const html = await confirm.text();
    expect(html).toContain('data-hs-view="logout"');
    expect(html).toContain('data-hs-client="First Party"');
    const xsrf = /data-hs-xsrf="([^"]+)"/.exec(html)![1];
    const done = await browser.request('/session/end/confirm', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ xsrf, logout: 'yes' }).toString(),
    });
    expect(done.status).toBe(303);
    const location = new URL(done.headers.get('location')!);
    expect(location.origin + location.pathname).toBe('https://rp.example/bye');
    expect(location.searchParams.get('state')).toBe('bye-state');
    expect(browser.cookies.has('hs_session')).toBe(false);
    // The refresh token was bound to that session, so it died with it.
    await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({
      error: 'invalid_grant',
    });
  });

  it('refuses an unregistered post-logout redirect', async () => {
    const { tokens, browser } = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const response = await browser.request(
      oidc.buildEndSessionUrl(config, {
        id_token_hint: tokens.id_token!,
        post_logout_redirect_uri: 'https://evil.example/',
      }).href,
      { headers: { accept: 'text/html' } },
    );
    expect(response.status).toBe(400);
    expect(await response.text()).toContain('data-hs-view="error"');
  });
});

describe('signing key rotation', () => {
  it('publishes a staged key without signing with it, then switches without breaking sessions', async () => {
    const before = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    const oldKid = decodeProtectedHeader(before.tokens.id_token!).kid;

    const staged = await server.keys.stage('cli');
    await server.reloadKeys();
    const jwks = await (await fetch(`${server.issuer}/jwks`)).json();
    expect(jwks.keys.map((k: { kid: string }) => k.kid)).toEqual(
      expect.arrayContaining([oldKid, staged]),
    );
    expect(jwks.keys.every((k: Record<string, unknown>) => !('d' in k))).toBe(true);

    const stillOld = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    expect(decodeProtectedHeader(stillOld.tokens.id_token!).kid).toBe(oldKid);

    await server.keys.promote(
      { stageHours: 24, rotationDays: 90, retireAfterSeconds: 3600 },
      'cli',
    );
    await server.reloadKeys();
    const after = await codeFlow('rp-first', SECRETS.RP_FIRST_SECRET, 'openid');
    expect(decodeProtectedHeader(after.tokens.id_token!).kid).toBe(staged);

    // The refresh token from before the rotation still works, and the old key is still published.
    const refreshed = await oidc.refreshTokenGrant(before.config, before.tokens.refresh_token!);
    expect(decodeJwt(refreshed.id_token!).sub).toBe(decodeJwt(before.tokens.id_token!).sub);
    const published = await (await fetch(`${server.issuer}/jwks`)).json();
    expect(published.keys.map((k: { kid: string }) => k.kid)).toContain(oldKid);
  });
});

describe('headers', () => {
  it('sets security headers on protocol responses too', async () => {
    const response = await fetch(`${server.issuer}/.well-known/openid-configuration`);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('marks session cookies HttpOnly and SameSite=Lax', async () => {
    const config = await relyingParty('rp-first', SECRETS.RP_FIRST_SECRET);
    const response = await fetch(
      oidc.buildAuthorizationUrl(config, {
        redirect_uri: 'https://rp.example/cb',
        scope: 'openid',
        code_challenge: 'x'.repeat(43),
        code_challenge_method: 'S256',
      }),
      { redirect: 'manual' },
    );
    const cookies = response.headers.getSetCookie().filter((c) => !c.includes('.sig='));
    expect(cookies.length).toBeGreaterThan(0);
    for (const cookie of cookies) {
      expect(cookie.toLowerCase()).toContain('httponly');
      expect(cookie.toLowerCase()).toContain('samesite=lax');
    }
  });
});

// Last on purpose: it uses up this IP's budget for the details route.
describe('rate limits', () => {
  it('slows down a client that hammers the sign-in API', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 35; i++)
      statuses.push((await fetch(`${server.issuer}/interaction/nope/details`)).status);
    expect(statuses).toContain(429);
    const limited = await fetch(`${server.issuer}/interaction/nope/details`);
    expect(await limited.json()).toMatchObject({ error: 'rate_limited' });
  });
});

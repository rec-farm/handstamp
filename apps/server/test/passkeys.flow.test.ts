import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import * as oidc from 'openid-client';
import { SoftAuthenticator } from './authenticator.ts';
import { Browser, freePort, SECRETS, startTestServer } from './harness.ts';
import { decodeJwt } from './jwt.ts';

let server: Awaited<ReturnType<typeof startTestServer>>;
let backchannel: Server;
const logoutTokens: string[] = [];
let authenticator: SoftAuthenticator;
let admin: Browser;

beforeAll(async () => {
  // A relying party with a back-channel logout endpoint, to see "sign out everywhere" reach apps.
  const port = await freePort();
  backchannel = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => {
      logoutTokens.push(new URLSearchParams(body).get('logout_token') ?? '');
      res.writeHead(200).end();
    });
  }).listen(port, '127.0.0.1');
  server = await startTestServer('passkeys', {
    env: { HANDSTAMP_DEV_LOGIN: '0', ALLOW_PRIVATE_NETWORKS: '1' },
    clients: [
      {
        clientId: 'rp-bcl',
        name: 'Back-channel App',
        redirectUris: ['https://bcl.example/cb'],
        scopes: ['openid', 'offline_access'],
        firstParty: true,
        backchannelLogoutUri: `http://127.0.0.1:${port}/logout`,
        secretEnv: 'RP_FIRST_SECRET',
      },
    ],
  });
  authenticator = new SoftAuthenticator(server.issuer);
});

afterAll(async () => {
  backchannel?.close();
  await server?.close();
});

async function interactionOf(browser: Browser, start: string) {
  const { response, location } = await browser.follow(start);
  expect(location, 'should stop at the sign-in page').toBeUndefined();
  expect(response.status).toBe(200);
  const uid = browser.cookies.get('hs_interaction')!.value;
  const details = await (await browser.request(`/interaction/${uid}/details`)).json();
  const post = (path: string, json: unknown = {}) =>
    browser.request(`/interaction/${uid}/${path}`, {
      method: 'POST',
      json,
      headers: { 'x-handstamp-csrf': details.csrf },
    });
  return { uid, details, post };
}

async function passkeySignIn(browser: Browser, start: string, auth = authenticator) {
  const { post } = await interactionOf(browser, start);
  const options = await (await post('passkey/options')).json();
  return post('passkey/verify', { response: auth.get(options) });
}

async function api(browser: Browser, path: string, init: { method?: string; json?: unknown } = {}) {
  const me = await (await browser.request('/api/me')).json();
  return browser.request(path, {
    method: init.method ?? 'GET',
    ...(init.json !== undefined ? { json: init.json } : {}),
    headers: { 'x-handstamp-csrf': me.csrf ?? '' },
  });
}

function rp() {
  return oidc.discovery(
    new URL(server.issuer),
    'rp-bcl',
    SECRETS.RP_FIRST_SECRET,
    oidc.ClientSecretBasic(SECRETS.RP_FIRST_SECRET),
    { execute: [oidc.allowInsecureRequests] },
  );
}

async function rpSignIn(browser: Browser) {
  const config = await rp();
  const verifier = oidc.randomPKCECodeVerifier();
  const start = oidc.buildAuthorizationUrl(config, {
    redirect_uri: 'https://bcl.example/cb',
    scope: 'openid',
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  }).href;
  const { location } = await browser.follow(start);
  let callback = location;
  if (!callback) {
    const signedIn = await passkeySignIn(browser, start);
    expect(signedIn.status).toBe(200);
    callback = (await browser.follow((await signedIn.json()).redirectTo)).location;
  }
  const tokens = await oidc.authorizationCodeGrant(config, callback!, {
    pkceCodeVerifier: verifier,
  });
  return { config, tokens };
}

describe('first-run setup', () => {
  let code: string;

  it('starts unclaimed, and / sends the console sign-in into claim mode', async () => {
    expect(await (await fetch(`${server.issuer}/api/instance`)).json()).toMatchObject({
      claimed: false,
    });
    code = (await server.setup.issueCode())!;
    const { details } = await interactionOf(new Browser(server.issuer), '/console/login');
    expect(details.mode).toBe('claim');
    expect(details.client.clientId).toBe('handstamp-console');
  });

  it('refuses a wrong code and a passkey before the code', async () => {
    const { post } = await interactionOf(new Browser(server.issuer), '/console/login');
    expect((await post('setup/verify', { code: 'HS-00000-00000-00000-00000' })).status).toBe(400);
    expect((await post('setup/passkey/options', { displayName: 'Mallory' })).status).toBe(403);
  });

  it('claims the instance with the code and a passkey, and lands signed in on /account', async () => {
    admin = new Browser(server.issuer);
    const { post } = await interactionOf(admin, '/console/login');
    expect((await post('setup/verify', { code: code.toLowerCase() })).status).toBe(200);
    const options = await (
      await post('setup/passkey/options', { displayName: 'Rec Admin', email: 'admin@example.com' })
    ).json();
    expect(options.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    });
    const claimed = await post('setup/passkey/verify', {
      response: authenticator.create(options),
      name: 'Test key',
    });
    expect(claimed.status).toBe(200);
    const { response } = await admin.follow((await claimed.json()).redirectTo);
    expect(response.status).toBe(200);
    expect(new URL(response.url).pathname).toBe('/account');

    const me = await (await admin.request('/api/me')).json();
    expect(me.user).toMatchObject({
      displayName: 'Rec Admin',
      isAdmin: true,
      email: 'admin@example.com',
    });
    expect(me.session.recentlyAuthenticated).toBe(true);
  });

  it('cannot be claimed twice', async () => {
    expect(await server.setup.issueCode()).toBeUndefined();
    const { details, post } = await interactionOf(new Browser(server.issuer), '/console/login');
    expect(details.mode).toBe('sign-in');
    expect((await post('setup/verify', { code })).status).toBe(409);
  });
});

describe('passkey sign-in', () => {
  it('signs into an app with the passkey and says so in amr', async () => {
    const { tokens } = await rpSignIn(new Browser(server.issuer));
    expect(tokens.claims()!.amr).toEqual(['pop', 'user', 'mfa']);
  });

  it('refuses a passkey this instance has never seen', async () => {
    const stranger = new SoftAuthenticator(server.issuer);
    stranger.create({ challenge: 'x', user: { id: 'x' } });
    const response = await passkeySignIn(new Browser(server.issuer), '/console/login', stranger);
    expect(response.status).toBe(401);
    expect((await response.json()).error).toBe('unknown_passkey');
  });

  it('refuses an assertion made for another origin (phishing)', async () => {
    // Same passkey, but the browser reports the phishing site's origin.
    const phished = new SoftAuthenticator('https://handstamp-login.evil', authenticator.rpId);
    phished.credentials.push(...authenticator.credentials);
    const response = await passkeySignIn(new Browser(server.issuer), '/console/login', phished);
    expect(response.status).toBe(401);
    expect((await response.json()).error).toBe('passkey_invalid');
  });

  it('refuses a counter that goes backwards (cloned authenticator)', async () => {
    authenticator.credentials[0].counter = 0;
    const response = await passkeySignIn(new Browser(server.issuer), '/console/login');
    expect(response.status).toBe(401);
    authenticator.credentials[0].counter = 1000; // back in step for the rest of the file
  });

  it('never accepts the same challenge twice', async () => {
    const { post } = await interactionOf(new Browser(server.issuer), '/console/login');
    const options = await (await post('passkey/options')).json();
    const assertion = authenticator.get(options);
    expect((await post('passkey/verify', { response: assertion })).status).toBe(200);
    // Same browser, new interaction: the old challenge is gone.
    const again = await interactionOf(new Browser(server.issuer), '/console/login');
    expect((await again.post('passkey/verify', { response: assertion })).status).toBe(400);
  });
});

describe('account API', () => {
  it('requires a signed-in console session', async () => {
    expect((await fetch(`${server.issuer}/api/me`)).status).toBe(401);
  });

  it('refuses writes without the CSRF token or from another origin', async () => {
    const [passkey] = await (await admin.request('/api/me/passkeys')).json();
    const noToken = await admin.request(`/api/me/passkeys/${passkey.id}`, {
      method: 'PATCH',
      json: { name: 'x' },
    });
    expect(noToken.status).toBe(403);
    const me = await (await admin.request('/api/me')).json();
    const crossSite = await admin.request(`/api/me/passkeys/${passkey.id}`, {
      method: 'PATCH',
      json: { name: 'x' },
      headers: { origin: 'https://evil.example', 'x-handstamp-csrf': me.csrf },
    });
    expect(crossSite.status).toBe(403);
  });

  it("won't remove your only passkey", async () => {
    const [passkey] = await (await admin.request('/api/me/passkeys')).json();
    const response = await api(admin, `/api/me/passkeys/${passkey.id}`, { method: 'DELETE' });
    expect(response.status).toBe(409);
    expect((await response.json()).error).toBe('last_method');
  });

  it('adds a second passkey, renames it, then removes the first', async () => {
    const options = await (
      await api(admin, '/api/me/passkeys/options', { method: 'POST', json: {} })
    ).json();
    const added = await api(admin, '/api/me/passkeys', {
      method: 'POST',
      json: { response: authenticator.create(options), name: '  Backup   key ' },
    });
    expect(added.status).toBe(201);
    const list = await (await admin.request('/api/me/passkeys')).json();
    expect(list.map((p: { name: string }) => p.name)).toEqual(['Test key', 'Backup key']);
    expect(
      (
        await api(admin, `/api/me/passkeys/${list[1].id}`, {
          method: 'PATCH',
          json: { name: 'Laptop' },
        })
      ).status,
    ).toBe(200);
    expect((await api(admin, `/api/me/passkeys/${list[0].id}`, { method: 'DELETE' })).status).toBe(
      204,
    );
  });

  it('asks for a fresh sign-in before changing passkeys after 5 minutes (step-up)', async () => {
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 6 * 60 * 1000 });
    try {
      const response = await api(admin, '/api/me/passkeys/options', { method: 'POST', json: {} });
      expect(response.status).toBe(403);
      expect((await response.json()).error).toBe('step_up_required');
    } finally {
      vi.useRealTimers();
    }
  });

  it('lists sessions with the apps signed into them', async () => {
    const sessions = await (await admin.request('/api/me/sessions')).json();
    const current = sessions.find((s: { current: boolean }) => s.current);
    expect(current.method).toBe('passkey');
    expect(current.apps.map((a: { clientId: string }) => a.clientId)).toContain(
      'handstamp-console',
    );
  });
});

describe('sign out everywhere', () => {
  it('ends every session, revokes refresh tokens, and tells apps over the back channel', async () => {
    authenticator.credentials.shift(); // the first passkey was removed above
    const phone = new Browser(server.issuer);
    const { config, tokens } = await rpSignIn(phone);
    expect(tokens.refresh_token).toBeTruthy();
    const before = logoutTokens.length;

    const response = await api(admin, '/api/me/sign-out-everywhere', { method: 'POST', json: {} });
    expect(response.status).toBe(200);
    expect((await response.json()).ended).toBeGreaterThanOrEqual(2);

    expect((await admin.request('/api/me')).status).toBe(401);
    await expect(oidc.refreshTokenGrant(config, tokens.refresh_token!)).rejects.toMatchObject({
      error: 'invalid_grant',
    });
    await vi.waitFor(() => expect(logoutTokens.length).toBeGreaterThan(before), { timeout: 3000 });
    const logout = decodeJwt(logoutTokens.at(-1)!);
    expect(logout.events).toHaveProperty(['http://schemas.openid.net/event/backchannel-logout']);
    expect(logout.sid).toBeTruthy();
  });
});

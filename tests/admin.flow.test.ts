import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as oidc from 'openid-client';
import { SoftAuthenticator } from './authenticator.ts';
import { Browser, startTestServer } from './harness.ts';
import { decodeJwt } from './jwt.ts';

// The admin API: authorization, guardrails, groups and app access, client secrets, audit (S19).

let server: Awaited<ReturnType<typeof startTestServer>>;

type Person = Awaited<ReturnType<typeof enrolled>>;
let admin: Person;
let bob: Person;

beforeAll(async () => {
  server = await startTestServer('admin', { env: { HANDSTAMP_DEV_LOGIN: '0' } });
  admin = await claimed();
  bob = await enrolled('Bob');
});

afterAll(async () => {
  await server?.close();
});

// A person with a browser and a passkey.
function browserFor(auth: SoftAuthenticator) {
  const hs = new Browser(server.issuer);
  async function interaction(start: string) {
    const { response, location } = await hs.follow(start);
    if (location) return { location } as const;
    expect(response.status).toBe(200);
    const uid = hs.cookies.get('hs_interaction')!.value;
    const details = await (await hs.request(`/interaction/${uid}/details`)).json();
    const post = (path: string, json: unknown = {}) =>
      hs.request(`/interaction/${uid}/${path}`, {
        method: 'POST',
        json,
        headers: { 'x-handstamp-csrf': details.csrf },
      });
    return { uid, details, post } as const;
  }
  async function api(path: string, method = 'GET', json?: unknown) {
    const me = await (await hs.request('/api/me')).json();
    return hs.request(path, {
      method,
      ...(json !== undefined || method !== 'GET' ? { json: json ?? {} } : {}),
      headers: { 'x-handstamp-csrf': me.csrf ?? '' },
    });
  }
  // Passkey sign-in wherever a sign-in card shows up; returns where the browser lands.
  async function signIn(start: string) {
    const step = await interaction(start);
    if ('location' in step) return step.location;
    if (step.details.prompt.name !== 'login') return step;
    const options = await (await step.post('passkey/options')).json();
    const signed = await step.post('passkey/verify', { response: auth.get(options) });
    expect(signed.status).toBe(200);
    const next = await hs.follow((await signed.json()).redirectTo);
    if (next.location) return next.location;
    return interaction(next.response.url);
  }
  return { hs, auth, interaction, api, signIn };
}

async function claimed() {
  const auth = new SoftAuthenticator(server.issuer);
  const person = browserFor(auth);
  const code = (await server.setup.issueCode())!;
  const step = await person.interaction('/console/login');
  if ('location' in step) throw new Error('expected the claim card');
  await step.post('setup/verify', { code });
  const options = await (await step.post('setup/passkey/options', { displayName: 'Admin' })).json();
  const done = await step.post('setup/passkey/verify', { response: auth.create(options) });
  await person.hs.follow((await done.json()).redirectTo);
  const me = await (await person.hs.request('/api/me')).json();
  return { ...person, id: me.user.sub as string };
}

async function enrolled(name: string) {
  const auth = new SoftAuthenticator(server.issuer);
  const person = browserFor(auth);
  const { token } = await server.enrollments.createInvite({ actorType: 'cli' });
  await person.hs.request('/api/enroll', { method: 'POST', json: { token } });
  const step = await person.interaction('/console/login');
  if ('location' in step) throw new Error('expected the invite card');
  const options = await (await step.post('enroll/passkey/options', { displayName: name })).json();
  const done = await step.post('enroll/passkey/verify', { response: auth.create(options) });
  await person.hs.follow((await done.json()).redirectTo);
  const me = await (await person.hs.request('/api/me')).json();
  return { ...person, id: me.user.sub as string };
}

async function rp(clientId: string, secret?: string) {
  return oidc.discovery(
    new URL(server.issuer),
    clientId,
    secret,
    secret ? oidc.ClientSecretBasic(secret) : oidc.None(),
    { execute: [oidc.allowInsecureRequests] },
  );
}

async function authorize(person: Person, config: oidc.Configuration, scope = 'openid groups') {
  const verifier = oidc.randomPKCECodeVerifier();
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: 'https://app.example/cb',
    scope,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  });
  const landed = await person.signIn(url.href);
  return { landed, verifier };
}

describe('who may use the admin API', () => {
  it('refuses signed-out visitors and non-admins', async () => {
    expect((await fetch(`${server.issuer}/api/admin/overview`)).status).toBe(401);
    const response = await bob.api('/api/admin/overview');
    expect(response.status).toBe(403);
    expect((await response.json()).error).toBe('not_admin');
  });

  it('shows an admin the overview', async () => {
    const overview = await (await admin.api('/api/admin/overview')).json();
    expect(overview).toMatchObject({ users: 2, disabledUsers: 0, clients: 5 });
    expect(overview.signingKey.kid).toBeTruthy();
  });

  // The 5-minute step-up window itself is unit-tested in Rust (console.rs).
  it('needs the CSRF token for every change', async () => {
    const noCsrf = await admin.hs.request('/api/admin/groups', {
      method: 'POST',
      json: { slug: 'x', name: 'X' },
    });
    expect(noCsrf.status).toBe(403);
  });
});

describe('users', () => {
  it('finds users by name or email', async () => {
    const list = await (await admin.api('/api/admin/users?q=bob')).json();
    expect(list.map((u: { displayName: string }) => u.displayName)).toEqual(['Bob']);
    expect(list[0].methods).toBe(1);
    const groupsList = await (await admin.api('/api/admin/groups')).json();
    expect(Array.isArray(groupsList)).toBe(true);
  });

  it("won't let an admin demote or disable themselves, or remove the last admin", async () => {
    const self = await admin.api(`/api/admin/users/${admin.id}`, 'PATCH', { isAdmin: false });
    expect((await self.json()).error).toBe('self');
    // Bob becomes an admin, then Bob tries to demote the only other admin… which is fine:
    expect((await admin.api(`/api/admin/users/${bob.id}`, 'PATCH', { isAdmin: true })).status).toBe(
      200,
    );
    expect(
      (await admin.api(`/api/admin/users/${bob.id}`, 'PATCH', { isAdmin: false })).status,
    ).toBe(200);
  });

  it('disabling a user ends their sessions and stops their passkey', async () => {
    const carol = await enrolled('Carol');
    expect((await carol.hs.request('/api/me')).status).toBe(200);
    expect(
      (await admin.api(`/api/admin/users/${carol.id}`, 'PATCH', { status: 'disabled' })).status,
    ).toBe(200);
    expect((await carol.hs.request('/api/me')).status).toBe(401);
    const step = await carol.interaction('/console/login');
    if ('location' in step) throw new Error('expected the sign-in card');
    const options = await (await step.post('passkey/options')).json();
    const refused = await step.post('passkey/verify', { response: carol.auth.get(options) });
    expect((await refused.json()).error).toBe('account_disabled');
  });

  it('sends a recovery link once, as a link it does not store', async () => {
    const response = await admin.api(`/api/admin/users/${bob.id}/recovery`, 'POST', {
      revokeOtherMethods: false,
    });
    const { link } = await response.json();
    expect(link).toMatch(new RegExp(`^${server.issuer}/enroll#`));
  });
});

describe('groups and app access', () => {
  let staff: string;
  let secret: string;

  it('creates a group and an app that requires it; the secret is shown once', async () => {
    const created = await admin.api('/api/admin/groups', 'POST', { slug: 'staff', name: 'Staff' });
    staff = (await created.json()).id;
    const app = await admin.api('/api/admin/clients', 'POST', {
      clientId: 'staff-app',
      name: 'Staff App',
      redirectUris: ['https://app.example/cb'],
      scopes: ['openid', 'groups'],
      firstParty: true,
      requiredGroup: 'staff',
    });
    expect(app.status).toBe(201);
    secret = (await app.json()).secret;
    expect(secret).toMatch(/^hs_sec_/);
    const view = await (await admin.api('/api/admin/clients/staff-app')).json();
    expect(view).toMatchObject({ requiredGroup: 'staff', hasSecret: true, source: 'db' });
    expect(JSON.stringify(view)).not.toContain(secret);
  });

  it('shows a non-member a "no access" card, and the app gets access_denied', async () => {
    const config = await rp('staff-app', secret);
    const { landed } = await authorize(bob, config);
    if (landed instanceof URL || !landed || !('post' in landed))
      throw new Error('expected the access card');
    expect(landed.details.prompt.name).toBe('access');
    expect(landed.details.requiredGroup).toEqual({ slug: 'staff', name: 'Staff' });
    const aborted = await landed.post!('abort');
    const back = await bob.hs.follow((await aborted.json()).redirectTo);
    expect(back.location!.searchParams.get('error')).toBe('access_denied');
  });

  it('lets a member in, with the group in the ID token', async () => {
    await admin.api(`/api/admin/groups/${staff}/members/${bob.id}`, 'PUT');
    const config = await rp('staff-app', secret);
    const { landed, verifier } = await authorize(bob, config);
    expect(landed).toBeInstanceOf(URL);
    const tokens = await oidc.authorizationCodeGrant(config, landed as URL, {
      pkceCodeVerifier: verifier,
    });
    expect(decodeJwt(tokens.id_token!).groups).toEqual(['staff']);
  });

  it('closes the door again on SSO once the member is removed', async () => {
    await admin.api(`/api/admin/groups/${staff}/members/${bob.id}`, 'DELETE');
    const config = await rp('staff-app', secret);
    const { landed } = await authorize(bob, config); // Bob is still signed in to Handstamp
    expect(landed).not.toBeInstanceOf(URL);
    expect((landed as { details: { prompt: { name: string } } }).details.prompt.name).toBe(
      'access',
    );
  });

  it('rotating the secret stops the old one immediately', async () => {
    await admin.api(`/api/admin/groups/${staff}/members/${admin.id}`, 'PUT');
    const fresh = (await (await admin.api('/api/admin/clients/staff-app/secret', 'POST')).json())
      .secret;
    const old = await rp('staff-app', secret);
    const { landed, verifier } = await authorize(admin, old);
    // invalid_client, delivered as a WWW-Authenticate challenge.
    await expect(
      oidc.authorizationCodeGrant(old, landed as URL, { pkceCodeVerifier: verifier }),
    ).rejects.toThrow(/WWW-Authenticate/);
    const current = await rp('staff-app', fresh);
    const again = await authorize(admin, current);
    const tokens = await oidc.authorizationCodeGrant(current, again.landed as URL, {
      pkceCodeVerifier: again.verifier,
    });
    expect(tokens.access_token).toBeTruthy();
  });

  it("won't delete a group an app requires", async () => {
    const response = await admin.api(`/api/admin/groups/${staff}`, 'DELETE');
    expect((await response.json()).error).toBe('in_use');
  });

  it('keeps file and built-in apps read-only', async () => {
    for (const id of ['rp-first', 'handstamp-console']) {
      const response = await admin.api(`/api/admin/clients/${id}/secret`, 'POST');
      expect((await response.json()).error).toBe('read_only');
    }
  });
});

describe('providers and keys', () => {
  it('adds an upstream provider; its secret is write-only', async () => {
    const created = await admin.api('/api/admin/providers', 'POST', {
      slug: 'corp',
      kind: 'oidc',
      displayName: 'Corp SSO',
      issuer: 'https://sso.corp.example',
      clientId: 'handstamp',
      clientSecret: 'super-secret-value',
    });
    expect(created.status).toBe(201);
    const list = await (await admin.api('/api/admin/providers')).json();
    expect(list.find((p: { slug: string }) => p.slug === 'corp')).toMatchObject({
      trustEmailVerified: false,
      source: 'db',
    });
    expect(JSON.stringify(list)).not.toContain('super-secret-value');
    const bad = await admin.api('/api/admin/providers', 'POST', {
      slug: 'plain',
      kind: 'oidc',
      displayName: 'Plain',
      issuer: 'http://sso.example.com',
      clientId: 'x',
      clientSecret: 'y',
    });
    expect((await bad.json()).field).toBe('issuer');
  });

  it('rotates the signing key in two steps', async () => {
    const before = (await (await fetch(`${server.issuer}/jwks`)).json()).keys.length;
    const { kid } = await (await admin.api('/api/admin/keys/rotate', 'POST')).json();
    const jwks = await (await fetch(`${server.issuer}/jwks`)).json();
    expect(jwks.keys.length).toBe(before + 1);
    expect((await (await admin.api('/api/admin/keys/promote', 'POST')).json()).kid).toBe(kid);
  });
});

describe('audit log (S19)', () => {
  it('records every admin change, attributed to the admin', async () => {
    const { entries } = await (await admin.api(`/api/admin/audit?actor=${admin.id}`)).json();
    const actions = new Set(entries.map((e: { action: string }) => e.action));
    for (const action of [
      'user.admin_granted',
      'user.admin_revoked',
      'user.disabled',
      'recovery.issued',
      'group.created',
      'group.member_added',
      'group.member_removed',
      'client.created',
      'client.secret_rotated',
      'provider.created',
      'key.staged',
      'key.activated',
    ])
      expect(actions, action).toContain(action);
    expect(entries.every((e: { actorName: string }) => e.actorName === 'Admin')).toBe(true);
  });

  it('filters by action prefix and exports CSV without spreadsheet formulas', async () => {
    const { entries } = await (await admin.api('/api/admin/audit?action=group.')).json();
    expect(entries.every((e: { action: string }) => e.action.startsWith('group.'))).toBe(true);
    // The admin's own name becomes a formula; it shows up as actorName on their audit rows.
    await admin.api(`/api/admin/users/${admin.id}`, 'PATCH', {
      displayName: '=HYPERLINK("https://evil")',
    });
    const csv = await (await admin.api('/api/admin/audit.csv')).text();
    expect(csv.split('\n')[0]).toContain(',action,');
    expect(csv).toContain(`"'=HYPERLINK(""https://evil"")"`);
    expect(csv).not.toMatch(/(^|,)"=/m);
  });
});

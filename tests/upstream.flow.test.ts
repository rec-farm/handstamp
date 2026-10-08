import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SoftAuthenticator } from './authenticator.ts';
import { Browser, freePort, startTestServer } from './harness.ts';
import { mockGitHub, mockOidcIssuer, type GitHubUser, type MockAccount } from './mocks.ts';

// Upstream sign-in, linking, invites and recovery, one test per threat in docs/PLAN.md §3.3.

let server: Awaited<ReturnType<typeof startTestServer>>;
let corp: Awaited<ReturnType<typeof mockOidcIssuer>>;
let github: ReturnType<typeof mockGitHub>;

beforeAll(async () => {
  const [port, idpPort, ghPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const issuer = `http://localhost:${port}`;
  corp = await mockOidcIssuer(
    idpPort,
    `${issuer}/upstream/corp/callback`,
    'corp-secret-0123456789',
  );
  github = mockGitHub(ghPort);
  server = await startTestServer('upstream', {
    port,
    env: {
      HANDSTAMP_DEV_LOGIN: '0',
      // Corporate SSO: sign-up open to @corp.example, emails trusted.
      HANDSTAMP_UPSTREAM_OIDC_CORP_ISSUER: corp.issuer,
      HANDSTAMP_UPSTREAM_OIDC_CORP_CLIENT_ID: 'handstamp',
      HANDSTAMP_UPSTREAM_OIDC_CORP_CLIENT_SECRET: 'corp-secret-0123456789',
      HANDSTAMP_UPSTREAM_OIDC_CORP_NAME: 'Corp SSO',
      HANDSTAMP_UPSTREAM_OIDC_CORP_ALLOW_SIGNUP: '1',
      HANDSTAMP_UPSTREAM_OIDC_CORP_ALLOWED_DOMAINS: 'corp.example',
      HANDSTAMP_UPSTREAM_OIDC_CORP_TRUST_EMAIL: '1',
      // GitHub: sign-up closed (the default).
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID: 'gh-client',
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_SECRET: 'gh-secret',
      HANDSTAMP_UPSTREAM_GITHUB_URL: github.url,
      HANDSTAMP_UPSTREAM_GITHUB_API_URL: `${github.url}/api/v3`,
    },
  });
  await server.sql('UPDATE instance_settings SET setup_completed_at = now()');
});

afterAll(async () => {
  await server?.close();
  await corp?.close();
  await github?.close();
});

// A person with their own cookies at Handstamp, the corporate IdP and GitHub.
function person() {
  const jars = new Map<string, Browser>();
  const jar = (origin: string) => {
    if (!jars.has(origin)) jars.set(origin, new Browser(origin));
    return jars.get(origin)!;
  };
  const hs = jar(server.issuer);
  async function travel(start: string) {
    let url = new URL(start, server.issuer);
    let response = await jar(url.origin).request(url.href);
    for (let hop = 0; hop < 20 && [302, 303].includes(response.status); hop++) {
      url = new URL(response.headers.get('location')!, url);
      response = await jar(url.origin).request(url.href);
    }
    return { url, response };
  }
  async function interaction(start = '/console/login') {
    const { url } = await travel(start);
    expect(url.pathname).toMatch(/^\/interaction\//);
    const uid = hs.cookies.get('hs_interaction')!.value;
    const details = await (await hs.request(`/interaction/${uid}/details`)).json();
    const post = (path: string, json: unknown = {}) =>
      hs.request(`/interaction/${uid}/${path}`, {
        method: 'POST',
        json,
        headers: { 'x-handstamp-csrf': details.csrf },
      });
    return { uid, details, post };
  }
  // Signs in to the console through an upstream provider; returns where the browser ended up.
  async function viaUpstream(slug: string, start = '/console/login?returnTo=/account') {
    const { uid } = await interaction(start);
    return (await travel(`/interaction/${uid}/upstream/${slug}`)).url;
  }
  async function viaPasskey(auth: SoftAuthenticator, start = '/console/login?returnTo=/account') {
    const { post } = await interaction(start);
    const options = await (await post('passkey/options')).json();
    const signed = await post('passkey/verify', { response: auth.get(options) });
    expect(signed.status).toBe(200);
    return (await travel((await signed.json()).redirectTo)).url;
  }
  async function api(path: string, init: { method?: string; json?: unknown } = {}) {
    const me = await (await hs.request('/api/me')).json();
    return hs.request(path, {
      method: init.method ?? 'GET',
      ...(init.json !== undefined ? { json: init.json } : {}),
      headers: { 'x-handstamp-csrf': me.csrf ?? '' },
    });
  }
  return { hs, travel, interaction, viaUpstream, viaPasskey, api };
}

const corpUser = (sub: string, email: string, name = 'Corp Person'): MockAccount => ({
  sub,
  email,
  email_verified: true,
  name,
});
let githubId = 1000;
const githubUser = (login: string, email: string): GitHubUser => ({
  id: ++githubId,
  login,
  emails: [{ email, primary: true, verified: true }],
});

let graceGithub: GitHubUser;

async function userByEmail(email: string) {
  const [user] = await server.sql<{ id: string }>('SELECT id FROM users WHERE lower(email) = $1', [
    email,
  ]);
  return user;
}

describe('upstream sign-in and sign-up policy', () => {
  it('lists the configured providers on the sign-in card', async () => {
    const { details } = await person().interaction();
    expect(details.providers.map((p: { slug: string }) => p.slug).sort()).toEqual([
      'corp',
      'github',
    ]);
  });

  it('signs up a new person through an allowed provider and domain, keeping their verified email', async () => {
    corp.signInAs(corpUser('ada', 'ada@corp.example', 'Ada Lovelace'));
    const ada = person();
    expect((await ada.viaUpstream('corp')).pathname).toBe('/account');
    const me = await (await ada.hs.request('/api/me')).json();
    expect(me.user).toMatchObject({
      displayName: 'Ada Lovelace',
      email: 'ada@corp.example',
      emailVerified: true,
    });
  });

  it('signs the same person in again by (issuer, subject), not by email', async () => {
    corp.signInAs(corpUser('ada', 'ada.new-address@corp.example', 'Ada Lovelace'));
    const again = person();
    expect((await again.viaUpstream('corp')).pathname).toBe('/account');
    const me = await (await again.hs.request('/api/me')).json();
    expect(me.user.email).toBe('ada@corp.example'); // same account; email isn't the key
  });

  it('refuses sign-up from outside the allowed email domains', async () => {
    corp.signInAs(corpUser('mallory', 'mallory@evil.example'));
    const url = await person().viaUpstream('corp');
    expect(url.searchParams.get('error')).toBe('email_domain');
  });

  it('refuses an unknown GitHub account when sign-up is closed', async () => {
    github.signInAs(githubUser('stranger', 'stranger@example.com'));
    const url = await person().viaUpstream('github');
    expect(url.pathname).toMatch(/^\/interaction\//);
    expect(url.searchParams.get('error')).toBe('unlinked_identity');
  });
});

describe('threat: account takeover via email (§3.3)', () => {
  it("doesn't hand Ada's account to a GitHub account that claims her email", async () => {
    github.signInAs(githubUser('not-ada', 'ada@corp.example'));
    const attacker = person();
    const url = await attacker.viaUpstream('github');
    // Same answer as for any unknown account: nothing reveals that Ada exists.
    expect(url.searchParams.get('error')).toBe('unlinked_identity');
    expect((await attacker.hs.request('/api/me')).status).toBe(401);
    const ada = await userByEmail('ada@corp.example');
    const linked = await server.sql<{ issuer: string }>(
      'SELECT issuer FROM identities WHERE user_id = $1',
      [ada.id],
    );
    expect(linked.map((i) => i.issuer)).toEqual([corp.issuer]);
  });

  it('creates a separate account without the email when a new upstream identity claims a held one', async () => {
    corp.signInAs(corpUser('ada-impostor', 'ada@corp.example', 'Not Ada'));
    const impostor = person();
    expect((await impostor.viaUpstream('corp')).pathname).toBe('/account');
    const me = await (await impostor.hs.request('/api/me')).json();
    const ada = await userByEmail('ada@corp.example');
    expect(me.user.sub).not.toBe(ada.id);
    expect(me.user.email).toBeNull();
    const conflicts = await server.sql<{ target_id: string }>(
      "SELECT target_id FROM audit_log WHERE action = 'user.email_conflict'",
    );
    expect(conflicts.some((c) => c.target_id === me.user.sub)).toBe(true);
  });
});

describe('linking', () => {
  it('links GitHub from the account page, and GitHub then signs into the same account', async () => {
    corp.signInAs(corpUser('grace', 'grace@corp.example', 'Grace Hopper'));
    const grace = person();
    await grace.viaUpstream('corp');
    const before = await (await grace.api('/api/me/identities')).json();
    expect(before.available.map((p: { slug: string }) => p.slug)).toEqual(['github']);

    const gh = (graceGithub = githubUser('grace-h', 'grace@users.noreply.github.com'));
    github.signInAs(gh);
    const start = await grace.api('/api/me/identities/link/github', { method: 'POST', json: {} });
    expect(start.status).toBe(200);
    const { url } = await grace.travel((await start.json()).redirectTo);
    expect(url.pathname + url.search).toBe('/account?linked=github');

    github.signInAs(gh);
    const later = person();
    expect((await later.viaUpstream('github')).pathname).toBe('/account');
    const me = await (await later.hs.request('/api/me')).json();
    expect(me.user.displayName).toBe('Grace Hopper');
  });

  it('refuses to link an identity that belongs to someone else', async () => {
    corp.signInAs(corpUser('ada', 'ada@corp.example', 'Ada Lovelace'));
    const ada = person();
    await ada.viaUpstream('corp');
    // Grace's GitHub, from the previous test.
    github.signInAs(graceGithub);
    const start = await ada.api('/api/me/identities/link/github', { method: 'POST', json: {} });
    const { url } = await ada.travel((await start.json()).redirectTo);
    expect(url.searchParams.get('error')).toBe('identity_taken');
  });

  it("won't unlink your only way in", async () => {
    corp.signInAs(corpUser('solo', 'solo@corp.example'));
    const solo = person();
    await solo.viaUpstream('corp');
    const { linked } = await (await solo.api('/api/me/identities')).json();
    const response = await solo.api(`/api/me/identities/${linked[0].id}`, { method: 'DELETE' });
    expect(response.status).toBe(409);
  });
});

describe('threat: compromised upstream account (§3.3)', () => {
  it('lets the attacker in, but not change how the victim signs in without the passkey', async () => {
    // Linus has a passkey and a linked corp identity.
    corp.signInAs(corpUser('linus', 'linus@corp.example', 'Linus'));
    const linus = person();
    await linus.viaUpstream('corp');
    const auth = new SoftAuthenticator(server.issuer);
    const options = await (
      await linus.api('/api/me/passkeys/options', { method: 'POST', json: {} })
    ).json();
    expect(
      (
        await linus.api('/api/me/passkeys', {
          method: 'POST',
          json: { response: auth.create(options) },
        })
      ).status,
    ).toBe(201);

    // Someone takes over Linus's corp account and signs in with it.
    corp.signInAs(corpUser('linus', 'linus@corp.example', 'Linus'));
    const attacker = person();
    expect((await attacker.viaUpstream('corp')).pathname).toBe('/account');
    for (const [path, method] of [
      ['/api/me/passkeys/options', 'POST'],
      [`/api/me/identities/link/github`, 'POST'],
    ] as const) {
      const response = await attacker.api(path, { method, json: {} });
      expect(response.status).toBe(403);
      expect(await response.json()).toMatchObject({ error: 'step_up_required', method: 'passkey' });
    }
    const [passkey] = await (await attacker.api('/api/me/passkeys')).json();
    expect(
      (await attacker.api(`/api/me/passkeys/${passkey.id}`, { method: 'DELETE' })).status,
    ).toBe(403);

    // The step-up card offers only the passkey.
    const { details } = await attacker.interaction('/console/login?fresh=1&passkey=1');
    expect(details.passkeyOnly).toBe(true);
    expect(details.providers).toEqual([]);
  });
});

describe('invites', () => {
  it('lets an invited person join with a passkey, once', async () => {
    const { token } = await server.enrollments.createInvite({ actorType: 'cli' });
    const newbie = person();
    const opened = await newbie.hs.request('/api/enroll', { method: 'POST', json: { token } });
    expect(await opened.json()).toMatchObject({ purpose: 'invite' });

    const { details, post } = await newbie.interaction('/console/login?returnTo=/account');
    expect(details.mode).toBe('invite');
    const auth = new SoftAuthenticator(server.issuer);
    const options = await (
      await post('enroll/passkey/options', { displayName: 'New Person' })
    ).json();
    const joined = await post('enroll/passkey/verify', { response: auth.create(options) });
    expect(joined.status).toBe(200);
    expect((await newbie.travel((await joined.json()).redirectTo)).url.pathname).toBe('/account');
    expect((await (await newbie.hs.request('/api/me')).json()).user.displayName).toBe('New Person');

    const reused = await person().hs.request('/api/enroll', { method: 'POST', json: { token } });
    expect(reused.status).toBe(410);
  });

  it('lets an invited person join with GitHub even though GitHub sign-up is closed', async () => {
    const { token } = await server.enrollments.createInvite({ actorType: 'cli' });
    const invited = person();
    await invited.hs.request('/api/enroll', { method: 'POST', json: { token } });
    github.signInAs(githubUser('invited', 'invited@example.com'));
    expect((await invited.viaUpstream('github')).pathname).toBe('/account');
  });
});

describe('threat: lost passkey (§3.3)', () => {
  it('recovers with an admin link: new passkey works, the lost one and old sessions are gone', async () => {
    // Rosa has only a passkey, and is signed in on her old laptop.
    const { token: inviteToken } = await server.enrollments.createInvite({ actorType: 'cli' });
    const laptop = person();
    await laptop.hs.request('/api/enroll', { method: 'POST', json: { token: inviteToken } });
    const lostKey = new SoftAuthenticator(server.issuer);
    const join = await laptop.interaction();
    const options = await (
      await join.post('enroll/passkey/options', { displayName: 'Rosa' })
    ).json();
    await laptop.travel(
      (
        await (
          await join.post('enroll/passkey/verify', { response: lostKey.create(options) })
        ).json()
      ).redirectTo,
    );
    const rosa = (await (await laptop.hs.request('/api/me')).json()).user;

    // The laptop is lost. An admin issues a recovery link that revokes old methods.
    const { token } = await server.enrollments.createRecovery(rosa.sub, {
      revokeOtherMethods: true,
    });
    const phone = person();
    expect(
      await (await phone.hs.request('/api/enroll', { method: 'POST', json: { token } })).json(),
    ).toMatchObject({
      purpose: 'recovery',
      name: 'Rosa',
    });
    const { details, post } = await phone.interaction();
    expect(details).toMatchObject({ mode: 'recovery', enrollingAs: 'Rosa' });
    const newKey = new SoftAuthenticator(server.issuer);
    const recoverOptions = await (await post('enroll/passkey/options')).json();
    const recovered = await post('enroll/passkey/verify', {
      response: newKey.create(recoverOptions),
    });
    expect(recovered.status).toBe(200);
    await phone.travel((await recovered.json()).redirectTo);
    expect((await (await phone.hs.request('/api/me')).json()).user.sub).toBe(rosa.sub);

    // The lost laptop's session is over and its passkey no longer exists.
    expect((await laptop.hs.request('/api/me')).status).toBe(401);
    const keys = await server.sql('SELECT id FROM passkeys WHERE user_id = $1', [rosa.sub]);
    expect(keys).toHaveLength(1);
    const tryOld = await person().interaction();
    const oldOptions = await (await tryOld.post('passkey/options')).json();
    expect(
      (await tryOld.post('passkey/verify', { response: lostKey.get(oldOptions) })).status,
    ).toBe(401);

    // And the new passkey signs in normally.
    expect((await person().viaPasskey(newKey)).pathname).toBe('/account');
    const used = await server.sql<{ actor_user_id: string }>(
      "SELECT actor_user_id FROM audit_log WHERE action = 'recovery.used'",
    );
    expect(used.some((u) => u.actor_user_id === rosa.sub)).toBe(true);
  });
});

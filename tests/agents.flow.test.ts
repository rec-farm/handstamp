import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as oidc from 'openid-client';
import { Browser, freePort, SECRETS, startTestServer } from './harness.ts';
import { mockOidcIssuer, type MockAccount } from './mocks.ts';

// Agent accounts through AgentID (docs/INTEGRATING.md, "Agent accounts"), against a mock issuer
// that signs like AgentID: ES256 ID tokens with actor_type and the owner's claims.

let server: Awaited<ReturnType<typeof startTestServer>>;
let agentid: Awaited<ReturnType<typeof mockOidcIssuer>>;
let corp: Awaited<ReturnType<typeof mockOidcIssuer>>;

beforeAll(async () => {
  const [port, agentPort, corpPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const issuer = `http://localhost:${port}`;
  agentid = await mockOidcIssuer(
    agentPort,
    `${issuer}/upstream/agentid/callback`,
    'agentid-secret-0123456789',
    { agentid: true },
  );
  corp = await mockOidcIssuer(
    corpPort,
    `${issuer}/upstream/corp/callback`,
    'corp-secret-0123456789',
  );
  server = await startTestServer('agents', {
    port,
    env: {
      HANDSTAMP_DEV_LOGIN: '0',
      AGENT_SESSION_HOURS: '2',
      HANDSTAMP_UPSTREAM_AGENTID_CLIENT_ID: 'handstamp',
      HANDSTAMP_UPSTREAM_AGENTID_CLIENT_SECRET: 'agentid-secret-0123456789',
      // Testing only: the real issuer is always https://auth.agentid.com.
      HANDSTAMP_UPSTREAM_AGENTID_ISSUER: agentid.issuer,
      HANDSTAMP_UPSTREAM_OIDC_CORP_ISSUER: corp.issuer,
      HANDSTAMP_UPSTREAM_OIDC_CORP_CLIENT_ID: 'handstamp',
      HANDSTAMP_UPSTREAM_OIDC_CORP_CLIENT_SECRET: 'corp-secret-0123456789',
      HANDSTAMP_UPSTREAM_OIDC_CORP_ALLOW_SIGNUP: '1',
      HANDSTAMP_UPSTREAM_OIDC_CORP_TRUST_EMAIL: '1',
    },
  });
  await server.sql('UPDATE instance_settings SET setup_completed_at = now()');
});

afterAll(async () => {
  await server?.close();
  await agentid?.close();
  await corp?.close();
});

// Someone (or something) with its own cookies at Handstamp and the upstream issuers.
function visitor() {
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
      if (url.origin === 'https://rp.example') return { url, response };
      response = await jar(url.origin).request(url.href);
    }
    return { url, response };
  }
  async function viaUpstream(slug: string, start = '/console/login?returnTo=/account') {
    const { url } = await travel(start);
    expect(url.pathname).toMatch(/^\/interaction\//);
    const uid = hs.cookies.get('hs_interaction')!.value;
    return (await travel(`/interaction/${uid}/upstream/${slug}`)).url;
  }
  async function api(path: string, init: { method?: string; json?: unknown } = {}) {
    const me = await (await hs.request('/api/me')).json();
    return hs.request(path, {
      method: init.method ?? 'GET',
      ...(init.json !== undefined ? { json: init.json } : {}),
      headers: { 'x-handstamp-csrf': me.csrf ?? '' },
    });
  }
  return { hs, travel, viaUpstream, api };
}

const agent = (sub: string, extra: Partial<MockAccount> = {}): MockAccount => ({
  sub,
  email: `${sub}@agents.example`,
  email_verified: true,
  name: `Agent ${sub}`,
  actor_type: 'agent',
  owner_sub: 'owner-ada',
  owner_name: 'Ada Lovelace',
  owner_email: 'ada@corp.example',
  ...extra,
});

async function invited() {
  const { token } = await server.enrollments.createInvite({ actorType: 'cli' });
  const bot = visitor();
  await bot.hs.request('/api/enroll', { method: 'POST', json: { token } });
  return bot;
}

describe('agent accounts', () => {
  it('refuses an agent without an invite: sign-up is off by default', async () => {
    agentid.signInAs(agent('stray'));
    const url = await visitor().viaUpstream('agentid');
    expect(url.searchParams.get('error')).toBe('unlinked_identity');
  });

  it('refuses an identity AgentID does not mark as an agent, even with an invite', async () => {
    agentid.signInAs(agent('person-at-agentid', { actor_type: undefined }));
    const url = await (await invited()).viaUpstream('agentid');
    expect(url.searchParams.get('error')).toBe('not_an_agent');
    const [row] = await server.sql<{ n: string }>(
      "SELECT count(*) AS n FROM identities WHERE subject = 'person-at-agentid'",
    );
    expect(Number(row.n)).toBe(0);
  });

  it('makes an invited agent an agent account, with its owner for display only', async () => {
    const discovery = await (
      await fetch(`${agentid.issuer}/.well-known/openid-configuration`)
    ).json();
    expect(discovery.id_token_signing_alg_values_supported).toEqual(['ES256']);
    agentid.signInAs(agent('scout'));
    const bot = await invited();
    expect((await bot.viaUpstream('agentid')).pathname).toBe('/account');
    const me = await (await bot.hs.request('/api/me')).json();
    expect(me.user).toMatchObject({ displayName: 'Agent scout', kind: 'agent' });
    // AgentID doesn't vouch for the agent's email.
    expect(me.user.email).toBeNull();
    const [identity] = await server.sql<{
      owner_subject: string;
      owner_name: string;
      owner_email: string;
    }>("SELECT owner_subject, owner_name, owner_email FROM identities WHERE subject = 'scout'");
    expect(identity).toEqual({
      owner_subject: 'owner-ada',
      owner_name: 'Ada Lovelace',
      owner_email: 'ada@corp.example',
    });

    // The session lasts AGENT_SESSION_HOURS, not SESSION_MAX_DAYS.
    const [session] = await server.sql<{ hours: number }>(
      "SELECT extract(epoch FROM expires_at - now()) / 3600 AS hours FROM oidc_payloads WHERE kind = 'session' AND account_id = $1",
      [me.user.sub],
    );
    expect(Number(session.hours)).toBeGreaterThan(1.9);
    expect(Number(session.hours)).toBeLessThanOrEqual(2);

    // Apps learn it is an agent: ID token, userinfo and introspection.
    const config = await oidc.discovery(
      new URL(server.issuer),
      'rp-first',
      SECRETS.RP_FIRST_SECRET,
      oidc.ClientSecretBasic(SECRETS.RP_FIRST_SECRET),
      { execute: [oidc.allowInsecureRequests] },
    );
    expect(config.serverMetadata().claims_supported).toContain('actor_type');
    const verifier = oidc.randomPKCECodeVerifier();
    const { url } = await bot.travel(
      oidc.buildAuthorizationUrl(config, {
        redirect_uri: 'https://rp.example/cb',
        scope: 'openid profile',
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
      }).href,
    );
    expect(url.origin).toBe('https://rp.example');
    const tokens = await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: verifier });
    expect(tokens.claims()).toMatchObject({ sub: me.user.sub });
    // Only when asked for: the ID token carries no claims nobody requested.
    expect(tokens.claims()?.actor_type).toBeUndefined();
    const info = await oidc.fetchUserInfo(config, tokens.access_token, me.user.sub);
    expect(info.actor_type).toBe('agent');
    const introspected = await oidc.tokenIntrospection(config, tokens.access_token);
    expect(introspected).toMatchObject({ active: true, actor_type: 'agent' });

    // It signs in again by (issuer, subject), with no invite.
    agentid.signInAs(agent('scout', { owner_name: 'Ada King' }));
    const again = visitor();
    expect((await again.viaUpstream('agentid')).pathname).toBe('/account');
    expect((await (await again.hs.request('/api/me')).json()).user.sub).toBe(me.user.sub);
  });

  it('tells apps a person is a person', async () => {
    corp.signInAs({ sub: 'grace', email: 'grace@corp.example', email_verified: true });
    const grace = visitor();
    await grace.viaUpstream('corp');
    const me = await (await grace.hs.request('/api/me')).json();
    expect(me.user.kind).toBe('person');
    const config = await oidc.discovery(
      new URL(server.issuer),
      'rp-first',
      SECRETS.RP_FIRST_SECRET,
      oidc.ClientSecretBasic(SECRETS.RP_FIRST_SECRET),
      { execute: [oidc.allowInsecureRequests] },
    );
    const verifier = oidc.randomPKCECodeVerifier();
    const { url } = await grace.travel(
      oidc.buildAuthorizationUrl(config, {
        redirect_uri: 'https://rp.example/cb',
        scope: 'openid',
        claims: JSON.stringify({ id_token: { actor_type: null } }),
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
      }).href,
    );
    const tokens = await oidc.authorizationCodeGrant(config, url, { pkceCodeVerifier: verifier });
    expect(tokens.claims()?.actor_type).toBe('person');

    // And an agent identity can't be linked to a person's account.
    agentid.signInAs(agent('hitchhiker'));
    const start = await grace.api('/api/me/identities/link/agentid', { method: 'POST', json: {} });
    expect(start.status).toBe(200);
    const linked = await grace.travel((await start.json()).redirectTo);
    expect(linked.url.searchParams.get('error')).toBe('account_kind');
  });
});

import * as oidc from 'openid-client';
import type { UpstreamIdentity } from '@handstamp/core';
import type { UpstreamProvider } from './providers.ts';

export type Pending = { state: string; verifier: string; nonce?: string };

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const insecureOk = (url: string) => {
  const u = new URL(url);
  return u.protocol === 'http:' && LOOPBACK.has(u.hostname);
};

export class UpstreamError extends Error {
  constructor(
    readonly code: 'upstream_cancelled' | 'upstream_failed',
    message: string,
  ) {
    super(message);
  }
}

// One openid-client Configuration per provider (and its current settings). GitHub speaks plain
// OAuth 2, so it gets a hand-built server description instead of discovery.
const configs = new Map<string, Promise<oidc.Configuration>>();

function configFor(provider: UpstreamProvider) {
  const key = `${provider.id}:${provider.updatedAt.getTime()}`;
  let config = configs.get(key);
  if (!config) {
    const options = insecureOk(provider.issuer) ? { execute: [oidc.allowInsecureRequests] } : {};
    config =
      provider.kind === 'github'
        ? Promise.resolve(
            (() => {
              const c = new oidc.Configuration(
                {
                  issuer: provider.issuer,
                  authorization_endpoint: `${provider.issuer}/login/oauth/authorize`,
                  token_endpoint: `${provider.issuer}/login/oauth/access_token`,
                },
                provider.clientId,
                provider.clientSecret,
                oidc.ClientSecretPost(provider.clientSecret),
              );
              if (insecureOk(provider.issuer)) oidc.allowInsecureRequests(c);
              return c;
            })(),
          )
        : oidc.discovery(
            new URL(provider.issuer),
            provider.clientId,
            provider.clientSecret,
            oidc.ClientSecretBasic(provider.clientSecret),
            options,
          );
    config.catch(() => configs.delete(key));
    configs.set(key, config);
  }
  return config;
}

function scopesFor(provider: UpstreamProvider) {
  if (provider.kind === 'github')
    return ['read:user', 'user:email', ...(provider.githubAllowedOrgs.length ? ['read:org'] : [])];
  return provider.scopes.length ? provider.scopes : ['openid', 'email', 'profile'];
}

export async function beginUpstream(provider: UpstreamProvider, redirectUri: string) {
  const config = await configFor(provider);
  const pending: Pending = {
    state: oidc.randomState(),
    verifier: oidc.randomPKCECodeVerifier(),
    ...(provider.kind === 'github' ? {} : { nonce: oidc.randomNonce() }),
  };
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: scopesFor(provider).join(' '),
    state: pending.state,
    code_challenge: await oidc.calculatePKCECodeChallenge(pending.verifier),
    code_challenge_method: 'S256',
    ...(pending.nonce ? { nonce: pending.nonce } : {}),
    // Let people pick an account instead of silently reusing whoever is signed in upstream.
    ...(provider.kind === 'google' ? { prompt: 'select_account' } : {}),
  });
  return { url: url.href, pending };
}

export async function finishUpstream(
  provider: UpstreamProvider,
  callback: URL,
  pending: Pending,
): Promise<UpstreamIdentity> {
  const error = callback.searchParams.get('error');
  if (error)
    throw new UpstreamError(
      error === 'access_denied' ? 'upstream_cancelled' : 'upstream_failed',
      `${provider.displayName} returned ${error}`,
    );
  const config = await configFor(provider);
  let tokens;
  try {
    tokens = await oidc.authorizationCodeGrant(config, callback, {
      pkceCodeVerifier: pending.verifier,
      expectedState: pending.state,
      ...(pending.nonce ? { expectedNonce: pending.nonce, idTokenExpected: true } : {}),
    });
  } catch (cause) {
    throw new UpstreamError(
      'upstream_failed',
      `Code exchange with ${provider.displayName} failed: ${(cause as Error).message}`,
    );
  }
  return provider.kind === 'github'
    ? githubIdentity(provider, tokens.access_token)
    : oidcIdentity(config, tokens);
}

// Many issuers (Handstamp included) put email only in userinfo, so ask for it when the ID token
// doesn't carry it. fetchUserInfo checks the subject matches the ID token.
async function oidcIdentity(
  config: oidc.Configuration,
  tokens: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
): Promise<UpstreamIdentity> {
  let claims: Record<string, unknown> & { sub: string } = tokens.claims()!;
  if (claims.email === undefined && config.serverMetadata().userinfo_endpoint) {
    try {
      claims = {
        ...(await oidc.fetchUserInfo(config, tokens.access_token, claims.sub)),
        ...claims,
      };
    } catch {
      // No profile beyond the ID token; sign-in still works, just without an email.
    }
  }
  return {
    issuer: config.serverMetadata().issuer,
    subject: claims.sub,
    email: typeof claims.email === 'string' ? claims.email : undefined,
    emailVerified: claims.email_verified === true,
    name: typeof claims.name === 'string' ? claims.name : undefined,
    loginHint: typeof claims.email === 'string' ? claims.email : undefined,
  };
}

async function github<T>(provider: UpstreamProvider, token: string, path: string): Promise<T> {
  const response = await fetch(`${provider.apiUrl}${path}`, {
    headers: {
      authorization: `Bearer ${token}`,
      accept: 'application/vnd.github+json',
      'user-agent': 'Handstamp',
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok)
    throw new UpstreamError(
      'upstream_failed',
      `${provider.displayName} API ${path} answered ${response.status}`,
    );
  return (await response.json()) as T;
}

// GitHub identity = (GitHub web URL, numeric user id). The login can be renamed; the id can't.
async function githubIdentity(
  provider: UpstreamProvider,
  token: string,
): Promise<UpstreamIdentity> {
  const user = await github<{ id: number; login: string; name: string | null }>(
    provider,
    token,
    '/user',
  );
  const emails = await github<{ email: string; primary: boolean; verified: boolean }[]>(
    provider,
    token,
    '/user/emails',
  );
  const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
  const orgs = provider.githubAllowedOrgs.length
    ? (await github<{ login: string }[]>(provider, token, '/user/orgs')).map((o) => o.login)
    : undefined;
  return {
    issuer: provider.issuer,
    subject: String(user.id),
    email: primary?.email,
    emailVerified: Boolean(primary),
    name: user.name ?? undefined,
    loginHint: user.login,
    orgs,
  };
}

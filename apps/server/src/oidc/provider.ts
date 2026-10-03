import Provider, { type Configuration, type KoaContextWithOIDC } from 'oidc-provider';
import { createOidcAdapter, type Database } from '@handstamp/db';
import type { Env } from '../env.ts';
import type { ClientStore } from '../clients.ts';
import { findAccount } from './account.ts';
import { interactionPolicyWithAccess } from './access.ts';
import type { ShellRenderer } from '../http/shell.ts';

export type ProviderDeps = {
  env: Env;
  db: Database;
  clients: ClientStore;
  jwks: { keys: Record<string, unknown>[] };
  cookieKeys: string[];
  shell: ShellRenderer;
};

const ERROR_CODE = /^[a-z_]{1,64}$/;

// `__Host-` needs Secure + Path=/. oidc-provider scopes the interaction and resume cookies to
// /interaction/:uid and /auth/:uid, so those get `__Secure-`. Over plain http (local dev only)
// browsers reject both prefixes, so they are dropped.
export function cookieNames(issuer: URL) {
  const https = issuer.protocol === 'https:';
  return {
    session: https ? '__Host-hs_session' : 'hs_session',
    interaction: https ? '__Secure-hs_interaction' : 'hs_interaction',
    resume: https ? '__Secure-hs_resume' : 'hs_resume',
  };
}

function isFirstParty(ctx: KoaContextWithOIDC) {
  return ctx.oidc.client?.metadata().handstamp_first_party === true;
}

export function createProvider({ env, db, clients, jwks, cookieKeys, shell }: ProviderDeps) {
  const issuer = env.HANDSTAMP_ISSUER;
  const secure = issuer.protocol === 'https:';
  const cookie = { httpOnly: true, sameSite: 'lax' as const, secure };
  // OIDC Core requires POST at the authorization endpoint. oidc-provider only allows it when the
  // SSO session cookie is SameSite=None, which needs Secure, so POST is on for https issuers (R16).
  const allowPost = secure;
  const sessionCookie = allowPost ? { ...cookie, sameSite: 'none' as const } : cookie;

  const configuration: Configuration = {
    adapter: createOidcAdapter(db, clients.load),
    findAccount: (ctx, sub) => findAccount(db, sub),
    jwks: jwks as Configuration['jwks'],
    cookies: { names: cookieNames(issuer), long: sessionCookie, short: cookie, keys: cookieKeys },
    enableHttpPostMethods: allowPost,

    scopes: ['openid', 'offline_access', 'profile', 'email', 'groups'],
    claims: {
      // `groups` is listed under openid so it can ride in the ID token; findAccount only returns
      // it when the `groups` scope was granted (D6). `amr` likewise, so apps always see how the
      // user signed in (R11); it is only set for passkey sign-ins.
      openid: ['sub', 'groups', 'amr'],
      profile: ['name', 'preferred_username', 'updated_at'],
      email: ['email', 'email_verified'],
      groups: ['groups'],
      acr: null,
      amr: null,
      auth_time: null,
      sid: null,
      iss: null,
    },
    // Spec default: profile and email claims go to userinfo only, not the ID token (D6).
    conformIdTokenClaims: true,

    responseTypes: ['code'],
    clientAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],
    enabledJWA: {
      idTokenSigningAlgValues: ['RS256'],
      userinfoSigningAlgValues: ['RS256'],
      clientAuthSigningAlgValues: ['RS256', 'ES256'],
    },
    clientDefaults: {
      grant_types: ['authorization_code'],
      response_types: ['code'],
      id_token_signed_response_alg: 'RS256',
      token_endpoint_auth_method: 'client_secret_basic',
    },
    extraClientMetadata: {
      properties: ['handstamp_first_party', 'handstamp_require_pkce', 'handstamp_required_group'],
    },
    // Console step-up asks the sign-in card for a passkey specifically.
    extraParams: ['handstamp_method'],

    // PKCE S256 is required unless a confidential client opts out (only conformance test clients).
    pkce: {
      required: (ctx, client) =>
        client.clientAuthMethod === 'none' || client.metadata().handstamp_require_pkce !== false,
    },

    ttl: {
      AuthorizationCode: 60,
      AccessToken: env.ACCESS_TOKEN_MINUTES * 60,
      IdToken: env.ID_TOKEN_MINUTES * 60,
      RefreshToken: env.REFRESH_TOKEN_DAYS * 24 * 60 * 60,
      Interaction: 60 * 60,
      Session: env.SESSION_MAX_DAYS * 24 * 60 * 60,
      Grant: env.SESSION_MAX_DAYS * 24 * 60 * 60,
    },
    // Rotate on every use. Reusing a consumed refresh token revokes the whole grant.
    rotateRefreshToken: true,
    // Clients allowed the refresh_token grant always get one. Without offline_access (which the
    // spec only honours with prompt=consent) it is bound to the SSO session and dies at sign-out.
    issueRefreshToken: async (ctx, client) => client.grantTypeAllowed('refresh_token'),

    features: {
      devInteractions: { enabled: false },
      userinfo: { enabled: true },
      revocation: { enabled: true },
      introspection: { enabled: true },
      claimsParameter: { enabled: true },
      backchannelLogout: { enabled: true },
      rpInitiatedLogout: {
        enabled: true,
        logoutSource: async (ctx, form) => {
          ctx.type = 'html';
          if (env.HANDSTAMP_CONFORMANCE_MODE) {
            // Plain form for the suite's browser automation; `form` is oidc-provider's own markup.
            ctx.body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign out</title></head><body>${form}<button id="hs-logout" type="submit" form="op.logoutForm" name="logout" value="yes">Sign out</button></body></html>`;
            return;
          }
          ctx.body = await shell.render('/logout', {
            view: 'logout',
            xsrf: ctx.oidc.session!.state!.secret as string,
            action: ctx.oidc.urlFor('end_session_confirm'),
            client: ctx.oidc.client?.clientName ?? ctx.oidc.client?.clientId ?? '',
          });
        },
        postLogoutSuccessSource: async (ctx) => {
          ctx.type = 'html';
          ctx.body = await shell.render('/signed-out', {
            view: 'signed-out',
            client: ctx.oidc.client?.clientName ?? ctx.oidc.client?.clientId ?? '',
          });
        },
      },
      // Not needed by REC apps; off to keep the surface small.
      dPoP: { enabled: false },
      pushedAuthorizationRequests: { enabled: false },
      resourceIndicators: { enabled: false },
      requestObjects: { enabled: false },
    },

    interactions: {
      policy: interactionPolicyWithAccess(db),
      url: (ctx, interaction) => `/interaction/${interaction.uid}`,
    },

    // First-party clients skip consent: their grant is created (or extended) automatically.
    async loadExistingGrant(ctx) {
      const { client, session } = ctx.oidc;
      const grantId = ctx.oidc.result?.consent?.grantId || session!.grantIdFor(client!.clientId);
      let grant = grantId ? await ctx.oidc.provider.Grant.find(grantId) : undefined;
      if (!isFirstParty(ctx)) return grant;
      grant ??= new ctx.oidc.provider.Grant({
        clientId: client!.clientId,
        accountId: session!.accountId!,
      });
      grant.addOIDCScope([...ctx.oidc.requestParamOIDCScopes].join(' '));
      if (ctx.oidc.requestParamClaims) grant.addOIDCClaims([...ctx.oidc.requestParamClaims]);
      await grant.save();
      return grant;
    },

    // Errors show a fixed message per code. Nothing from the request is reflected (S20).
    async renderError(ctx, out) {
      const code =
        typeof out.error === 'string' && ERROR_CODE.test(out.error) ? out.error : 'server_error';
      ctx.type = 'html';
      if (env.HANDSTAMP_CONFORMANCE_MODE) {
        ctx.body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Error</title></head><body><h1>Handstamp could not complete this request</h1><p>error: ${code}</p></body></html>`;
        return;
      }
      ctx.body = await shell.render('/error', { view: 'error', code });
    },
  };

  // oidc-provider refuses outbound calls (back-channel logout) to loopback and private
  // addresses. Apps on the same private network as Handstamp need ALLOW_PRIVATE_NETWORKS.
  // (`fetch` is a real option; @types/oidc-provider doesn't list it yet.)
  if (env.ALLOW_PRIVATE_NETWORKS)
    Object.assign(configuration, {
      fetch: (url: string | URL, options: RequestInit & { dispatcher?: unknown }) => {
        const { dispatcher: _ssrfGuard, ...rest } = options;
        return globalThis.fetch(url, rest);
      },
    });

  const provider = new Provider(issuer.origin, configuration);
  provider.proxy = env.trustProxy !== false;
  return provider;
}

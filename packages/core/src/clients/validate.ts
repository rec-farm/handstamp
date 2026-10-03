import { z } from 'zod';
import { GROUP_SLUG } from '../groups.ts';

export const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'groups', 'offline_access'] as const;
export type Scope = (typeof SUPPORTED_SCOPES)[number];

export const TOKEN_ENDPOINT_AUTH_METHODS = [
  'client_secret_basic',
  'client_secret_post',
  'none',
] as const;

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// `*.localhost` is loopback too (RFC 6761 §6.3), so local dev servers can keep named URLs.
// Chrome and Firefox resolve it to 127.0.0.1 without asking DNS; Safari defers to the OS
// resolver, which should but may not. Fine for development; production apps use https.
function isLoopback(hostname: string): boolean {
  return LOOPBACK_HOSTS.has(hostname) || hostname.endsWith('.localhost');
}

// Exact-match redirect URIs only: absolute https URLs (http only on loopback, RFC 8252),
// no wildcards, no fragments, no embedded credentials.
export function redirectUriProblem(value: string): string | undefined {
  if (value.includes('*')) return 'Wildcards are not allowed. Register each URI exactly.';
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'Use an absolute URL, such as https://app.example.com/callback.';
  }
  if (url.protocol === 'http:' && !isLoopback(url.hostname))
    return 'Use https://. Plain http:// is only allowed for localhost and *.localhost.';
  if (url.protocol !== 'https:' && url.protocol !== 'http:')
    return 'Only https:// URLs are supported.';
  if (url.hash) return 'Remove the #fragment. Redirect URIs cannot have one.';
  if (url.username || url.password) return 'Remove the credentials from the URL.';
  return undefined;
}

const redirectUri = z.string().superRefine((value, ctx) => {
  const problem = redirectUriProblem(value);
  if (problem) ctx.addIssue({ code: 'custom', message: problem });
});

export const clientDefinitionSchema = z
  .object({
    clientId: z
      .string()
      .regex(
        /^[a-z0-9][a-z0-9._-]{1,63}$/,
        'Use 2–64 lowercase letters, digits, dots, dashes or underscores.',
      ),
    name: z.string().trim().min(1).max(80),
    redirectUris: z.array(redirectUri).min(1),
    postLogoutRedirectUris: z.array(redirectUri).default([]),
    scopes: z.array(z.enum(SUPPORTED_SCOPES)).default(['openid', 'profile', 'email']),
    tokenEndpointAuthMethod: z.enum(TOKEN_ENDPOINT_AUTH_METHODS).default('client_secret_basic'),
    firstParty: z.boolean().default(false),
    requirePkce: z.boolean().default(true),
    backchannelLogoutUri: redirectUri.optional(),
    // Only members of this group (by slug) may sign in to the app (R7).
    requiredGroup: z.string().regex(GROUP_SLUG).optional(),
  })
  .superRefine((client, ctx) => {
    if (!client.scopes.includes('openid'))
      ctx.addIssue({ code: 'custom', path: ['scopes'], message: 'Scopes must include openid.' });
    if (client.tokenEndpointAuthMethod === 'none' && !client.requirePkce)
      ctx.addIssue({
        code: 'custom',
        path: ['requirePkce'],
        message: 'Public clients always require PKCE.',
      });
  });

export type ClientDefinition = z.output<typeof clientDefinitionSchema>;

// Metadata in the shape oidc-provider expects. `handstamp_*` keys are registered as
// extraClientMetadata so the provider config can read them.
export function toProviderMetadata(
  client: ClientDefinition,
  secret: string | undefined,
  requiredGroupId?: string | null,
) {
  const isPublic = client.tokenEndpointAuthMethod === 'none';
  if (!isPublic && !secret) throw new Error(`Client ${client.clientId} needs a secret`);
  return {
    client_id: client.clientId,
    ...(isPublic ? {} : { client_secret: secret }),
    client_name: client.name,
    redirect_uris: client.redirectUris,
    post_logout_redirect_uris: client.postLogoutRedirectUris,
    response_types: ['code'],
    grant_types: client.scopes.includes('offline_access')
      ? ['authorization_code', 'refresh_token']
      : ['authorization_code'],
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    id_token_signed_response_alg: 'RS256',
    scope: client.scopes.join(' '),
    ...(client.backchannelLogoutUri
      ? {
          backchannel_logout_uri: client.backchannelLogoutUri,
          backchannel_logout_session_required: true,
        }
      : {}),
    handstamp_first_party: client.firstParty,
    handstamp_require_pkce: isPublic || client.requirePkce,
    handstamp_required_group: requiredGroupId ?? null,
  };
}

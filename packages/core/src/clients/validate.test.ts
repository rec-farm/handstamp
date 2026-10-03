import { describe, expect, it } from 'vitest';
import { clientDefinitionSchema, redirectUriProblem, toProviderMetadata } from './validate.ts';

const base = { clientId: 'paramtune', name: 'Paramtune', redirectUris: ['https://p.example/cb'] };

describe('redirectUriProblem', () => {
  it.each(['https://p.example/cb', 'http://localhost:3000/cb', 'http://127.0.0.1/cb'])(
    'accepts %s',
    (uri) => expect(redirectUriProblem(uri)).toBeUndefined(),
  );

  it.each([
    ['https://*.p.example/cb', /Wildcards/],
    ['http://p.example/cb', /https/],
    ['https://p.example/cb#x', /fragment/],
    ['https://user:pw@p.example/cb', /credentials/],
    ['/relative', /absolute/],
    ['myapp://cb', /https/],
  ])('rejects %s', (uri, message) => expect(redirectUriProblem(uri)).toMatch(message));
});

describe('clientDefinitionSchema', () => {
  it('applies secure defaults', () => {
    const client = clientDefinitionSchema.parse(base);
    expect(client.requirePkce).toBe(true);
    expect(client.firstParty).toBe(false);
    expect(client.tokenEndpointAuthMethod).toBe('client_secret_basic');
  });

  it('requires openid', () => {
    expect(clientDefinitionSchema.safeParse({ ...base, scopes: ['email'] }).success).toBe(false);
  });

  it('never lets a public client skip PKCE', () => {
    const result = clientDefinitionSchema.safeParse({
      ...base,
      tokenEndpointAuthMethod: 'none',
      requirePkce: false,
    });
    expect(result.success).toBe(false);
  });
});

describe('toProviderMetadata', () => {
  it('only allows refresh tokens with offline_access', () => {
    const plain = toProviderMetadata(clientDefinitionSchema.parse(base), 's');
    const offline = toProviderMetadata(
      clientDefinitionSchema.parse({ ...base, scopes: ['openid', 'offline_access'] }),
      's',
    );
    expect(plain.grant_types).toEqual(['authorization_code']);
    expect(offline.grant_types).toEqual(['authorization_code', 'refresh_token']);
  });

  it('refuses a confidential client without a secret', () => {
    expect(() => toProviderMetadata(clientDefinitionSchema.parse(base), undefined)).toThrow();
  });
});

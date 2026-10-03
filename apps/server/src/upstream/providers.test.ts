import { describe, expect, it } from 'vitest';
import { providersFromEnv } from './providers.ts';

describe('providersFromEnv', () => {
  it('seeds nothing by default', () => {
    expect(providersFromEnv({})).toEqual([]);
  });

  it('seeds GitHub with sensible defaults and GitHub Enterprise when asked', () => {
    const [github] = providersFromEnv({
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID: 'id',
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_SECRET: 'secret',
      HANDSTAMP_UPSTREAM_GITHUB_ALLOWED_ORGS: 'reciam, other',
    });
    expect(github).toMatchObject({
      slug: 'github',
      issuer: 'https://github.com',
      apiUrl: 'https://api.github.com',
      allowSignup: false,
      githubAllowedOrgs: ['reciam', 'other'],
    });
    const [ghe] = providersFromEnv({
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID: 'id',
      HANDSTAMP_UPSTREAM_GITHUB_CLIENT_SECRET: 'secret',
      HANDSTAMP_UPSTREAM_GITHUB_URL: 'https://git.example.com/',
    });
    expect(ghe).toMatchObject({
      issuer: 'https://git.example.com',
      apiUrl: 'https://git.example.com/api/v3',
    });
  });

  it('seeds any number of generic OIDC issuers, untrusted emails by default', () => {
    const seeds = providersFromEnv({
      HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_ISSUER: 'https://sso.corp.example',
      HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_CLIENT_ID: 'id',
      HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_CLIENT_SECRET: 'secret',
      HANDSTAMP_UPSTREAM_OIDC_CORP_SSO_ALLOW_SIGNUP: 'true',
    });
    expect(seeds).toEqual([
      expect.objectContaining({
        slug: 'corp-sso',
        kind: 'oidc',
        displayName: 'corp-sso',
        allowSignup: true,
        trustEmailVerified: false,
        scopes: ['openid', 'email', 'profile'],
      }),
    ]);
  });

  it('fails loudly on a missing secret or a plain-http issuer', () => {
    expect(() => providersFromEnv({ HANDSTAMP_UPSTREAM_GOOGLE_CLIENT_ID: 'id' })).toThrow(
      /google.*CLIENT_SECRET is missing/,
    );
    expect(() =>
      providersFromEnv({
        HANDSTAMP_UPSTREAM_OIDC_X_ISSUER: 'http://sso.example.com',
        HANDSTAMP_UPSTREAM_OIDC_X_CLIENT_ID: 'id',
        HANDSTAMP_UPSTREAM_OIDC_X_CLIENT_SECRET: 'secret',
      }),
    ).toThrow(/must use https/);
  });
});

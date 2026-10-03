import { describe, expect, it } from 'vitest';
import {
  signupDecision,
  trustedEmail,
  type SignupPolicy,
  type UpstreamIdentity,
} from './upstream.ts';

const person: UpstreamIdentity = {
  issuer: 'https://accounts.google.com',
  subject: '1234',
  email: 'Ada@Example.com',
  emailVerified: true,
};
const open: SignupPolicy = {
  kind: 'google',
  allowSignup: true,
  allowedEmailDomains: [],
  githubAllowedOrgs: [],
  trustEmailVerified: false,
};

describe('trustedEmail', () => {
  it('passes on verified emails from GitHub and Google, lowercased', () => {
    expect(trustedEmail(person, open)).toBe('ada@example.com');
    expect(trustedEmail(person, { ...open, kind: 'github' })).toBe('ada@example.com');
  });

  it('ignores unverified emails', () => {
    expect(trustedEmail({ ...person, emailVerified: false }, open)).toBeUndefined();
  });

  it("doesn't believe a generic issuer unless the operator trusts it", () => {
    expect(trustedEmail(person, { ...open, kind: 'oidc' })).toBeUndefined();
    expect(trustedEmail(person, { ...open, kind: 'oidc', trustEmailVerified: true })).toBe(
      'ada@example.com',
    );
  });
});

describe('signupDecision', () => {
  it('is closed by default', () => {
    expect(signupDecision(person, { ...open, allowSignup: false })).toEqual({
      allowed: false,
      reason: 'signup_closed',
    });
  });

  it('limits sign-up to allowed email domains, using only trusted emails', () => {
    const policy = { ...open, allowedEmailDomains: ['@example.com'] };
    expect(signupDecision(person, policy)).toEqual({ allowed: true });
    expect(signupDecision({ ...person, email: 'ada@evil.com' }, policy).allowed).toBe(false);
    expect(signupDecision({ ...person, emailVerified: false }, policy).allowed).toBe(false);
    // A look-alike subdomain is not the domain.
    expect(signupDecision({ ...person, email: 'ada@mail.example.com' }, policy).allowed).toBe(
      false,
    );
  });

  it('limits GitHub sign-up to members of allowed orgs', () => {
    const policy: SignupPolicy = { ...open, kind: 'github', githubAllowedOrgs: ['RECIAM'] };
    expect(signupDecision({ ...person, orgs: ['reciam', 'other'] }, policy)).toEqual({
      allowed: true,
    });
    expect(signupDecision({ ...person, orgs: ['other'] }, policy)).toEqual({
      allowed: false,
      reason: 'org',
    });
  });
});

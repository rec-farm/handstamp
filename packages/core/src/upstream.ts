// Upstream identities and the sign-up policy (docs/PLAN.md §3.1). Pure functions, no I/O.

export type UpstreamKind = 'github' | 'google' | 'oidc';

// What an upstream provider told us about a person. Identity is (issuer, subject); the rest is
// profile data that may change.
export type UpstreamIdentity = {
  issuer: string;
  subject: string;
  email?: string;
  emailVerified: boolean;
  name?: string;
  loginHint?: string;
  orgs?: string[]; // GitHub orgs, when the provider restricts by org
};

export type SignupPolicy = {
  kind: UpstreamKind;
  allowSignup: boolean;
  allowedEmailDomains: string[];
  githubAllowedOrgs: string[];
  trustEmailVerified: boolean;
};

export type SignupRefusal = 'signup_closed' | 'email_domain' | 'org';

// GitHub and Google only report emails they verified. A generic issuer's email_verified is only
// believed when the operator says so (S13: an untrusted issuer must not vouch for an email).
export function trustedEmail(
  identity: UpstreamIdentity,
  policy: Pick<SignupPolicy, 'kind' | 'trustEmailVerified'>,
) {
  if (!identity.email || !identity.emailVerified) return undefined;
  if (policy.kind === 'oidc' && !policy.trustEmailVerified) return undefined;
  return identity.email.toLowerCase();
}

export function signupDecision(
  identity: UpstreamIdentity,
  policy: SignupPolicy,
): { allowed: true } | { allowed: false; reason: SignupRefusal } {
  if (!policy.allowSignup) return { allowed: false, reason: 'signup_closed' };
  if (policy.allowedEmailDomains.length) {
    const domain = trustedEmail(identity, policy)?.split('@')[1];
    const allowed = policy.allowedEmailDomains.map((d) => d.toLowerCase().replace(/^@/, ''));
    if (!domain || !allowed.includes(domain)) return { allowed: false, reason: 'email_domain' };
  }
  if (policy.kind === 'github' && policy.githubAllowedOrgs.length) {
    const orgs = new Set((identity.orgs ?? []).map((o) => o.toLowerCase()));
    if (!policy.githubAllowedOrgs.some((o) => orgs.has(o.toLowerCase())))
      return { allowed: false, reason: 'org' };
  }
  return { allowed: true };
}

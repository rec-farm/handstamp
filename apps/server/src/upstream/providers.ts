import { and, asc, eq, notInArray } from 'drizzle-orm';
import { deriveKey, open, seal, type SignupPolicy, type UpstreamKind } from '@handstamp/core';
import { upstreamProviders, writeAudit, type Database } from '@handstamp/db';

export type UpstreamProvider = typeof upstreamProviders.$inferSelect & { clientSecret: string };

type Seed = {
  slug: string;
  kind: UpstreamKind;
  displayName: string;
  issuer: string;
  apiUrl?: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  allowSignup: boolean;
  allowedEmailDomains: string[];
  githubAllowedOrgs: string[];
  trustEmailVerified: boolean;
};

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);
const list = (value: string | undefined) =>
  (value ?? '')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);
const yes = (value: string | undefined) => value === '1' || value === 'true';

// Upstream issuers must be https (loopback http is allowed for local testing).
export function upstreamUrlProblem(value: string) {
  try {
    const url = new URL(value);
    if (url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname)))
      return undefined;
    return 'must use https://';
  } catch {
    return 'is not a URL';
  }
}

// Providers configured through env vars (docs/PLAN.md §6.3). Unset means not seeded.
export function providersFromEnv(env: Record<string, string | undefined>): Seed[] {
  const seeds: Seed[] = [];
  const github = 'HANDSTAMP_UPSTREAM_GITHUB_';
  if (env[`${github}CLIENT_ID`]) {
    const web = (env[`${github}URL`] || 'https://github.com').replace(/\/$/, '');
    seeds.push({
      slug: 'github',
      kind: 'github',
      displayName: env[`${github}NAME`] || 'GitHub',
      issuer: web,
      apiUrl: (
        env[`${github}API_URL`] ||
        (web === 'https://github.com' ? 'https://api.github.com' : `${web}/api/v3`)
      ).replace(/\/$/, ''),
      clientId: env[`${github}CLIENT_ID`]!,
      clientSecret: env[`${github}CLIENT_SECRET`] ?? '',
      scopes: [],
      allowSignup: yes(env[`${github}ALLOW_SIGNUP`]),
      allowedEmailDomains: list(env[`${github}ALLOWED_DOMAINS`]),
      githubAllowedOrgs: list(env[`${github}ALLOWED_ORGS`]),
      trustEmailVerified: true,
    });
  }
  const google = 'HANDSTAMP_UPSTREAM_GOOGLE_';
  if (env[`${google}CLIENT_ID`])
    seeds.push({
      slug: 'google',
      kind: 'google',
      displayName: env[`${google}NAME`] || 'Google',
      issuer: 'https://accounts.google.com',
      clientId: env[`${google}CLIENT_ID`]!,
      clientSecret: env[`${google}CLIENT_SECRET`] ?? '',
      scopes: ['openid', 'email', 'profile'],
      allowSignup: yes(env[`${google}ALLOW_SIGNUP`]),
      allowedEmailDomains: list(env[`${google}ALLOWED_DOMAINS`]),
      githubAllowedOrgs: [],
      trustEmailVerified: true,
    });
  for (const key of Object.keys(env)) {
    const match = /^HANDSTAMP_UPSTREAM_OIDC_([A-Z0-9_]+)_ISSUER$/.exec(key);
    if (!match) continue;
    const prefix = `HANDSTAMP_UPSTREAM_OIDC_${match[1]}_`;
    const slug = match[1].toLowerCase().replace(/_/g, '-');
    seeds.push({
      slug,
      kind: 'oidc',
      displayName: env[`${prefix}NAME`] || slug,
      issuer: env[key]!.replace(/\/$/, ''),
      clientId: env[`${prefix}CLIENT_ID`] ?? '',
      clientSecret: env[`${prefix}CLIENT_SECRET`] ?? '',
      scopes: list(env[`${prefix}SCOPES`]).length
        ? list(env[`${prefix}SCOPES`])
        : ['openid', 'email', 'profile'],
      allowSignup: yes(env[`${prefix}ALLOW_SIGNUP`]),
      allowedEmailDomains: list(env[`${prefix}ALLOWED_DOMAINS`]),
      githubAllowedOrgs: [],
      trustEmailVerified: yes(env[`${prefix}TRUST_EMAIL`]),
    });
  }
  for (const seed of seeds) {
    const problems = [
      !seed.clientId && 'CLIENT_ID is missing',
      !seed.clientSecret && 'CLIENT_SECRET is missing',
      upstreamUrlProblem(seed.issuer) && `issuer ${upstreamUrlProblem(seed.issuer)}`,
      seed.apiUrl &&
        upstreamUrlProblem(seed.apiUrl) &&
        `API URL ${upstreamUrlProblem(seed.apiUrl)}`,
    ].filter(Boolean);
    if (problems.length)
      throw new Error(`Upstream provider "${seed.slug}" is misconfigured: ${problems.join(', ')}`);
  }
  return seeds;
}

export class ProviderStore {
  readonly #key: Buffer;

  constructor(
    private readonly db: Database,
    secretKey: Buffer,
  ) {
    this.#key = deriveKey(secretKey, 'upstream-secrets');
  }

  // Env-seeded providers are synced at boot and read-only in the admin UI. One removed from the
  // environment is disabled, not deleted, so identities that used it stay attributable.
  async syncEnv(env: Record<string, string | undefined>) {
    const seeds = providersFromEnv(env);
    for (const [index, seed] of seeds.entries()) {
      const { clientSecret, ...rest } = seed;
      const columns = {
        ...rest,
        apiUrl: seed.apiUrl ?? null,
        clientSecretEnc: seal(this.#key, clientSecret, seed.slug),
        source: 'env' as const,
        enabled: true,
        sortOrder: index,
        updatedAt: new Date(),
      };
      await this.db
        .insert(upstreamProviders)
        .values(columns)
        .onConflictDoUpdate({ target: upstreamProviders.slug, set: columns });
    }
    const removed = await this.db
      .update(upstreamProviders)
      .set({ enabled: false, updatedAt: new Date() })
      .where(
        and(
          eq(upstreamProviders.source, 'env'),
          eq(upstreamProviders.enabled, true),
          seeds.length
            ? notInArray(
                upstreamProviders.slug,
                seeds.map((s) => s.slug),
              )
            : undefined,
        ),
      )
      .returning({ slug: upstreamProviders.slug });
    for (const { slug } of removed)
      await writeAudit(this.db, {
        action: 'provider.disabled',
        actorType: 'system',
        targetType: 'provider',
        targetId: slug,
        metadata: { reason: 'removed_from_env' },
      });
    return seeds.map((s) => s.slug);
  }

  // What the sign-in card shows.
  async listEnabled() {
    return this.db
      .select({
        slug: upstreamProviders.slug,
        kind: upstreamProviders.kind,
        displayName: upstreamProviders.displayName,
      })
      .from(upstreamProviders)
      .where(eq(upstreamProviders.enabled, true))
      .orderBy(asc(upstreamProviders.sortOrder), asc(upstreamProviders.displayName));
  }

  async load(slug: string): Promise<UpstreamProvider | undefined> {
    const [row] = await this.db
      .select()
      .from(upstreamProviders)
      .where(and(eq(upstreamProviders.slug, slug), eq(upstreamProviders.enabled, true)));
    if (!row) return undefined;
    return { ...row, clientSecret: open(this.#key, row.clientSecretEnc, row.slug).toString() };
  }

  async byId(id: string) {
    const [row] = await this.db
      .select()
      .from(upstreamProviders)
      .where(eq(upstreamProviders.id, id));
    return row;
  }
}

export function policyOf(provider: UpstreamProvider): SignupPolicy {
  return {
    kind: provider.kind,
    allowSignup: provider.allowSignup,
    allowedEmailDomains: provider.allowedEmailDomains,
    githubAllowedOrgs: provider.githubAllowedOrgs,
    trustEmailVerified: provider.trustEmailVerified,
  };
}

export class ReadOnlyProviderError extends Error {}

export type ProviderInput = Omit<Seed, 'clientSecret'> & { clientSecret?: string };

// Admin-managed providers (source 'db'). Env-seeded ones stay read-only.
export class ProviderAdmin {
  readonly #key: Buffer;

  constructor(
    private readonly db: Database,
    secretKey: Buffer,
  ) {
    this.#key = deriveKey(secretKey, 'upstream-secrets');
  }

  list() {
    return this.db
      .select({
        id: upstreamProviders.id,
        slug: upstreamProviders.slug,
        kind: upstreamProviders.kind,
        displayName: upstreamProviders.displayName,
        issuer: upstreamProviders.issuer,
        apiUrl: upstreamProviders.apiUrl,
        clientId: upstreamProviders.clientId,
        scopes: upstreamProviders.scopes,
        allowSignup: upstreamProviders.allowSignup,
        allowedEmailDomains: upstreamProviders.allowedEmailDomains,
        githubAllowedOrgs: upstreamProviders.githubAllowedOrgs,
        trustEmailVerified: upstreamProviders.trustEmailVerified,
        enabled: upstreamProviders.enabled,
        source: upstreamProviders.source,
        updatedAt: upstreamProviders.updatedAt,
      })
      .from(upstreamProviders)
      .orderBy(asc(upstreamProviders.sortOrder), asc(upstreamProviders.displayName));
  }

  async #row(slug: string) {
    const [row] = await this.db
      .select()
      .from(upstreamProviders)
      .where(eq(upstreamProviders.slug, slug));
    return row;
  }

  async create(input: ProviderInput) {
    if (await this.#row(input.slug)) return false;
    const { clientSecret, ...rest } = input;
    await this.db.insert(upstreamProviders).values({
      ...rest,
      apiUrl: input.apiUrl ?? null,
      clientSecretEnc: seal(this.#key, clientSecret ?? '', input.slug),
      source: 'db',
      sortOrder: 100,
    });
    return true;
  }

  // The secret is write-only: leave it out to keep the current one.
  async update(input: ProviderInput) {
    const row = await this.#row(input.slug);
    if (!row) return false;
    if (row.source !== 'db') throw new ReadOnlyProviderError();
    const { clientSecret, ...rest } = input;
    await this.db
      .update(upstreamProviders)
      .set({
        ...rest,
        apiUrl: input.apiUrl ?? null,
        ...(clientSecret ? { clientSecretEnc: seal(this.#key, clientSecret, input.slug) } : {}),
        updatedAt: new Date(),
      })
      .where(eq(upstreamProviders.slug, input.slug));
    return true;
  }

  async setEnabled(slug: string, enabled: boolean) {
    const row = await this.#row(slug);
    if (!row) return false;
    if (row.source !== 'db') throw new ReadOnlyProviderError();
    await this.db
      .update(upstreamProviders)
      .set({ enabled, updatedAt: new Date() })
      .where(eq(upstreamProviders.slug, slug));
    return true;
  }
}

import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { and, asc, eq, inArray, lte, sql } from 'drizzle-orm';
import { deriveKey, open, seal } from '@handstamp/core';
import { cookieKeys, signingKeys, writeAudit, type Database } from '@handstamp/db';

type Jwk = Record<string, unknown> & { kid?: string };
type Actor = 'system' | 'cli' | 'admin';

const ALG = 'RS256';

// RFC 7638 thumbprint, so the kid is derived from the key itself.
function thumbprint(jwk: Jwk) {
  return createHash('sha256')
    .update(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
    .digest('base64url');
}

function generateRsaKey() {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' }) as Jwk;
  const kid = thumbprint(jwk);
  const meta = { kid, alg: ALG, use: 'sig' };
  return {
    kid,
    privateJwk: { ...jwk, ...meta },
    publicJwk: { kty: jwk.kty, n: jwk.n, e: jwk.e, ...meta },
  };
}

export type RotationPolicy = {
  stageHours: number;
  rotationDays: number; // 0 turns automatic rotation off
  retireAfterSeconds: number;
};

// Signing keys: staged (published, not signing) → active (signs) → retiring (published) → retired
// (unpublished, private key wiped). Sessions and refresh tokens are opaque rows, so rotation
// never signs anyone out. See docs/PLAN.md §2.3.
export class KeyStore {
  readonly #signingKey: Buffer;
  readonly #cookieKey: Buffer;

  constructor(
    private readonly db: Database,
    secretKey: Buffer,
  ) {
    this.#signingKey = deriveKey(secretKey, 'signing-keys');
    this.#cookieKey = deriveKey(secretKey, 'cookie-keys');
  }

  async #insertSigningKey(state: 'staged' | 'active') {
    const key = generateRsaKey();
    await this.db.insert(signingKeys).values({
      kid: key.kid,
      alg: ALG,
      privateJwkEnc: seal(this.#signingKey, JSON.stringify(key.privateJwk), key.kid),
      publicJwk: key.publicJwk,
      state,
      activatedAt: state === 'active' ? new Date() : null,
    });
    return key.kid;
  }

  // First boot: nobody has cached a JWKS yet, so the first key can sign immediately.
  async ensure() {
    const [active] = await this.db
      .select({ kid: signingKeys.kid })
      .from(signingKeys)
      .where(and(eq(signingKeys.alg, ALG), eq(signingKeys.state, 'active')));
    if (!active) {
      const kid = await this.#insertSigningKey('active');
      await writeAudit(this.db, {
        action: 'key.activated',
        actorType: 'system',
        targetType: 'signing_key',
        targetId: kid,
      });
    }
    const [cookie] = await this.db
      .select({ id: cookieKeys.id })
      .from(cookieKeys)
      .where(eq(cookieKeys.state, 'active'));
    if (!cookie)
      await this.db.insert(cookieKeys).values({
        keyEnc: seal(this.#cookieKey, randomBytes(32).toString('base64url')),
        state: 'active',
      });
  }

  async stage(actor: Actor = 'cli', userId?: string) {
    const kid = await this.#insertSigningKey('staged');
    await writeAudit(this.db, {
      action: 'key.staged',
      actorType: actor,
      actorUserId: userId,
      targetType: 'signing_key',
      targetId: kid,
    });
    return kid;
  }

  // Promote the oldest staged key; the previous active key keeps being published until retire_after.
  async promote(policy: RotationPolicy, actor: Actor = 'system', userId?: string) {
    return this.db.transaction(async (tx) => {
      const [staged] = await tx
        .select({ kid: signingKeys.kid })
        .from(signingKeys)
        .where(and(eq(signingKeys.alg, ALG), eq(signingKeys.state, 'staged')))
        .orderBy(asc(signingKeys.createdAt))
        .limit(1);
      if (!staged) return undefined;
      await tx
        .update(signingKeys)
        .set({
          state: 'retiring',
          retireAfter: sql`now() + make_interval(secs => ${policy.retireAfterSeconds})`,
        })
        .where(and(eq(signingKeys.alg, ALG), eq(signingKeys.state, 'active')));
      await tx
        .update(signingKeys)
        .set({ state: 'active', activatedAt: sql`now()` })
        .where(eq(signingKeys.kid, staged.kid));
      await writeAudit(tx, {
        action: 'key.activated',
        actorType: actor,
        actorUserId: userId,
        targetType: 'signing_key',
        targetId: staged.kid,
      });
      return staged.kid;
    });
  }

  // Scheduled transitions. Returns true when the published key set changed.
  async tick(policy: RotationPolicy) {
    let changed = false;
    const retired = await this.db
      .update(signingKeys)
      .set({ state: 'retired', retiredAt: sql`now()`, privateJwkEnc: null })
      .where(and(eq(signingKeys.state, 'retiring'), lte(signingKeys.retireAfter, sql`now()`)))
      .returning({ kid: signingKeys.kid });
    for (const { kid } of retired) {
      changed = true;
      await writeAudit(this.db, {
        action: 'key.retired',
        actorType: 'system',
        targetType: 'signing_key',
        targetId: kid,
      });
    }

    const [ready] = await this.db
      .select({ kid: signingKeys.kid })
      .from(signingKeys)
      .where(
        and(
          eq(signingKeys.state, 'staged'),
          lte(signingKeys.createdAt, sql`now() - make_interval(hours => ${policy.stageHours})`),
        ),
      )
      .limit(1);
    if (ready && (await this.promote(policy))) changed = true;

    if (policy.rotationDays > 0) {
      const [due] = await this.db
        .select({ kid: signingKeys.kid })
        .from(signingKeys)
        .where(
          and(
            eq(signingKeys.state, 'active'),
            lte(
              signingKeys.activatedAt,
              sql`now() - make_interval(days => ${policy.rotationDays})`,
            ),
          ),
        );
      const [pending] = await this.db
        .select({ kid: signingKeys.kid })
        .from(signingKeys)
        .where(eq(signingKeys.state, 'staged'))
        .limit(1);
      if (due && !pending) {
        await this.stage('system');
        changed = true;
      }
    }
    return changed;
  }

  // Order matters: oidc-provider signs with the first key for an alg and publishes all of them.
  async providerJwks() {
    const rows = await this.db
      .select()
      .from(signingKeys)
      .where(inArray(signingKeys.state, ['active', 'staged', 'retiring']));
    const rank = { active: 0, staged: 1, retiring: 2, retired: 3 } as const;
    rows.sort(
      (a, b) => rank[a.state] - rank[b.state] || a.createdAt.getTime() - b.createdAt.getTime(),
    );
    const keys = rows.map(
      (row) => JSON.parse(open(this.#signingKey, row.privateJwkEnc!, row.kid).toString()) as Jwk,
    );
    return { keys, fingerprint: rows.map((row) => `${row.kid}:${row.state}`).join(',') };
  }

  async cookieSecrets() {
    const rows = await this.db
      .select()
      .from(cookieKeys)
      .where(inArray(cookieKeys.state, ['active', 'retiring']))
      .orderBy(sql`${cookieKeys.state} = 'active' DESC`, asc(cookieKeys.createdAt));
    return rows.map((row) => open(this.#cookieKey, row.keyEnc).toString());
  }

  async list() {
    return this.db
      .select({
        kid: signingKeys.kid,
        alg: signingKeys.alg,
        state: signingKeys.state,
        createdAt: signingKeys.createdAt,
        activatedAt: signingKeys.activatedAt,
        retireAfter: signingKeys.retireAfter,
      })
      .from(signingKeys)
      .orderBy(asc(signingKeys.createdAt));
  }
}

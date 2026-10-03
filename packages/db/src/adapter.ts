import { and, eq, gt, isNull, lt, or, sql } from 'drizzle-orm';
import type { Database } from './index.ts';
import { oidcPayloads } from './schema.ts';

type Payload = Record<string, unknown> & {
  grantId?: string;
  uid?: string;
  userCode?: string;
  accountId?: string;
};

export type ClientLoader = (clientId: string) => Promise<Record<string, unknown> | undefined>;

const notExpired = () => or(isNull(oidcPayloads.expiresAt), gt(oidcPayloads.expiresAt, sql`now()`));

function hydrate(row: typeof oidcPayloads.$inferSelect | undefined) {
  if (!row) return undefined;
  return row.consumedAt
    ? { ...row.payload, consumed: Math.floor(row.consumedAt.getTime() / 1000) }
    : row.payload;
}

// Storage for oidc-provider. One generic table, plus extracted columns for the lookups the
// provider and the console need. `Client` is read-only and comes from `oidc_clients`.
export function createOidcAdapter(db: Database, loadClient: ClientLoader) {
  return class PostgresAdapter {
    constructor(readonly name: string) {}

    async upsert(id: string, payload: Payload, expiresIn?: number) {
      if (this.name === 'Client') throw new Error('Clients are managed by Handstamp');
      const columns = {
        payload,
        grantId: payload.grantId ?? null,
        uid: payload.uid ?? null,
        userCode: payload.userCode ?? null,
        accountId: payload.accountId ?? null,
        expiresAt: expiresIn ? new Date(Date.now() + expiresIn * 1000) : null,
      };
      await db
        .insert(oidcPayloads)
        .values({ kind: this.name, id, ...columns })
        .onConflictDoUpdate({ target: [oidcPayloads.kind, oidcPayloads.id], set: columns });
    }

    async find(id: string) {
      if (this.name === 'Client') return loadClient(id);
      const [row] = await db
        .select()
        .from(oidcPayloads)
        .where(and(eq(oidcPayloads.kind, this.name), eq(oidcPayloads.id, id), notExpired()))
        .limit(1);
      return hydrate(row);
    }

    async findByUid(uid: string) {
      const [row] = await db
        .select()
        .from(oidcPayloads)
        .where(and(eq(oidcPayloads.kind, this.name), eq(oidcPayloads.uid, uid), notExpired()))
        .limit(1);
      return hydrate(row);
    }

    async findByUserCode(userCode: string) {
      const [row] = await db
        .select()
        .from(oidcPayloads)
        .where(
          and(eq(oidcPayloads.kind, this.name), eq(oidcPayloads.userCode, userCode), notExpired()),
        )
        .limit(1);
      return hydrate(row);
    }

    async consume(id: string) {
      await db
        .update(oidcPayloads)
        .set({ consumedAt: sql`now()` })
        .where(and(eq(oidcPayloads.kind, this.name), eq(oidcPayloads.id, id)));
    }

    async destroy(id: string) {
      await db
        .delete(oidcPayloads)
        .where(and(eq(oidcPayloads.kind, this.name), eq(oidcPayloads.id, id)));
    }

    async revokeByGrantId(grantId: string) {
      await db.delete(oidcPayloads).where(eq(oidcPayloads.grantId, grantId));
    }
  };
}

export async function deleteExpiredPayloads(db: Database) {
  const deleted = await db
    .delete(oidcPayloads)
    .where(lt(oidcPayloads.expiresAt, sql`now()`))
    .returning({ id: oidcPayloads.id });
  return deleted.length;
}

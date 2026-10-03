import { and, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';
import type Provider from 'oidc-provider';
import { oidcClients, oidcPayloads, type Database } from '@handstamp/db';

type Authorization = { sid?: string; grantId?: string };
type SessionPayload = {
  uid: string;
  accountId: string;
  loginTs?: number;
  amr?: string[];
  exp?: number;
  authorizations?: Record<string, Authorization>;
};

const live = () => or(isNull(oidcPayloads.expiresAt), gt(oidcPayloads.expiresAt, sql`now()`));

// SSO sessions as oidc-provider stores them, read and ended from outside a request (sign out
// everywhere, revoking one device, disabling a user).
export class Sessions {
  constructor(
    private readonly db: Database,
    private readonly provider: () => Provider,
    private readonly log: { warn(obj: object, msg: string): void },
  ) {}

  async #rows(accountId: string, uid?: string) {
    const rows = await this.db
      .select({ payload: oidcPayloads.payload })
      .from(oidcPayloads)
      .where(
        and(
          eq(oidcPayloads.kind, 'Session'),
          eq(oidcPayloads.accountId, accountId),
          uid ? eq(oidcPayloads.uid, uid) : undefined,
          live(),
        ),
      );
    return rows.map((r) => r.payload as unknown as SessionPayload);
  }

  async exists(accountId: string, uid: string) {
    return (await this.#rows(accountId, uid)).length > 0;
  }

  // The OP session a client's `sid` belongs to (sid is per client inside the session).
  async uidForSid(accountId: string, clientId: string, sid: string) {
    const [row] = await this.db
      .select({ uid: oidcPayloads.uid })
      .from(oidcPayloads)
      .where(
        and(
          eq(oidcPayloads.kind, 'Session'),
          eq(oidcPayloads.accountId, accountId),
          sql`${oidcPayloads.payload} -> 'authorizations' -> ${clientId} ->> 'sid' = ${sid}`,
          live(),
        ),
      );
    return row?.uid ?? undefined;
  }

  async list(accountId: string) {
    const sessions = await this.#rows(accountId);
    const clientIds = [...new Set(sessions.flatMap((s) => Object.keys(s.authorizations ?? {})))];
    const names = new Map(
      clientIds.length
        ? (
            await this.db
              .select({ id: oidcClients.clientId, name: oidcClients.name })
              .from(oidcClients)
              .where(inArray(oidcClients.clientId, clientIds))
          ).map((c) => [c.id, c.name])
        : [],
    );
    return sessions
      .map((s) => ({
        uid: s.uid,
        signedInAt: s.loginTs ? new Date(s.loginTs * 1000).toISOString() : null,
        expiresAt: s.exp ? new Date(s.exp * 1000).toISOString() : null,
        method: s.amr?.includes('pop') ? 'passkey' : s.amr?.length ? s.amr.join(' ') : 'other',
        apps: Object.keys(s.authorizations ?? {}).map((id) => ({
          clientId: id,
          name: names.get(id) ?? id,
        })),
      }))
      .sort((a, b) => (b.signedInAt ?? '').localeCompare(a.signedInAt ?? ''));
  }

  // Ends sessions: every app in them gets a back-channel logout, and the grants (with their
  // access and refresh tokens) are revoked. With `uid`, only that session.
  async end(accountId: string, uid?: string) {
    const sessions = await this.#rows(accountId, uid);
    const grantIds: string[] = [];
    for (const session of sessions)
      for (const [clientId, auth] of Object.entries(session.authorizations ?? {})) {
        if (auth.grantId) grantIds.push(auth.grantId);
        if (auth.sid) void this.#backchannel(clientId, accountId, auth.sid);
      }
    if (!uid) {
      // Sign out everywhere also revokes grants that outlive sessions (offline_access).
      const grants = await this.db
        .select({ id: oidcPayloads.id })
        .from(oidcPayloads)
        .where(and(eq(oidcPayloads.kind, 'Grant'), eq(oidcPayloads.accountId, accountId)));
      grantIds.push(...grants.map((g) => g.id));
    }
    await this.db.transaction(async (tx) => {
      if (grantIds.length) {
        await tx.delete(oidcPayloads).where(inArray(oidcPayloads.grantId, grantIds));
        await tx
          .delete(oidcPayloads)
          .where(and(eq(oidcPayloads.kind, 'Grant'), inArray(oidcPayloads.id, grantIds)));
      }
      await tx
        .delete(oidcPayloads)
        .where(
          and(
            eq(oidcPayloads.kind, 'Session'),
            eq(oidcPayloads.accountId, accountId),
            uid ? eq(oidcPayloads.uid, uid) : undefined,
          ),
        );
    });
    return sessions.length;
  }

  async #backchannel(clientId: string, accountId: string, sid: string) {
    try {
      // backchannelLogout exists on oidc-provider's Client but is missing from its type definitions.
      const client = (await this.provider().Client.find(clientId)) as
        | {
            backchannelLogoutUri?: string;
            backchannelLogout(sub: string, sid: string): Promise<void>;
          }
        | undefined;
      if (client?.backchannelLogoutUri) await client.backchannelLogout(accountId, sid);
    } catch (error) {
      this.log.warn({ err: error, clientId }, 'back-channel logout failed');
    }
  }
}

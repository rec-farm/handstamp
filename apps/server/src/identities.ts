import { and, asc, count, eq, sql } from 'drizzle-orm';
import { trustedEmail, type UpstreamIdentity } from '@handstamp/core';
import {
  identities,
  passkeys,
  upstreamProviders,
  users,
  writeAudit,
  type Database,
} from '@handstamp/db';
import { policyOf, type UpstreamProvider } from './upstream/providers.ts';

type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];

export class LastMethodError extends Error {}
export class IdentityTakenError extends Error {}

// Every way a user can sign in. Nobody may remove their last one (docs/PLAN.md §3.2).
export async function signInMethodCount(db: Database | Tx, userId: string) {
  const [[p], [i]] = await Promise.all([
    db.select({ n: count() }).from(passkeys).where(eq(passkeys.userId, userId)),
    db.select({ n: count() }).from(identities).where(eq(identities.userId, userId)),
  ]);
  return p.n + i.n;
}

// Locks the user row so two concurrent removals can't both see "one more left".
export async function lockUser(tx: Tx, userId: string) {
  await tx.execute(sql`SELECT id FROM users WHERE id = ${userId} FOR UPDATE`);
}

export class IdentityStore {
  constructor(private readonly db: Database) {}

  // The only lookup used for sign-in: (issuer, subject). Never email (S13).
  async find(issuer: string, subject: string) {
    const [row] = await this.db
      .select()
      .from(identities)
      .where(and(eq(identities.issuer, issuer), eq(identities.subject, subject)));
    return row;
  }

  listForUser(userId: string) {
    return this.db
      .select({
        id: identities.id,
        provider: upstreamProviders.slug,
        providerName: upstreamProviders.displayName,
        loginHint: identities.loginHint,
        email: identities.email,
        linkedAt: identities.linkedAt,
        lastUsedAt: identities.lastUsedAt,
      })
      .from(identities)
      .innerJoin(upstreamProviders, eq(upstreamProviders.id, identities.providerId))
      .where(eq(identities.userId, userId))
      .orderBy(asc(identities.linkedAt));
  }

  async touch(id: string, identity: UpstreamIdentity) {
    await this.db
      .update(identities)
      .set({
        lastUsedAt: sql`now()`,
        email: identity.email ?? null,
        emailVerified: identity.emailVerified,
        loginHint: identity.loginHint ?? null,
      })
      .where(eq(identities.id, id));
  }

  async link(
    db: Database | Tx,
    userId: string,
    provider: UpstreamProvider,
    identity: UpstreamIdentity,
  ) {
    const existing = await this.find(identity.issuer, identity.subject);
    if (existing && existing.userId !== userId) throw new IdentityTakenError();
    if (existing) return existing.id;
    const [row] = await db
      .insert(identities)
      .values({
        userId,
        providerId: provider.id,
        issuer: identity.issuer,
        subject: identity.subject,
        email: identity.email ?? null,
        emailVerified: identity.emailVerified,
        loginHint: identity.loginHint ?? null,
        lastUsedAt: sql`now()`,
      })
      .onConflictDoNothing()
      .returning({ id: identities.id });
    if (!row) throw new IdentityTakenError(); // lost a race to another account
    return row.id;
  }

  async unlink(userId: string, id: string) {
    return this.db.transaction(async (tx) => {
      await lockUser(tx, userId);
      const [target] = await tx
        .select({ id: identities.id })
        .from(identities)
        .where(and(eq(identities.id, id), eq(identities.userId, userId)));
      if (!target) return false;
      if ((await signInMethodCount(tx, userId)) <= 1) throw new LastMethodError();
      await tx.update(users).set({ emailIdentityId: null }).where(eq(users.emailIdentityId, id));
      await tx.delete(identities).where(eq(identities.id, id));
      return true;
    });
  }

  // A new person arriving through an upstream provider (sign-up allowed, or an invite).
  // Their email is only kept when it's trustworthy and no other user already holds it verified,
  // so a relying party keyed on email can never see two people with one address (§2.1).
  async createUser(provider: UpstreamProvider, identity: UpstreamIdentity, via: string) {
    return this.db.transaction(async (tx) => {
      const email = trustedEmail(identity, policyOf(provider));
      const holder = email
        ? (
            await tx
              .select({ id: users.id })
              .from(users)
              .where(and(sql`lower(${users.email}) = ${email}`, eq(users.emailVerified, true)))
          )[0]
        : undefined;
      const [user] = await tx
        .insert(users)
        .values({
          displayName: identity.name || identity.loginHint || email?.split('@')[0] || 'New user',
          email: holder ? null : (email ?? null),
          emailVerified: Boolean(email && !holder),
        })
        .returning({ id: users.id });
      const identityId = await this.link(tx, user.id, provider, identity);
      if (email && !holder)
        await tx.update(users).set({ emailIdentityId: identityId }).where(eq(users.id, user.id));
      await writeAudit(tx, {
        action: 'user.created',
        actorType: 'user',
        actorUserId: user.id,
        targetType: 'user',
        targetId: user.id,
        metadata: { via, provider: provider.slug },
      });
      if (holder)
        await writeAudit(tx, {
          action: 'user.email_conflict',
          actorType: 'system',
          targetType: 'user',
          targetId: user.id,
          metadata: { provider: provider.slug, held_by: holder.id },
        });
      return user.id;
    });
  }
}

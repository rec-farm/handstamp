import { and, eq, gt, isNull, or, sql } from 'drizzle-orm';
import { randomToken, sha256 } from '@handstamp/core';
import type { AuditEntry } from '@handstamp/core';
import { enrollmentTokens, passkeys, users, writeAudit, type Database } from '@handstamp/db';

type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];

export const INVITE_DAYS = 7;
export const RECOVERY_MINUTES = 30;

export type EnrollmentPurpose = 'invite' | 'recovery';
export type Enrollment = typeof enrollmentTokens.$inferSelect & { purpose: EnrollmentPurpose };

const hash = (token: string) => sha256(`enroll:${token.trim()}`);

// One-time links (docs/PLAN.md §3.2): invites let a new person create their first sign-in
// method while sign-up is closed; recovery links let someone who lost every method add a new
// one. Opening a link never signs anyone in by itself: a new method must be created first.
export class Enrollments {
  constructor(
    private readonly db: Database,
    private readonly issuer: URL,
  ) {}

  link(token: string) {
    // The token rides in the fragment, so it never reaches server logs or Referer headers.
    return `${this.issuer.origin}/enroll#${token}`;
  }

  async createInvite(createdBy: { userId?: string; actorType: AuditEntry['actorType'] }) {
    const token = randomToken(32);
    const [row] = await this.db
      .insert(enrollmentTokens)
      .values({
        tokenHash: hash(token),
        purpose: 'invite',
        createdBy: createdBy.userId,
        expiresAt: new Date(Date.now() + INVITE_DAYS * 24 * 3600 * 1000),
      })
      .returning({ id: enrollmentTokens.id });
    await writeAudit(this.db, {
      action: 'invite.created',
      actorType: createdBy.actorType,
      actorUserId: createdBy.userId,
      targetType: 'enrollment',
      targetId: row.id,
    });
    return { token, link: this.link(token), expiresInDays: INVITE_DAYS };
  }

  async createRecovery(
    userId: string,
    options: {
      revokeOtherMethods: boolean;
      createdBy?: string;
      actorType: AuditEntry['actorType'];
    },
  ) {
    const token = randomToken(32);
    await this.db.transaction(async (tx) => {
      // Only the newest recovery link for a user works.
      await tx
        .update(enrollmentTokens)
        .set({ expiresAt: sql`now()` })
        .where(
          and(
            eq(enrollmentTokens.userId, userId),
            eq(enrollmentTokens.purpose, 'recovery'),
            isNull(enrollmentTokens.consumedAt),
          ),
        );
      await tx.insert(enrollmentTokens).values({
        tokenHash: hash(token),
        purpose: 'recovery',
        userId,
        createdBy: options.createdBy,
        revokeOtherMethods: options.revokeOtherMethods,
        expiresAt: new Date(Date.now() + RECOVERY_MINUTES * 60 * 1000),
      });
      await writeAudit(tx, {
        action: 'recovery.issued',
        actorType: options.actorType,
        actorUserId: options.createdBy,
        targetType: 'user',
        targetId: userId,
        metadata: { revoke_other_methods: options.revokeOtherMethods },
      });
    });
    return { token, link: this.link(token), expiresInMinutes: RECOVERY_MINUTES };
  }

  async find(token: string): Promise<Enrollment | undefined> {
    const [row] = await this.db
      .select()
      .from(enrollmentTokens)
      .where(
        and(
          eq(enrollmentTokens.tokenHash, hash(token)),
          or(eq(enrollmentTokens.purpose, 'invite'), eq(enrollmentTokens.purpose, 'recovery')),
          isNull(enrollmentTokens.consumedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      );
    return row as Enrollment | undefined;
  }

  async byId(id: string): Promise<Enrollment | undefined> {
    const [row] = await this.db
      .select()
      .from(enrollmentTokens)
      .where(
        and(
          eq(enrollmentTokens.id, id),
          isNull(enrollmentTokens.consumedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      );
    return row as Enrollment | undefined;
  }

  // Single use: inside the caller's transaction, so a failed enrollment leaves the link usable.
  async consume(tx: Tx, id: string, userId?: string) {
    const [row] = await tx
      .update(enrollmentTokens)
      .set({ consumedAt: sql`now()`, consumedByUserId: userId ?? null })
      .where(
        and(
          eq(enrollmentTokens.id, id),
          isNull(enrollmentTokens.consumedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      )
      .returning();
    return row as Enrollment | undefined;
  }

  // Invites are consumed before the account exists; this records who used it.
  async recordConsumer(id: string, userId: string) {
    await this.db
      .update(enrollmentTokens)
      .set({ consumedByUserId: userId })
      .where(eq(enrollmentTokens.id, id));
  }

  // "I lost my device": a recovery link can take every old passkey with it.
  async revokeOtherPasskeys(tx: Tx, userId: string, keepId?: string) {
    await tx
      .delete(passkeys)
      .where(
        and(eq(passkeys.userId, userId), keepId ? sql`${passkeys.id} <> ${keepId}` : undefined),
      );
  }

  async userName(userId: string) {
    const [user] = await this.db
      .select({ name: users.displayName })
      .from(users)
      .where(eq(users.id, userId));
    return user?.name;
  }
}

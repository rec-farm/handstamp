import { and, eq, gt, isNull, sql } from 'drizzle-orm';
import { hashSetupCode, newSetupCode, randomToken } from '@handstamp/core';
import {
  enrollmentTokens,
  instanceSettings,
  users,
  writeAudit,
  type Database,
} from '@handstamp/db';
import type { PasskeyStore, VerifiedPasskey } from './passkeys.ts';

export const SETUP_CODE_MINUTES = 60;

export class SetupError extends Error {
  constructor(
    readonly code: 'already_claimed' | 'code_required',
    message: string,
  ) {
    super(message);
  }
}

// First-run setup (docs/PLAN.md §1.4 C): whoever proves the code printed in the server logs
// creates the first admin, with a passkey, in one transaction.
export class Setup {
  constructor(
    private readonly db: Database,
    private readonly passkeys: PasskeyStore,
  ) {}

  async claimed() {
    const [row] = await this.db
      .select({ at: instanceSettings.setupCompletedAt })
      .from(instanceSettings);
    return Boolean(row?.at);
  }

  // A fresh code on every boot (and from the CLI) until someone claims the instance. Earlier
  // unused codes stop working.
  async issueCode() {
    if (await this.claimed()) return undefined;
    const code = newSetupCode();
    await this.db.transaction(async (tx) => {
      await tx
        .delete(enrollmentTokens)
        .where(and(eq(enrollmentTokens.purpose, 'setup'), isNull(enrollmentTokens.consumedAt)));
      await tx.insert(enrollmentTokens).values({
        tokenHash: hashSetupCode(code),
        purpose: 'setup',
        expiresAt: new Date(Date.now() + SETUP_CODE_MINUTES * 60 * 1000),
      });
    });
    return code;
  }

  // Binds a valid code to the interaction that proved it. Constant-time by construction: the
  // lookup is by hash.
  async verifyCode(code: string, interactionUid: string) {
    const rows = await this.db
      .update(enrollmentTokens)
      .set({ boundTo: interactionUid })
      .where(
        and(
          eq(enrollmentTokens.tokenHash, hashSetupCode(code)),
          eq(enrollmentTokens.purpose, 'setup'),
          isNull(enrollmentTokens.consumedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      )
      .returning({ id: enrollmentTokens.id });
    return rows.length > 0;
  }

  async isVerified(interactionUid: string) {
    const [row] = await this.db
      .select({ id: enrollmentTokens.id })
      .from(enrollmentTokens)
      .where(
        and(
          eq(enrollmentTokens.boundTo, interactionUid),
          eq(enrollmentTokens.purpose, 'setup'),
          isNull(enrollmentTokens.consumedAt),
          gt(enrollmentTokens.expiresAt, sql`now()`),
        ),
      );
    return Boolean(row);
  }

  newUserHandle() {
    return randomToken(32);
  }

  async claim(
    interactionUid: string,
    profile: { displayName: string; email?: string; handle: string },
    passkey: VerifiedPasskey,
    passkeyName: string,
  ) {
    return this.db.transaction(async (tx) => {
      // Serialises concurrent claims: only the first one sees an unclaimed instance.
      const [settings] = await tx
        .execute<{ setup_completed_at: Date | null }>(
          sql`SELECT setup_completed_at FROM instance_settings WHERE id = 1 FOR UPDATE`,
        )
        .then((r) => r.rows);
      if (settings?.setup_completed_at)
        throw new SetupError('already_claimed', 'This Handstamp instance already has an admin.');
      const [token] = await tx
        .update(enrollmentTokens)
        .set({ consumedAt: sql`now()` })
        .where(
          and(
            eq(enrollmentTokens.boundTo, interactionUid),
            eq(enrollmentTokens.purpose, 'setup'),
            isNull(enrollmentTokens.consumedAt),
            gt(enrollmentTokens.expiresAt, sql`now()`),
          ),
        )
        .returning({ id: enrollmentTokens.id });
      if (!token)
        throw new SetupError('code_required', 'Enter the setup code from the server logs first.');
      const [user] = await tx
        .insert(users)
        .values({
          displayName: profile.displayName,
          email: profile.email || null,
          emailVerified: false,
          isAdmin: true,
          webauthnUserHandle: profile.handle,
        })
        .returning({ id: users.id });
      await this.passkeys.add(tx, user.id, passkey, passkeyName);
      await tx
        .update(enrollmentTokens)
        .set({ consumedByUserId: user.id })
        .where(eq(enrollmentTokens.id, token.id));
      await tx
        .update(instanceSettings)
        .set({ setupCompletedAt: sql`now()`, updatedAt: sql`now()` })
        .where(eq(instanceSettings.id, 1));
      await writeAudit(tx, {
        action: 'instance.claimed',
        actorType: 'user',
        actorUserId: user.id,
        targetType: 'user',
        targetId: user.id,
      });
      return user.id;
    });
  }
}

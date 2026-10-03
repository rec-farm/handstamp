import { and, asc, eq, gt, isNull, sql } from 'drizzle-orm';
import { LastMethodError, lockUser, signInMethodCount } from './identities.ts';
import { CHALLENGE_TTL_SECONDS, PasskeyError } from '@handstamp/core';
import { passkeys, webauthnChallenges, type ChallengePurpose, type Database } from '@handstamp/db';

export { LastMethodError } from './identities.ts';

export type VerifiedPasskey = {
  credentialId: string;
  publicKey: Buffer;
  signCount: number;
  transports: string[];
  aaguid: string;
  deviceType: 'singleDevice' | 'multiDevice';
  backedUp: boolean;
};

// Storage for passkeys and their WebAuthn challenges. The ceremony itself lives in @handstamp/core.
export class PasskeyStore {
  constructor(private readonly db: Database) {}

  async saveChallenge(
    purpose: ChallengePurpose,
    binding: string,
    challenge: string,
    extra: { userId?: string; pending?: Record<string, string> } = {},
  ) {
    await this.db.insert(webauthnChallenges).values({
      purpose,
      binding,
      challenge,
      userId: extra.userId,
      pending: extra.pending ?? {},
      expiresAt: new Date(Date.now() + CHALLENGE_TTL_SECONDS * 1000),
    });
  }

  // Single use: the first caller gets the row, everyone after gets nothing.
  async consumeChallenge(purpose: ChallengePurpose, binding: string, challenge: string) {
    const [row] = await this.db
      .update(webauthnChallenges)
      .set({ consumedAt: sql`now()` })
      .where(
        and(
          eq(webauthnChallenges.challenge, challenge),
          eq(webauthnChallenges.purpose, purpose),
          eq(webauthnChallenges.binding, binding),
          isNull(webauthnChallenges.consumedAt),
          gt(webauthnChallenges.expiresAt, sql`now()`),
        ),
      )
      .returning();
    return row;
  }

  async findByCredentialId(credentialId: string) {
    const [row] = await this.db
      .select()
      .from(passkeys)
      .where(eq(passkeys.credentialId, credentialId));
    return row;
  }

  listForUser(userId: string) {
    return this.db
      .select()
      .from(passkeys)
      .where(eq(passkeys.userId, userId))
      .orderBy(asc(passkeys.createdAt));
  }

  async add(db: Pick<Database, 'insert'>, userId: string, passkey: VerifiedPasskey, name: string) {
    const [row] = await db
      .insert(passkeys)
      .values({
        userId,
        credentialId: passkey.credentialId,
        publicKey: passkey.publicKey,
        signCount: passkey.signCount,
        transports: passkey.transports,
        aaguid: passkey.aaguid === '00000000-0000-0000-0000-000000000000' ? null : passkey.aaguid,
        deviceType: passkey.deviceType,
        backedUp: passkey.backedUp,
        name,
      })
      .returning({ id: passkeys.id });
    return row.id;
  }

  async recordUse(id: string, signCount: number, backedUp: boolean) {
    await this.db
      .update(passkeys)
      .set({ signCount, backedUp, lastUsedAt: sql`now()` })
      .where(eq(passkeys.id, id));
  }

  async rename(userId: string, id: string, name: string) {
    const rows = await this.db
      .update(passkeys)
      .set({ name })
      .where(and(eq(passkeys.id, id), eq(passkeys.userId, userId)))
      .returning({ id: passkeys.id });
    return rows.length > 0;
  }

  // Nobody can remove their last way in: passkeys and linked identities both count.
  async remove(userId: string, id: string) {
    return this.db.transaction(async (tx) => {
      await lockUser(tx, userId);
      const [target] = await tx
        .select({ id: passkeys.id, name: passkeys.name })
        .from(passkeys)
        .where(and(eq(passkeys.id, id), eq(passkeys.userId, userId)));
      if (!target) return undefined;
      if ((await signInMethodCount(tx, userId)) <= 1) throw new LastMethodError();
      await tx.delete(passkeys).where(eq(passkeys.id, id));
      return target;
    });
  }
}

export function cleanName(name: unknown, taken: string[] = []) {
  const trimmed = typeof name === 'string' ? name.trim().replace(/\s+/g, ' ').slice(0, 56) : '';
  const base = trimmed || 'Passkey';
  // Two "Passkey on Mac"s are indistinguishable on the account page; number the newcomer.
  let candidate = base;
  for (let n = 2; taken.includes(candidate); n++) candidate = `${base} ${n}`;
  return candidate;
}

export function passkeyMessage(error: unknown) {
  if (error instanceof PasskeyError && error.code === 'counter')
    return 'This passkey looks like a copy of another one, so we stopped. Use a different passkey or ask your admin.';
  return "We couldn't verify that passkey. Try again, or use a different one.";
}

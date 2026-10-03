import type { FastifyReply, FastifyRequest } from 'fastify';
import type Provider from 'oidc-provider';
import { eq, sql } from 'drizzle-orm';
import { ipPrefix } from '@handstamp/core';
import { users, writeAudit, type Database } from '@handstamp/db';

// Passkey sign-ins prove possession (pop) and user verification (user): RFC 8176.
export const PASSKEY_AMR = ['pop', 'user', 'mfa'];

// Ends an interaction with a signed-in account and records it. Returns where the browser goes next.
export async function completeSignIn(
  deps: { provider: () => Provider; db: Database },
  req: FastifyRequest,
  reply: FastifyReply,
  sign: { clientId: string; accountId: string; method: string; amr?: string[] },
) {
  const redirectTo = await deps.provider().interactionResult(req.raw, reply.raw, {
    login: { accountId: sign.accountId, ...(sign.amr ? { amr: sign.amr } : {}), remember: true },
  });
  await deps.db
    .update(users)
    .set({ lastSignInAt: sql`now()` })
    .where(eq(users.id, sign.accountId));
  await writeAudit(deps.db, {
    action: 'auth.sign_in.succeeded',
    actorType: 'user',
    actorUserId: sign.accountId,
    clientId: sign.clientId,
    ipPrefix: ipPrefix(req.ip),
    userAgent: req.headers['user-agent'],
    metadata: { method: sign.method },
  });
  return redirectTo;
}

export async function recordRefusal(
  db: Database,
  req: FastifyRequest,
  details: { clientId?: string; method: string; reason: string; userId?: string },
) {
  await writeAudit(db, {
    action: details.method === 'passkey' ? 'auth.sign_in.failed' : 'auth.sign_in.refused',
    actorType: 'user',
    actorUserId: details.userId,
    clientId: details.clientId,
    ipPrefix: ipPrefix(req.ip),
    userAgent: req.headers['user-agent'],
    metadata: { method: details.method, reason: details.reason },
  });
}

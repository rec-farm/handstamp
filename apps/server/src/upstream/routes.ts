import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type Provider from 'oidc-provider';
import { and, eq } from 'drizzle-orm';
import { signupDecision, type UpstreamIdentity } from '@handstamp/core';
import { users, writeAudit, type Database } from '@handstamp/db';
import type { Enrollments } from '../enrollment.ts';
import { SealedCookie } from '../http/sealed-cookie.ts';
import type { RateLimits } from '../http/rate-limit.ts';
import { IdentityTakenError, type IdentityStore } from '../identities.ts';
import { completeSignIn, recordRefusal } from '../interaction/sign-in.ts';
import type { Sessions } from '../sessions.ts';
import { beginUpstream, finishUpstream, UpstreamError, type Pending } from './client.ts';
import { policyOf, type ProviderStore } from './providers.ts';

type UpstreamState = Pending & {
  purpose: 'login' | 'link';
  slug: string;
  uid?: string; // login: the interaction to resume
  sub?: string; // link: the signed-in user…
  consoleUid?: string; // …and their console session
  identity?: UpstreamIdentity; // set once the provider answered
};

export type EnrollState = { enrollmentId: string };

export type UpstreamDeps = {
  provider: () => Provider;
  db: Database;
  issuer: URL;
  secretKey: Buffer;
  providers: ProviderStore;
  identities: IdentityStore;
  enrollments: Enrollments;
  enrollCookie: SealedCookie<EnrollState>;
  sessions: Sessions;
  limits: RateLimits;
  consoleSession: (req: FastifyRequest) => Promise<{ sub: string; uid: string } | undefined>;
};

// The redirect half of an upstream sign-in, shared with the account page (linking).
export function createUpstreamFlow(deps: Pick<UpstreamDeps, 'issuer' | 'secretKey' | 'providers'>) {
  const state = new SealedCookie<UpstreamState>(
    deps.secretKey,
    deps.issuer,
    'hs_upstream',
    10 * 60,
  );
  async function begin(
    reply: FastifyReply,
    slug: string,
    extra: Omit<UpstreamState, keyof Pending | 'slug'>,
  ) {
    const provider = await deps.providers.load(slug);
    if (!provider) return undefined;
    const { url, pending } = await beginUpstream(
      provider,
      `${deps.issuer.origin}/upstream/${slug}/callback`,
    );
    state.write(reply, { ...pending, ...extra, slug });
    return url;
  }
  return {
    state,
    begin,
    // Start linking another identity to the signed-in user (account page, after step-up).
    startLink: (reply: FastifyReply, slug: string, session: { sub: string; uid: string }) =>
      begin(reply, slug, { purpose: 'link', sub: session.sub, consoleUid: session.uid }),
  };
}

export type UpstreamFlow = ReturnType<typeof createUpstreamFlow>;

// Sign-in and linking through GitHub, Google or a generic OIDC issuer (docs/PLAN.md §1.4 B).
// The provider calls back to a fixed URL, which can't see the path-scoped interaction cookie,
// so the result is parked in a sealed cookie and finished under /interaction/:uid (M1-2).
export async function upstreamRoutes(
  app: FastifyInstance,
  deps: UpstreamDeps & { flow: UpstreamFlow },
) {
  const { state, begin } = deps.flow;
  const back = (uid: string, error: string) => `/interaction/${uid}?error=${error}`;

  app.get<{ Params: { uid: string; slug: string } }>(
    '/interaction/:uid/upstream/:slug',
    { config: { rateLimit: deps.limits.authorization } },
    async (req, reply) => {
      let interaction;
      try {
        interaction = await deps.provider().interactionDetails(req.raw, reply.raw);
      } catch {
        return reply.redirect('/error?code=session_not_found', 303);
      }
      if (interaction.uid !== req.params.uid || interaction.prompt.name !== 'login')
        return reply.redirect(`/interaction/${interaction.uid}`, 303);
      const url = await begin(reply, req.params.slug, { purpose: 'login', uid: interaction.uid });
      return reply.redirect(url ?? back(interaction.uid, 'provider_unavailable'), 303);
    },
  );

  app.get<{ Params: { slug: string } }>(
    '/upstream/:slug/callback',
    { config: { rateLimit: deps.limits.authorization } },
    async (req, reply) => {
      const pending = state.read(req);
      state.clear(reply);
      if (!pending || pending.slug !== req.params.slug)
        return reply.redirect('/error?code=session_not_found', 303);
      const fail = (code: string) =>
        reply.redirect(
          pending.purpose === 'link' ? `/account?error=${code}` : back(pending.uid!, code),
          303,
        );
      const provider = await deps.providers.load(pending.slug);
      if (!provider) return fail('provider_unavailable');
      let identity;
      try {
        identity = await finishUpstream(provider, new URL(req.url, deps.issuer), pending);
      } catch (error) {
        req.log.warn({ err: error, provider: provider.slug }, 'upstream sign-in failed');
        return fail(error instanceof UpstreamError ? error.code : 'upstream_failed');
      }

      if (pending.purpose === 'link') {
        // Linking needs the same signed-in console session that started it (S14).
        const session = await deps.consoleSession(req);
        if (!session || session.sub !== pending.sub || session.uid !== pending.consoleUid)
          return fail('link_expired');
        try {
          await deps.identities.link(deps.db, session.sub, provider, identity);
        } catch (error) {
          if (!(error instanceof IdentityTakenError)) throw error;
          await writeAudit(deps.db, {
            action: 'identity.link_refused',
            actorType: 'user',
            actorUserId: session.sub,
            metadata: { provider: provider.slug, reason: 'identity_taken' },
          });
          return fail('identity_taken');
        }
        await writeAudit(deps.db, {
          action: 'identity.linked',
          actorType: 'user',
          actorUserId: session.sub,
          targetType: 'identity',
          targetId: `${identity.issuer}#${identity.subject}`,
          metadata: { provider: provider.slug },
        });
        return reply.redirect(`/account?linked=${provider.slug}`, 303);
      }

      state.write(reply, { ...pending, identity });
      return reply.redirect(`/interaction/${pending.uid}/upstream/complete`, 303);
    },
  );

  app.get<{ Params: { uid: string } }>(
    '/interaction/:uid/upstream/complete',
    async (req, reply) => {
      const done = state.read(req);
      state.clear(reply);
      let interaction;
      try {
        interaction = await deps.provider().interactionDetails(req.raw, reply.raw);
      } catch {
        return reply.redirect('/error?code=session_not_found', 303);
      }
      const uid = interaction.uid;
      if (!done?.identity || done.uid !== uid || uid !== req.params.uid)
        return reply.redirect(back(uid, 'upstream_expired'), 303);
      const provider = await deps.providers.load(done.slug);
      if (!provider) return reply.redirect(back(uid, 'provider_unavailable'), 303);
      const clientId = interaction.params.client_id as string;
      const identity = done.identity;
      const refuse = async (reason: string, userId?: string) => {
        await recordRefusal(deps.db, req, { clientId, method: provider.slug, reason, userId });
        return reply.redirect(back(uid, reason), 303);
      };

      const enrollState = deps.enrollCookie.read(req);
      const enrollment = enrollState
        ? await deps.enrollments.byId(enrollState.enrollmentId)
        : undefined;
      const existing = await deps.identities.find(identity.issuer, identity.subject);
      let accountId: string;
      let method = provider.slug;

      if (existing) {
        // A recovery link for one person can't be finished with someone else's identity.
        if (enrollment?.purpose === 'recovery' && existing.userId !== enrollment.userId)
          return refuse('identity_taken', existing.userId);
        accountId = existing.userId;
        if (enrollment?.purpose === 'recovery') {
          await finishRecovery(enrollment.id, accountId, enrollment.revokeOtherMethods);
          deps.enrollCookie.clear(reply);
          method = `${provider.slug}_recovery`;
        }
        await deps.identities.touch(existing.id, identity);
      } else if (enrollment?.purpose === 'invite') {
        const consumed = await deps.db.transaction((tx) =>
          deps.enrollments.consume(tx, enrollment.id),
        );
        if (!consumed) return refuse('enrollment_expired');
        accountId = await deps.identities.createUser(provider, identity, 'invite');
        await deps.enrollments.recordConsumer(enrollment.id, accountId);
        await writeAudit(deps.db, {
          action: 'invite.used',
          actorType: 'user',
          actorUserId: accountId,
          targetType: 'enrollment',
          targetId: enrollment.id,
        });
        deps.enrollCookie.clear(reply);
      } else if (enrollment?.purpose === 'recovery') {
        accountId = enrollment.userId!;
        try {
          await deps.identities.link(deps.db, accountId, provider, identity);
        } catch (error) {
          if (error instanceof IdentityTakenError) return refuse('identity_taken');
          throw error;
        }
        await finishRecovery(enrollment.id, accountId, enrollment.revokeOtherMethods);
        deps.enrollCookie.clear(reply);
        method = `${provider.slug}_recovery`;
      } else {
        // Unknown identity, no invite: only the provider's sign-up policy can let them in. The
        // answer is the same whether or not someone already uses that email here (§3.3).
        const decision = signupDecision(identity, policyOf(provider));
        if (!decision.allowed)
          return refuse(
            decision.reason === 'signup_closed' ? 'unlinked_identity' : decision.reason,
          );
        accountId = await deps.identities.createUser(provider, identity, 'signup');
      }

      const [user] = await deps.db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.id, accountId), eq(users.status, 'active')));
      if (!user) return refuse('account_disabled', accountId);
      const redirectTo = await completeSignIn(deps, req, reply, { clientId, accountId, method });
      return reply.redirect(redirectTo, 303);
    },
  );

  // Recovery: consume the link, and on "I lost my device" drop every old passkey and session.
  async function finishRecovery(enrollmentId: string, userId: string, revokeOthers: boolean) {
    await deps.db.transaction(async (tx) => {
      await deps.enrollments.consume(tx, enrollmentId, userId);
      if (revokeOthers) await deps.enrollments.revokeOtherPasskeys(tx, userId);
    });
    if (revokeOthers) await deps.sessions.end(userId);
    await writeAudit(deps.db, {
      action: 'recovery.used',
      actorType: 'user',
      actorUserId: userId,
      targetType: 'user',
      targetId: userId,
      metadata: { revoked_other_methods: revokeOthers },
    });
  }
}

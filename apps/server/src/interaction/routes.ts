import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type Provider from 'oidc-provider';
import { eq, sql } from 'drizzle-orm';
import {
  authenticationOptions,
  challengeOf,
  ipPrefix,
  registrationOptions,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type RelyingParty,
} from '@handstamp/core';
import { groups, users, writeAudit, type Database } from '@handstamp/db';
import { CONSOLE_CLIENT_ID } from '../console/session.ts';
import { cleanName, passkeyMessage, type PasskeyStore } from '../passkeys.ts';
import { SetupError, type Setup } from '../setup.ts';
import type { RateLimits } from '../http/rate-limit.ts';
import { CSRF_HEADER, csrfToken, csrfValid, sameOrigin } from '../http/csrf.ts';
import type { SealedCookie } from '../http/sealed-cookie.ts';
import type { Enrollments } from '../enrollment.ts';
import type { Sessions } from '../sessions.ts';
import type { ProviderStore } from '../upstream/providers.ts';
import type { EnrollState } from '../upstream/routes.ts';
import { completeSignIn, PASSKEY_AMR, recordRefusal } from './sign-in.ts';

export type InteractionDeps = {
  provider: () => Provider;
  db: Database;
  issuer: URL;
  instanceName: string;
  csrfKey: Buffer;
  testUserId?: string;
  limits: RateLimits;
  rp: RelyingParty;
  passkeys: PasskeyStore;
  setup: Setup;
  providers: ProviderStore;
  enrollments: Enrollments;
  enrollCookie: SealedCookie<EnrollState>;
  sessions: Sessions;
  // OIDF conformance runs: plain no-JS forms the suite's browser automation can click (S17).
  conformance?: boolean;
};

type Params = { uid: string };

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

class InteractionProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

// JSON API behind the sign-in card. It lives under /interaction/:uid because that is the path
// oidc-provider scopes its interaction cookie to. The SPA page itself is GET /interaction/:uid.
export async function interactionRoutes(app: FastifyInstance, deps: InteractionDeps) {
  async function load(req: FastifyRequest<{ Params: Params }>, reply: FastifyReply) {
    let interaction;
    try {
      interaction = await deps.provider().interactionDetails(req.raw, reply.raw);
    } catch {
      throw new InteractionProblem(
        410,
        'interaction_expired',
        'This sign-in request has expired. Go back to the app and start again.',
      );
    }
    if (interaction.uid !== req.params.uid)
      throw new InteractionProblem(
        409,
        'interaction_mismatch',
        'This sign-in page belongs to a different request. Go back to the app and start again.',
      );
    return interaction;
  }

  const isForm = (req: FastifyRequest) =>
    req.headers['content-type']?.startsWith('application/x-www-form-urlencoded') ?? false;

  function guard(req: FastifyRequest<{ Params: Params }>) {
    const form = deps.conformance && isForm(req);
    const token = form
      ? (req.body as Record<string, string> | undefined)?.csrf
      : req.headers[CSRF_HEADER];
    // The conformance browser may send neither Origin nor Sec-Fetch-Site; its forms still carry the token.
    const originOk = sameOrigin(req, deps.issuer) || (form && !req.headers.origin);
    if (!originOk || !csrfValid(deps.csrfKey, `interaction:${req.params.uid}`, token))
      throw new InteractionProblem(
        403,
        'csrf',
        'We blocked this request because it did not come from this page. Reload and try again.',
      );
  }

  function finish(req: FastifyRequest, reply: FastifyReply, redirectTo: string) {
    if (deps.conformance && isForm(req)) return reply.redirect(redirectTo, 303);
    return { redirectTo };
  }

  function requireLoginStep(interaction: { prompt: { name: string } }) {
    if (interaction.prompt.name !== 'login')
      throw new InteractionProblem(
        409,
        'wrong_step',
        'You are already signed in. Reload the page to continue.',
      );
  }

  const signIn = (
    req: FastifyRequest<{ Params: Params }>,
    reply: FastifyReply,
    clientId: string,
    accountId: string,
    method: string,
    amr?: string[],
  ) => completeSignIn(deps, req, reply, { clientId, accountId, method, amr });

  const signInFailed = (req: FastifyRequest, clientId: string, reason: string, userId?: string) =>
    recordRefusal(deps.db, req, { clientId, method: 'passkey', reason, userId });

  // An invite or recovery link in progress, for the console's own sign-in only.
  async function pendingEnrollment(req: FastifyRequest, clientId: unknown) {
    if (clientId !== CONSOLE_CLIENT_ID) return undefined;
    const state = deps.enrollCookie.read(req);
    return state ? deps.enrollments.byId(state.enrollmentId) : undefined;
  }

  if (deps.conformance) {
    app.addContentTypeParser(
      'application/x-www-form-urlencoded',
      { parseAs: 'string' },
      (_req, body, done) => done(null, Object.fromEntries(new URLSearchParams(body as string))),
    );
    app.get<{ Params: Params }>(
      '/interaction/:uid',
      { config: { rateLimit: deps.limits.interaction } },
      async (req, reply) => {
        const interaction = await load(req, reply);
        const csrf = csrfToken(deps.csrfKey, `interaction:${interaction.uid}`);
        const action = interaction.prompt.name === 'login' ? 'dev-login' : 'consent';
        const label = action === 'dev-login' ? 'Continue as test user' : 'Allow';
        reply.header('cache-control', 'no-store').type('text/html; charset=utf-8');
        return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Handstamp conformance</title></head><body>
<h1>${action === 'dev-login' ? 'Sign in' : 'Consent'}</h1>
<form method="post" action="/interaction/${interaction.uid}/${action}"><input type="hidden" name="csrf" value="${csrf}">
<button id="hs-continue" type="submit">${label}</button></form></body></html>`;
      },
    );
  }

  app.setErrorHandler((error, _req, reply) => {
    if (error instanceof InteractionProblem)
      return reply.code(error.status).send({ error: error.code, message: error.message });
    if ((error as { statusCode?: number }).statusCode === 429)
      return reply.code(429).send({
        error: 'rate_limited',
        message: 'Too many attempts. Wait a minute and try again.',
      });
    app.log.error({ err: error }, 'interaction failed');
    return reply.code(500).send({
      error: 'server_error',
      message: 'Something went wrong on our side. Try again in a moment.',
    });
  });

  app.get<{ Params: Params }>(
    '/interaction/:uid/details',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      const interaction = await load(req, reply);
      const client = await deps.provider().Client.find(interaction.params.client_id as string);
      const enrollment = await pendingEnrollment(req, client?.clientId);
      reply.header('cache-control', 'no-store');
      return {
        uid: interaction.uid,
        prompt: {
          name: interaction.prompt.name,
          reasons: interaction.prompt.reasons,
          missingScopes:
            (interaction.prompt.details.missingOIDCScope as string[] | undefined) ?? [],
        },
        client: { clientId: client?.clientId, name: client?.clientName ?? client?.clientId },
        instanceName: deps.instanceName,
        issuer: deps.issuer.origin,
        devLogin: Boolean(deps.testUserId),
        // The console's own sign-in doubles as first-run setup until someone claims the instance.
        mode:
          client?.clientId === CONSOLE_CLIENT_ID && !(await deps.setup.claimed())
            ? 'claim'
            : (enrollment?.purpose ?? 'sign-in'),
        setupVerified: await deps.setup.isVerified(interaction.uid),
        // Recovery: whose account this is. Invites: nothing to show yet.
        enrollingAs:
          enrollment?.purpose === 'recovery'
            ? await deps.enrollments.userName(enrollment.userId!)
            : undefined,
        // Step-up for passkey holders: the console asks for a passkey, not an upstream sign-in.
        passkeyOnly: interaction.params.handstamp_method === 'passkey',
        // Access refused by an app's required group: name the group so the person can ask for it.
        requiredGroup:
          interaction.prompt.name === 'access'
            ? (
                await deps.db
                  .select({ slug: groups.slug, name: groups.name })
                  .from(groups)
                  .where(eq(groups.id, interaction.prompt.details.requiredGroup as string))
              )[0]
            : undefined,
        providers:
          interaction.params.handstamp_method === 'passkey'
            ? []
            : await deps.providers.listEnabled(),
        csrf: csrfToken(deps.csrfKey, `interaction:${interaction.uid}`),
      };
    },
  );

  app.post<{ Params: Params }>(
    '/interaction/:uid/dev-login',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      if (!deps.testUserId) throw new InteractionProblem(404, 'not_found', 'Not found.');
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      const redirectTo = await signIn(
        req,
        reply,
        interaction.params.client_id as string,
        deps.testUserId,
        'dev_test_account',
      );
      return finish(req, reply, redirectTo);
    },
  );

  app.post<{ Params: Params }>(
    '/interaction/:uid/consent',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const provider = deps.provider();
      const interaction = await load(req, reply);
      if (interaction.prompt.name !== 'consent' || !interaction.session?.accountId)
        throw new InteractionProblem(
          409,
          'wrong_step',
          'There is nothing to approve. Reload the page to continue.',
        );
      const { details } = interaction.prompt;
      const grant = interaction.grantId
        ? await provider.Grant.find(interaction.grantId)
        : new provider.Grant({
            accountId: interaction.session.accountId,
            clientId: interaction.params.client_id as string,
          });
      if (!grant)
        throw new InteractionProblem(
          410,
          'grant_missing',
          'This request expired. Go back to the app and start again.',
        );
      if (details.missingOIDCScope)
        grant.addOIDCScope((details.missingOIDCScope as string[]).join(' '));
      if (details.missingOIDCClaims) grant.addOIDCClaims(details.missingOIDCClaims as string[]);
      const grantId = await grant.save();
      const redirectTo = await provider.interactionResult(req.raw, reply.raw, {
        consent: interaction.grantId ? {} : { grantId },
      });
      await writeAudit(deps.db, {
        action: 'auth.consent.granted',
        actorType: 'user',
        actorUserId: interaction.session.accountId,
        clientId: interaction.params.client_id as string,
        metadata: { scopes: (details.missingOIDCScope as string[] | undefined) ?? [] },
      });
      return finish(req, reply, redirectTo);
    },
  );

  app.post<{ Params: Params }>(
    '/interaction/:uid/abort',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      await load(req, reply);
      const redirectTo = await deps
        .provider()
        .interactionResult(
          req.raw,
          reply.raw,
          { error: 'access_denied', error_description: 'The user cancelled the sign-in.' },
          { mergeWithLastSubmission: false },
        );
      return { redirectTo };
    },
  );

  // ── passkey sign-in ──
  app.post<{ Params: Params }>(
    '/interaction/:uid/passkey/options',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      const options = await authenticationOptions(deps.rp);
      await deps.passkeys.saveChallenge(
        'authenticate',
        `interaction:${interaction.uid}`,
        options.challenge,
      );
      return options;
    },
  );

  app.post<{ Params: Params; Body: { response?: AuthenticationResponseJSON } }>(
    '/interaction/:uid/passkey/verify',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      const clientId = interaction.params.client_id as string;
      const response = req.body?.response;
      const challenge = response && challengeOf(response);
      const stored =
        challenge &&
        (await deps.passkeys.consumeChallenge(
          'authenticate',
          `interaction:${interaction.uid}`,
          challenge,
        ));
      if (!response || !stored)
        throw new InteractionProblem(
          400,
          'challenge_expired',
          'That took too long. Try your passkey again.',
        );
      const passkey = await deps.passkeys.findByCredentialId(response.id);
      if (!passkey) {
        await signInFailed(req, clientId, 'unknown_credential');
        throw new InteractionProblem(
          401,
          'unknown_passkey',
          "This passkey isn't registered with this Handstamp instance. Try another one, or ask your admin.",
        );
      }
      const [user] = await deps.db.select().from(users).where(eq(users.id, passkey.userId));
      if (!user || user.status !== 'active') {
        await signInFailed(req, clientId, 'user_disabled', passkey.userId);
        throw new InteractionProblem(
          403,
          'account_disabled',
          'This account is turned off. Ask your admin.',
        );
      }
      let result;
      try {
        result = await verifyAuthentication(deps.rp, response, challenge, passkey);
      } catch (error) {
        await signInFailed(req, clientId, (error as { code?: string }).code ?? 'invalid', user.id);
        throw new InteractionProblem(401, 'passkey_invalid', passkeyMessage(error));
      }
      await deps.passkeys.recordUse(passkey.id, result.signCount, result.backedUp);
      const redirectTo = await signIn(req, reply, clientId, user.id, 'passkey', PASSKEY_AMR);
      return { redirectTo };
    },
  );

  // ── first-run setup: claim the instance (docs/PLAN.md §1.4 C) ──
  async function requireClaimable(interaction: { params: Record<string, unknown> }) {
    if (interaction.params.client_id !== CONSOLE_CLIENT_ID || (await deps.setup.claimed()))
      throw new InteractionProblem(
        409,
        'already_claimed',
        'This Handstamp instance already has an admin.',
      );
  }

  app.post<{ Params: Params; Body: { code?: string } }>(
    '/interaction/:uid/setup/verify',
    { config: { rateLimit: deps.limits.setup } },
    async (req, reply) => {
      guard(req);
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      await requireClaimable(interaction);
      if (!(await deps.setup.verifyCode(String(req.body?.code ?? ''), interaction.uid)))
        throw new InteractionProblem(
          400,
          'code_invalid',
          "That setup code didn't match. Copy the latest one from the server logs (restarting prints a new one).",
        );
      return { verified: true };
    },
  );

  app.post<{ Params: Params; Body: { displayName?: string; email?: string } }>(
    '/interaction/:uid/setup/passkey/options',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      await requireClaimable(interaction);
      if (!(await deps.setup.isVerified(interaction.uid)))
        throw new InteractionProblem(
          403,
          'code_required',
          'Enter the setup code from the server logs first.',
        );
      const displayName = String(req.body?.displayName ?? '')
        .trim()
        .slice(0, 80);
      const email = String(req.body?.email ?? '')
        .trim()
        .slice(0, 254);
      if (!displayName)
        throw new InteractionProblem(
          400,
          'name_required',
          'Add your name so people know who the admin is.',
        );
      if (email && !EMAIL.test(email))
        throw new InteractionProblem(
          400,
          'email_invalid',
          'That email address needs an @ and a domain.',
        );
      const handle = deps.setup.newUserHandle();
      const options = await registrationOptions(
        deps.rp,
        { handle, name: email || displayName, displayName },
        [],
      );
      await deps.passkeys.saveChallenge(
        'setup',
        `interaction:${interaction.uid}`,
        options.challenge,
        {
          pending: { handle, displayName, email },
        },
      );
      return options;
    },
  );

  app.post<{ Params: Params; Body: { response?: RegistrationResponseJSON; name?: string } }>(
    '/interaction/:uid/setup/passkey/verify',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const interaction = await load(req, reply);
      requireLoginStep(interaction);
      await requireClaimable(interaction);
      const response = req.body?.response;
      const challenge = response && challengeOf(response);
      const stored =
        challenge &&
        (await deps.passkeys.consumeChallenge(
          'setup',
          `interaction:${interaction.uid}`,
          challenge,
        ));
      if (!response || !stored)
        throw new InteractionProblem(
          400,
          'challenge_expired',
          'That took too long. Create the passkey again.',
        );
      let verified;
      try {
        verified = await verifyRegistration(deps.rp, response, challenge);
      } catch (error) {
        throw new InteractionProblem(400, 'passkey_invalid', passkeyMessage(error));
      }
      let userId;
      try {
        userId = await deps.setup.claim(
          interaction.uid,
          {
            displayName: stored.pending.displayName,
            email: stored.pending.email,
            handle: stored.pending.handle,
          },
          verified,
          cleanName(req.body?.name),
        );
      } catch (error) {
        if (error instanceof SetupError)
          throw new InteractionProblem(409, error.code, error.message);
        throw error;
      }
      const redirectTo = await signIn(
        req,
        reply,
        CONSOLE_CLIENT_ID,
        userId,
        'passkey_setup',
        PASSKEY_AMR,
      );
      return { redirectTo };
    },
  );

  // ── invite and recovery links (docs/PLAN.md §3.2) ──
  // The link page posts its token here; it's parked in a sealed cookie for the console sign-in.
  app.post<{ Body: { token?: string } }>(
    '/api/enroll',
    { config: { rateLimit: deps.limits.setup } },
    async (req, reply) => {
      if (!sameOrigin(req, deps.issuer))
        throw new InteractionProblem(403, 'csrf', 'Open the link in this browser and try again.');
      const enrollment = await deps.enrollments.find(String(req.body?.token ?? ''));
      if (!enrollment)
        throw new InteractionProblem(
          410,
          'enrollment_expired',
          'This link has expired or was already used. Ask your admin for a new one.',
        );
      deps.enrollCookie.write(reply, { enrollmentId: enrollment.id });
      return {
        purpose: enrollment.purpose,
        name: enrollment.userId ? await deps.enrollments.userName(enrollment.userId) : undefined,
      };
    },
  );

  async function requireEnrollment(req: FastifyRequest<{ Params: Params }>, reply: FastifyReply) {
    const interaction = await load(req, reply);
    requireLoginStep(interaction);
    const enrollment = await pendingEnrollment(req, interaction.params.client_id);
    if (!enrollment)
      throw new InteractionProblem(
        410,
        'enrollment_expired',
        'This link has expired or was already used. Ask your admin for a new one.',
      );
    return { interaction, enrollment };
  }

  app.post<{ Params: Params; Body: { displayName?: string } }>(
    '/interaction/:uid/enroll/passkey/options',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const { interaction, enrollment } = await requireEnrollment(req, reply);
      let user: { handle: string; name: string; displayName: string };
      let existing: { credentialId: string; transports: string[] }[] = [];
      if (enrollment.purpose === 'invite') {
        const displayName = String(req.body?.displayName ?? '')
          .trim()
          .slice(0, 80);
        if (!displayName)
          throw new InteractionProblem(
            400,
            'name_required',
            'Add your name so people know who you are.',
          );
        user = { handle: deps.setup.newUserHandle(), name: displayName, displayName };
      } else {
        const [row] = await deps.db.select().from(users).where(eq(users.id, enrollment.userId!));
        let handle = row.webauthnUserHandle;
        if (!handle) {
          handle = deps.setup.newUserHandle();
          await deps.db
            .update(users)
            .set({ webauthnUserHandle: handle })
            .where(eq(users.id, row.id));
        }
        user = { handle, name: row.email ?? row.displayName, displayName: row.displayName };
        if (!enrollment.revokeOtherMethods) existing = await deps.passkeys.listForUser(row.id);
      }
      const options = await registrationOptions(deps.rp, user, existing);
      await deps.passkeys.saveChallenge(
        'enroll',
        `interaction:${interaction.uid}`,
        options.challenge,
        {
          pending: { handle: user.handle, displayName: user.displayName },
        },
      );
      return options;
    },
  );

  app.post<{ Params: Params; Body: { response?: RegistrationResponseJSON; name?: string } }>(
    '/interaction/:uid/enroll/passkey/verify',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      guard(req);
      const { interaction, enrollment } = await requireEnrollment(req, reply);
      const response = req.body?.response;
      const challenge = response && challengeOf(response);
      const stored =
        challenge &&
        (await deps.passkeys.consumeChallenge(
          'enroll',
          `interaction:${interaction.uid}`,
          challenge,
        ));
      if (!response || !stored)
        throw new InteractionProblem(
          400,
          'challenge_expired',
          'That took too long. Create the passkey again.',
        );
      let verified;
      try {
        verified = await verifyRegistration(deps.rp, response, challenge);
      } catch (error) {
        throw new InteractionProblem(400, 'passkey_invalid', passkeyMessage(error));
      }
      const accountId = await deps.db.transaction(async (tx) => {
        if (!(await deps.enrollments.consume(tx, enrollment.id)))
          throw new InteractionProblem(
            410,
            'enrollment_expired',
            'This link was just used. Ask your admin for a new one.',
          );
        let userId = enrollment.userId;
        if (enrollment.purpose === 'invite') {
          const [created] = await tx
            .insert(users)
            .values({
              displayName: stored.pending.displayName,
              webauthnUserHandle: stored.pending.handle,
            })
            .returning({ id: users.id });
          userId = created.id;
          await writeAudit(tx, {
            action: 'user.created',
            actorType: 'user',
            actorUserId: userId,
            targetType: 'user',
            targetId: userId,
            metadata: { via: 'invite' },
          });
        } else if (enrollment.revokeOtherMethods) {
          await deps.enrollments.revokeOtherPasskeys(tx, userId!);
        }
        const taken = (await deps.passkeys.listForUser(userId!)).map((p) => p.name);
        await deps.passkeys.add(tx, userId!, verified, cleanName(req.body?.name, taken));
        return userId!;
      });
      await deps.enrollments.recordConsumer(enrollment.id, accountId);
      if (enrollment.purpose === 'recovery' && enrollment.revokeOtherMethods)
        await deps.sessions.end(accountId);
      await writeAudit(deps.db, {
        action: enrollment.purpose === 'invite' ? 'invite.used' : 'recovery.used',
        actorType: 'user',
        actorUserId: accountId,
        targetType: 'enrollment',
        targetId: enrollment.id,
        metadata: { method: 'passkey', revoked_other_methods: enrollment.revokeOtherMethods },
      });
      deps.enrollCookie.clear(reply);
      const redirectTo = await signIn(
        req,
        reply,
        CONSOLE_CLIENT_ID,
        accountId,
        `passkey_${enrollment.purpose}`,
        PASSKEY_AMR,
      );
      return { redirectTo };
    },
  );
}

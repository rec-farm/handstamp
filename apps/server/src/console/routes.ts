import type { FastifyInstance, FastifyRequest } from 'fastify';
import * as oidc from 'openid-client';
import { and, desc, eq, inArray, or } from 'drizzle-orm';
import {
  challengeOf,
  ipPrefix,
  registrationOptions,
  safeReturnPath,
  verifyRegistration,
  type RegistrationResponseJSON,
  type RelyingParty,
} from '@handstamp/core';
import { auditLog, instanceSettings, users, writeAudit, type Database } from '@handstamp/db';
import { CSRF_HEADER, csrfToken, csrfValid, sameOrigin } from '../http/csrf.ts';
import type { RateLimits } from '../http/rate-limit.ts';
import { cleanName, LastMethodError, passkeyMessage, type PasskeyStore } from '../passkeys.ts';
import type { Sessions } from '../sessions.ts';
import { LastMethodError as UnlinkLastMethodError, type IdentityStore } from '../identities.ts';
import type { ProviderStore } from '../upstream/providers.ts';
import type { UpstreamFlow } from '../upstream/routes.ts';
import { ApiProblem, apiErrorHandler, consoleAuth } from './auth.ts';
import {
  CONSOLE_CLIENT_ID,
  ConsoleCookies,
  consoleOidc,
  recentlyAuthenticated,
  type ConsoleSession,
} from './session.ts';

export type ConsoleDeps = {
  db: Database;
  issuer: URL;
  instanceName: string;
  secret: string;
  secretKey: Buffer;
  csrfKey: Buffer;
  rp: RelyingParty;
  passkeys: PasskeyStore;
  sessions: Sessions;
  limits: RateLimits;
  identities: IdentityStore;
  providers: ProviderStore;
  flow: UpstreamFlow;
};

// The console's own sign-in (an OIDC client of this issuer) and the account API behind /account.
export async function consoleRoutes(app: FastifyInstance, deps: ConsoleDeps) {
  const cookies = new ConsoleCookies(deps.secretKey, deps.issuer);
  const config = consoleOidc(app, deps.issuer, deps.secret);
  const callback = `${deps.issuer.origin}/console/callback`;
  const csrfFor = (s: ConsoleSession) => csrfToken(deps.csrfKey, `console:${s.uid}`);

  apiErrorHandler(app);
  const { signedIn } = consoleAuth(deps);

  // ── sign-in for the console itself ──
  app.get<{ Querystring: { returnTo?: string; fresh?: string; passkey?: string } }>(
    '/console/login',
    async (req, reply) => {
      const verifier = oidc.randomPKCECodeVerifier();
      const pending = {
        state: oidc.randomState(),
        nonce: oidc.randomNonce(),
        verifier,
        returnTo: safeReturnPath(req.query.returnTo, '/account'),
      };
      cookies.writePending(reply, pending);
      const url = oidc.buildAuthorizationUrl(await config(), {
        redirect_uri: callback,
        scope: 'openid profile email groups',
        state: pending.state,
        nonce: pending.nonce,
        code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
        code_challenge_method: 'S256',
        // sid finds the SSO session; auth_time drives step-up.
        claims: JSON.stringify({
          id_token: { sid: { essential: true }, auth_time: { essential: true }, amr: null },
        }),
        ...(req.query.fresh ? { max_age: '0' } : {}),
        ...(req.query.passkey ? { handstamp_method: 'passkey' } : {}),
      });
      return reply.redirect(url.href, 303);
    },
  );

  app.get('/console/callback', async (req, reply) => {
    const pending = cookies.readPending(req);
    cookies.clear(reply, cookies.state);
    const url = new URL(req.url, deps.issuer);
    if (url.searchParams.get('error') === 'access_denied')
      return reply.redirect('/signed-out', 303);
    if (!pending) return reply.redirect('/console/login', 303);
    let claims;
    try {
      const tokens = await oidc.authorizationCodeGrant(await config(), url, {
        pkceCodeVerifier: pending.verifier,
        expectedState: pending.state,
        expectedNonce: pending.nonce,
        idTokenExpected: true,
      });
      claims = tokens.claims()!;
    } catch (error) {
      req.log.warn({ err: error }, 'console sign-in failed');
      return reply.redirect('/error?code=invalid_request', 303);
    }
    const uid = await deps.sessions.uidForSid(claims.sub, CONSOLE_CLIENT_ID, String(claims.sid));
    if (!uid) return reply.redirect('/console/login', 303);
    cookies.writeSession(reply, {
      sub: claims.sub,
      uid,
      authTime: Number(claims.auth_time ?? Math.floor(Date.now() / 1000)),
      amr: (claims.amr as string[] | undefined) ?? [],
    });
    return reply.redirect(safeReturnPath(pending.returnTo, '/account'), 303);
  });

  app.get('/console/logout', async (_req, reply) => {
    cookies.clear(reply, cookies.session);
    const end = new URL('/session/end', deps.issuer);
    end.searchParams.set('client_id', CONSOLE_CLIENT_ID);
    end.searchParams.set('post_logout_redirect_uri', `${deps.issuer.origin}/signed-out`);
    return reply.redirect(end.pathname + end.search, 303);
  });

  // ── account API ──
  app.get('/api/instance', async (_req, reply) => {
    const [settings] = await deps.db.select().from(instanceSettings);
    reply.header('cache-control', 'no-store');
    return { claimed: Boolean(settings?.setupCompletedAt), instanceName: deps.instanceName };
  });

  app.get('/api/me', async (req, reply) => {
    const { user, session } = await signedIn(req);
    reply.header('cache-control', 'no-store');
    return {
      user: {
        sub: user.id,
        displayName: user.displayName,
        email: user.email,
        emailVerified: user.emailVerified,
        isAdmin: user.isAdmin,
        createdAt: user.createdAt,
      },
      session: {
        uid: session.uid,
        authTime: new Date(session.authTime * 1000).toISOString(),
        recentlyAuthenticated: recentlyAuthenticated(session),
      },
      csrf: csrfFor(session),
    };
  });

  app.get('/api/me/passkeys', async (req) => {
    const { user } = await signedIn(req);
    return (await deps.passkeys.listForUser(user.id)).map((p) => ({
      id: p.id,
      name: p.name,
      createdAt: p.createdAt,
      lastUsedAt: p.lastUsedAt,
      synced: p.backedUp,
    }));
  });

  app.post(
    '/api/me/passkeys/options',
    { config: { rateLimit: deps.limits.interaction } },
    async (req) => {
      const { user, session } = await signedIn(req, { write: true, stepUp: true });
      let handle = user.webauthnUserHandle;
      if (!handle) {
        handle = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString('base64url');
        await deps.db
          .update(users)
          .set({ webauthnUserHandle: handle })
          .where(eq(users.id, user.id));
      }
      const existing = await deps.passkeys.listForUser(user.id);
      const options = await registrationOptions(
        deps.rp,
        {
          handle,
          displayName: user.displayName,
          email: user.email,
          username: user.preferredUsername,
        },
        existing,
      );
      await deps.passkeys.saveChallenge('register', `console:${session.uid}`, options.challenge, {
        userId: user.id,
      });
      return options;
    },
  );

  app.post<{ Body: { response: RegistrationResponseJSON; name?: string } }>(
    '/api/me/passkeys',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      const { user, session } = await signedIn(req, { write: true, stepUp: true });
      const response = req.body?.response;
      const challenge = response && challengeOf(response);
      const stored =
        challenge &&
        (await deps.passkeys.consumeChallenge('register', `console:${session.uid}`, challenge));
      if (!stored || stored.userId !== user.id)
        throw new ApiProblem(
          400,
          'challenge_expired',
          'That took too long. Try adding the passkey again.',
        );
      let verified;
      try {
        verified = await verifyRegistration(deps.rp, response, challenge);
      } catch (error) {
        throw new ApiProblem(400, 'passkey_invalid', passkeyMessage(error));
      }
      if (await deps.passkeys.findByCredentialId(verified.credentialId))
        throw new ApiProblem(409, 'passkey_exists', 'This passkey is already registered.');
      const taken = (await deps.passkeys.listForUser(user.id)).map((p) => p.name);
      const id = await deps.passkeys.add(
        deps.db,
        user.id,
        verified,
        cleanName(req.body.name, taken),
      );
      await writeAudit(deps.db, {
        action: 'passkey.added',
        actorType: 'user',
        actorUserId: user.id,
        targetType: 'passkey',
        targetId: id,
        ipPrefix: ipPrefix(req.ip),
        userAgent: req.headers['user-agent'],
        metadata: { synced: verified.backedUp },
      });
      return reply.code(201).send({ id });
    },
  );

  app.patch<{ Params: { id: string }; Body: { name?: string } }>(
    '/api/me/passkeys/:id',
    async (req) => {
      const { user } = await signedIn(req, { write: true });
      const name = cleanName(req.body?.name);
      if (!(await deps.passkeys.rename(user.id, req.params.id, name)))
        throw new ApiProblem(404, 'not_found', 'That passkey no longer exists.');
      await writeAudit(deps.db, {
        action: 'passkey.renamed',
        actorType: 'user',
        actorUserId: user.id,
        targetType: 'passkey',
        targetId: req.params.id,
      });
      return { name };
    },
  );

  app.delete<{ Params: { id: string } }>('/api/me/passkeys/:id', async (req, reply) => {
    const { user } = await signedIn(req, { write: true, stepUp: true });
    try {
      const removed = await deps.passkeys.remove(user.id, req.params.id);
      if (!removed) throw new ApiProblem(404, 'not_found', 'That passkey no longer exists.');
      await writeAudit(deps.db, {
        action: 'passkey.removed',
        actorType: 'user',
        actorUserId: user.id,
        targetType: 'passkey',
        targetId: req.params.id,
        ipPrefix: ipPrefix(req.ip),
      });
      return reply.code(204).send();
    } catch (error) {
      if (error instanceof LastMethodError)
        throw new ApiProblem(
          409,
          'last_method',
          "This is your only passkey. Add another one first, so you can't get locked out.",
        );
      throw error;
    }
  });

  app.get('/api/me/sessions', async (req) => {
    const { user, session } = await signedIn(req);
    return (await deps.sessions.list(user.id)).map((s) => ({
      ...s,
      current: s.uid === session.uid,
    }));
  });

  app.delete<{ Params: { uid: string } }>('/api/me/sessions/:uid', async (req, reply) => {
    const { user, session } = await signedIn(req, { write: true });
    if (!(await deps.sessions.end(user.id, req.params.uid)))
      throw new ApiProblem(404, 'not_found', 'That session has already ended.');
    await writeAudit(deps.db, {
      action: 'session.revoked',
      actorType: 'user',
      actorUserId: user.id,
      targetType: 'session',
      targetId: req.params.uid,
    });
    if (req.params.uid === session.uid) cookies.clear(reply, cookies.session);
    return reply.code(204).send();
  });

  // The escape hatch: deliberately no step-up, so it works even with a stolen passkey's session.
  app.post('/api/me/sign-out-everywhere', async (req, reply) => {
    const { user } = await signedIn(req, { write: true });
    const ended = await deps.sessions.end(user.id);
    await writeAudit(deps.db, {
      action: 'session.revoked_all',
      actorType: 'user',
      actorUserId: user.id,
      ipPrefix: ipPrefix(req.ip),
      metadata: { sessions: ended },
    });
    cookies.clear(reply, cookies.session);
    return { ended };
  });

  // ── linked identities ──
  app.get('/api/me/identities', async (req) => {
    const { user } = await signedIn(req);
    const linked = await deps.identities.listForUser(user.id);
    const providers = await deps.providers.listEnabled();
    return {
      linked,
      // One identity per provider keeps the account page simple.
      available: providers.filter((p) => !linked.some((l) => l.provider === p.slug)),
    };
  });

  app.post<{ Params: { slug: string } }>(
    '/api/me/identities/link/:slug',
    { config: { rateLimit: deps.limits.interaction } },
    async (req, reply) => {
      const { session } = await signedIn(req, { write: true, stepUp: true });
      const url = await deps.flow.startLink(reply, req.params.slug, session);
      if (!url) throw new ApiProblem(404, 'not_found', 'That sign-in provider is not available.');
      return { redirectTo: url };
    },
  );

  app.delete<{ Params: { id: string } }>('/api/me/identities/:id', async (req, reply) => {
    const { user } = await signedIn(req, { write: true, stepUp: true });
    try {
      if (!(await deps.identities.unlink(user.id, req.params.id)))
        throw new ApiProblem(404, 'not_found', 'That account is no longer linked.');
    } catch (error) {
      if (error instanceof UnlinkLastMethodError)
        throw new ApiProblem(
          409,
          'last_method',
          "This is your only way to sign in. Add a passkey first, so you can't get locked out.",
        );
      throw error;
    }
    await writeAudit(deps.db, {
      action: 'identity.unlinked',
      actorType: 'user',
      actorUserId: user.id,
      targetType: 'identity',
      targetId: req.params.id,
      ipPrefix: ipPrefix(req.ip),
    });
    return reply.code(204).send();
  });

  // Security activity on the account page: what changed, when, from roughly where.
  app.get('/api/me/activity', async (req) => {
    const { user } = await signedIn(req);
    const rows = await deps.db
      .select({
        at: auditLog.at,
        action: auditLog.action,
        metadata: auditLog.metadata,
        ipPrefix: auditLog.ipPrefix,
        clientId: auditLog.clientId,
      })
      .from(auditLog)
      .where(
        and(
          or(
            eq(auditLog.actorUserId, user.id),
            and(eq(auditLog.targetType, 'user'), eq(auditLog.targetId, user.id)),
          ),
          inArray(auditLog.action, ACTIVITY),
        ),
      )
      .orderBy(desc(auditLog.at))
      .limit(20);
    return rows;
  });
}

const ACTIVITY = [
  'auth.sign_in.succeeded',
  'auth.sign_in.failed',
  'passkey.added',
  'passkey.removed',
  'identity.linked',
  'identity.unlinked',
  'recovery.issued',
  'recovery.used',
  'session.revoked_all',
  'instance.claimed',
] as const;

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { and, eq } from 'drizzle-orm';
import { users, type Database } from '@handstamp/db';
import { CSRF_HEADER, csrfValid, sameOrigin } from '../http/csrf.ts';
import type { PasskeyStore } from '../passkeys.ts';
import type { Sessions } from '../sessions.ts';
import { ConsoleCookies, recentlyAuthenticated } from './session.ts';

export class ApiProblem extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

// JSON errors for the console and admin APIs: what happened, what to do next (§12).
export function apiErrorHandler(app: FastifyInstance) {
  app.setErrorHandler((error, _req, reply) => {
    if (error instanceof ApiProblem)
      return reply
        .code(error.status)
        .send({ error: error.code, message: error.message, ...error.extra });
    if ((error as { statusCode?: number }).statusCode === 429)
      return reply.code(429).send({
        error: 'rate_limited',
        message: 'Too many attempts. Wait a minute and try again.',
      });
    if ((error as { validation?: unknown }).validation)
      return reply
        .code(400)
        .send({ error: 'invalid_request', message: 'Some of the details sent were not valid.' });
    app.log.error({ err: error }, 'console request failed');
    return reply.code(500).send({
      error: 'server_error',
      message: 'Something went wrong on our side. Try again in a moment.',
    });
  });
}

export type AuthDeps = {
  db: Database;
  issuer: URL;
  secretKey: Buffer;
  csrfKey: Buffer;
  sessions: Sessions;
  passkeys: PasskeyStore;
};

// Who is signed in to the console, and may they do this? Shared by /api/me and /api/admin.
export function consoleAuth(deps: AuthDeps) {
  const cookies = new ConsoleCookies(deps.secretKey, deps.issuer);

  // A console session is only as alive as the SSO session it rides on: signing out anywhere
  // (or "sign out everywhere") ends it immediately.
  async function current(req: FastifyRequest) {
    const session = cookies.readSession(req);
    if (!session || !(await deps.sessions.exists(session.sub, session.uid))) return undefined;
    const [user] = await deps.db
      .select()
      .from(users)
      .where(and(eq(users.id, session.sub), eq(users.status, 'active')));
    return user ? { session, user } : undefined;
  }

  async function signedIn(
    req: FastifyRequest,
    { write = false, stepUp = false, admin = false } = {},
  ) {
    const found = await current(req);
    if (!found) throw new ApiProblem(401, 'signed_out', 'Sign in to continue.');
    if (admin && !found.user.isAdmin)
      throw new ApiProblem(403, 'not_admin', 'Only Handstamp admins can do this.');
    if (write) {
      const token = req.headers[CSRF_HEADER];
      if (
        !sameOrigin(req, deps.issuer) ||
        !csrfValid(deps.csrfKey, `console:${found.session.uid}`, token)
      )
        throw new ApiProblem(
          403,
          'csrf',
          'We blocked this request because it did not come from this page. Reload and try again.',
        );
    }
    if (stepUp) {
      // A passkey holder confirms with a passkey: a hijacked GitHub account can't stand in for
      // them when it comes to changing how they sign in, or anything an admin does (§3.3).
      const hasPasskey = (await deps.passkeys.listForUser(found.user.id)).length > 0;
      const fresh = recentlyAuthenticated(found.session);
      if (!fresh || (hasPasskey && !found.session.amr.includes('pop')))
        throw new ApiProblem(403, 'step_up_required', 'For your safety, confirm it is you first.', {
          method: hasPasskey ? 'passkey' : 'any',
        });
    }
    return found;
  }

  return { cookies, current, signedIn };
}

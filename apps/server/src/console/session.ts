import '@fastify/cookie';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import * as oidc from 'openid-client';
import { deriveKey, open, seal, type ClientDefinition } from '@handstamp/core';

export const CONSOLE_CLIENT_ID = 'handstamp-console';
export const STEP_UP_SECONDS = 5 * 60;
const SESSION_HOURS = 12;
const STATE_MINUTES = 10;

// Handstamp's own account and admin UI is a first-party client of itself (docs/PLAN.md §1.3).
export function consoleClient(issuer: URL): ClientDefinition {
  return {
    clientId: CONSOLE_CLIENT_ID,
    name: 'Handstamp',
    redirectUris: [`${issuer.origin}/console/callback`],
    postLogoutRedirectUris: [`${issuer.origin}/signed-out`],
    scopes: ['openid', 'profile', 'email', 'groups'],
    tokenEndpointAuthMethod: 'client_secret_basic',
    firstParty: true,
    requirePkce: true,
  };
}

export function consoleSecret(secretKey: Buffer) {
  return deriveKey(secretKey, 'console-client').toString('base64url');
}

// The console talks OIDC to its own issuer through Fastify's inject, not the network, so it
// works even where the container can't reach its own public hostname.
function injectFetch(app: FastifyInstance, issuer: URL): oidc.CustomFetch {
  return async (input, init) => {
    const url = new URL(input);
    const headers: Record<string, string> = {};
    new Headers(init?.headers).forEach((value, key) => (headers[key] = value));
    // oidc-provider builds endpoint URLs from the request, so it must look like the public one.
    headers.host = issuer.host;
    if (issuer.protocol === 'https:') headers['x-forwarded-proto'] = 'https';
    const response = await app.inject({
      method: (init?.method ?? 'GET') as 'GET',
      url: url.pathname + url.search,
      headers,
      payload:
        init?.body == null
          ? undefined
          : init.body instanceof Uint8Array
            ? Buffer.from(init.body)
            : String(init.body),
    });
    const out = new Headers();
    for (const [key, value] of Object.entries(response.headers))
      for (const v of Array.isArray(value) ? value : [value])
        if (v !== undefined) out.append(key, String(v));
    return new Response(new Uint8Array(response.rawPayload), {
      status: response.statusCode,
      headers: out,
    });
  };
}

export function consoleOidc(app: FastifyInstance, issuer: URL, secret: string) {
  let config: Promise<oidc.Configuration> | undefined;
  return () =>
    (config ??= oidc
      .discovery(issuer, CONSOLE_CLIENT_ID, secret, oidc.ClientSecretBasic(secret), {
        [oidc.customFetch]: injectFetch(app, issuer),
        execute: issuer.protocol === 'http:' ? [oidc.allowInsecureRequests] : [],
      })
      .catch((error) => {
        config = undefined;
        throw error;
      }));
}

export type ConsoleSession = {
  sub: string;
  uid: string; // the OP session this console session rides on
  authTime: number;
  amr: string[];
  exp: number;
};
type PendingLogin = {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  exp: number;
};

export class ConsoleCookies {
  readonly #key: Buffer;
  readonly session: string;
  readonly state: string;
  readonly #secure: boolean;

  constructor(secretKey: Buffer, issuer: URL) {
    this.#key = deriveKey(secretKey, 'state-cookies');
    this.#secure = issuer.protocol === 'https:';
    this.session = this.#secure ? '__Host-hs_console' : 'hs_console';
    this.state = this.#secure ? '__Host-hs_console_state' : 'hs_console_state';
  }

  #write(reply: FastifyReply, name: string, value: object, maxAge: number) {
    reply.setCookie(name, seal(this.#key, JSON.stringify(value), name).toString('base64url'), {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: this.#secure,
      maxAge,
    });
  }

  #read<T extends { exp: number }>(req: FastifyRequest, name: string): T | undefined {
    const raw = req.cookies[name];
    if (!raw) return undefined;
    try {
      const value = JSON.parse(
        open(this.#key, Buffer.from(raw, 'base64url'), name).toString(),
      ) as T;
      return value.exp > Date.now() / 1000 ? value : undefined;
    } catch {
      return undefined;
    }
  }

  writePending(reply: FastifyReply, pending: Omit<PendingLogin, 'exp'>) {
    const exp = Math.floor(Date.now() / 1000) + STATE_MINUTES * 60;
    this.#write(reply, this.state, { ...pending, exp }, STATE_MINUTES * 60);
  }

  readPending(req: FastifyRequest) {
    return this.#read<PendingLogin>(req, this.state);
  }

  writeSession(reply: FastifyReply, session: Omit<ConsoleSession, 'exp'>) {
    const exp = Math.floor(Date.now() / 1000) + SESSION_HOURS * 3600;
    this.#write(reply, this.session, { ...session, exp }, SESSION_HOURS * 3600);
  }

  readSession(req: FastifyRequest) {
    return this.#read<ConsoleSession>(req, this.session);
  }

  clear(reply: FastifyReply, name: string) {
    reply.clearCookie(name, { path: '/', secure: this.#secure, httpOnly: true, sameSite: 'lax' });
  }
}

export function recentlyAuthenticated(session: ConsoleSession) {
  return Date.now() / 1000 - session.authTime <= STEP_UP_SECONDS;
}

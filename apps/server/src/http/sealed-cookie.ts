import '@fastify/cookie';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { deriveKey, open, seal } from '@handstamp/core';

// A short-lived, encrypted, HttpOnly cookie holding server state between redirects (upstream
// sign-in state, a pending enrollment). Sealed with AES-GCM and bound to its own name.
export class SealedCookie<T extends object> {
  readonly name: string;
  readonly #key: Buffer;
  readonly #secure: boolean;

  constructor(
    secretKey: Buffer,
    issuer: URL,
    base: string,
    private readonly maxAgeSeconds: number,
  ) {
    this.#key = deriveKey(secretKey, 'state-cookies');
    this.#secure = issuer.protocol === 'https:';
    this.name = this.#secure ? `__Host-${base}` : base;
  }

  write(reply: FastifyReply, value: T) {
    const exp = Math.floor(Date.now() / 1000) + this.maxAgeSeconds;
    const sealed = seal(this.#key, JSON.stringify({ ...value, exp }), this.name);
    reply.setCookie(this.name, sealed.toString('base64url'), {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: this.#secure,
      maxAge: this.maxAgeSeconds,
    });
  }

  read(req: FastifyRequest): T | undefined {
    const raw = req.cookies[this.name];
    if (!raw) return undefined;
    try {
      const value = JSON.parse(
        open(this.#key, Buffer.from(raw, 'base64url'), this.name).toString(),
      );
      return value.exp > Date.now() / 1000 ? (value as T) : undefined;
    } catch {
      return undefined;
    }
  }

  clear(reply: FastifyReply) {
    reply.clearCookie(this.name, {
      path: '/',
      secure: this.#secure,
      httpOnly: true,
      sameSite: 'lax',
    });
  }
}

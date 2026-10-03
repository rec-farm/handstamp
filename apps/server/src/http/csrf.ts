import { createHmac } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { constantTimeEqual } from '@handstamp/core';

export const CSRF_HEADER = 'x-handstamp-csrf';

// State-changing requests must come from our own pages: the Origin must be the issuer (or, when a
// browser omits it, Sec-Fetch-Site must say same-origin), plus a token bound to the interaction (S5).
export function sameOrigin(req: FastifyRequest, issuer: URL) {
  const origin = req.headers.origin;
  if (origin) return origin === issuer.origin;
  return req.headers['sec-fetch-site'] === 'same-origin';
}

export function csrfToken(key: Buffer, binding: string) {
  return createHmac('sha256', key).update(binding).digest('base64url');
}

export function csrfValid(key: Buffer, binding: string, presented: unknown) {
  if (typeof presented !== 'string') return false;
  return constantTimeEqual(Buffer.from(csrfToken(key, binding)), Buffer.from(presented));
}

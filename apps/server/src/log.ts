import type { FastifyServerOptions } from 'fastify';
import pino from 'pino';

// Anything that can authenticate someone: never write it to logs (S9).
export const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  '*.client_secret',
  '*.code',
  '*.code_verifier',
  '*.refresh_token',
  '*.access_token',
  '*.id_token',
  '*.id_token_hint',
  '*.token',
  '*.xsrf',
  '*.password',
];

// Query strings carry authorization codes, state and id_token_hint, so URLs are logged by path only.
export function pathOnly(url: string | undefined) {
  if (!url) return url;
  const index = url.indexOf('?');
  return index === -1 ? url : `${url.slice(0, index)}?[redacted]`;
}

export function loggerOptions(level: string): FastifyServerOptions['logger'] {
  return {
    level,
    redact: { paths: REDACT_PATHS, censor: '[redacted]' },
    serializers: {
      req: (req) => ({ method: req.method, url: pathOnly(req.url), remoteAddress: req.ip }),
    },
  };
}

// For output outside request handling (CLI, boot). Same redaction rules.
export function createLogger(level = 'info') {
  return pino({ level, redact: { paths: REDACT_PATHS, censor: '[redacted]' } });
}

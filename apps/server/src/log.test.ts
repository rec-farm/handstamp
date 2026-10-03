import { Writable } from 'node:stream';
import pino from 'pino';
import { describe, expect, it } from 'vitest';
import { pathOnly, REDACT_PATHS } from './log.ts';

function capture() {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, done) {
      lines.push(chunk.toString());
      done();
    },
  });
  return { logger: pino({ redact: { paths: REDACT_PATHS, censor: '[redacted]' } }, stream), lines };
}

describe('log redaction (S9)', () => {
  it('drops credentials from request and body objects', () => {
    const { logger, lines } = capture();
    logger.info({
      req: { headers: { authorization: 'Basic c2VjcmV0', cookie: 'hs_session=abc' } },
      body: {
        client_secret: 's3cret',
        code: 'auth-code',
        refresh_token: 'rt',
        id_token_hint: 'jwt',
      },
    });
    const output = lines.join('');
    for (const secret of ['c2VjcmV0', 'hs_session=abc', 's3cret', 'auth-code', '"rt"', '"jwt"'])
      expect(output).not.toContain(secret);
  });

  it('logs URLs without their query string', () => {
    expect(pathOnly('/cb?code=abc&state=xyz')).toBe('/cb?[redacted]');
    expect(pathOnly('/token')).toBe('/token');
  });
});

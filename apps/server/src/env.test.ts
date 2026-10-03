import { describe, expect, it } from 'vitest';
import { parseEnv, parseTrustProxy } from './env.ts';

const base = {
  DATABASE_URL: 'postgres://x',
  HANDSTAMP_ISSUER: 'https://id.example.com',
  HANDSTAMP_SECRET_KEY: Buffer.alloc(32, 1).toString('base64'),
};

describe('parseEnv', () => {
  it('accepts a minimal production config', () => {
    const env = parseEnv({ ...base, NODE_ENV: 'production' });
    expect(env.HANDSTAMP_ISSUER.origin).toBe('https://id.example.com');
    expect(env.trustProxy).toBe(false);
  });

  it.each([
    ['http://id.example.com', /https/],
    ['https://id.example.com/oidc', /bare origin/],
  ])('rejects issuer %s', (issuer, message) => {
    expect(() => parseEnv({ ...base, HANDSTAMP_ISSUER: issuer })).toThrow(message);
  });

  it('allows http for localhost', () => {
    expect(
      parseEnv({ ...base, HANDSTAMP_ISSUER: 'http://localhost:3000' }).HANDSTAMP_ISSUER.port,
    ).toBe('3000');
  });

  it('never prints secret values when it fails', () => {
    const secret = 'c2hvcnQ=';
    try {
      parseEnv({ ...base, HANDSTAMP_SECRET_KEY: secret });
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).toContain('HANDSTAMP_SECRET_KEY');
      expect((error as Error).message).not.toContain(secret);
    }
  });

  describe('dev login (S17)', () => {
    const dev = { ...base, HANDSTAMP_DEV_LOGIN: '1' };

    it('works on a local issuer outside production', () => {
      expect(
        parseEnv({ ...dev, HANDSTAMP_ISSUER: 'http://localhost:3000' }).HANDSTAMP_DEV_LOGIN,
      ).toBe(true);
    });

    it('refuses a real hostname', () => {
      expect(() => parseEnv({ ...dev, NODE_ENV: 'development' })).toThrow(/HANDSTAMP_DEV_LOGIN/);
    });

    it('refuses production unless in conformance mode on a .test host', () => {
      const local = { ...dev, NODE_ENV: 'production', HANDSTAMP_ISSUER: 'https://handstamp.test' };
      expect(() => parseEnv(local)).toThrow(/HANDSTAMP_DEV_LOGIN/);
      expect(parseEnv({ ...local, HANDSTAMP_CONFORMANCE_MODE: '1' }).HANDSTAMP_DEV_LOGIN).toBe(
        true,
      );
      expect(() =>
        parseEnv({
          ...local,
          HANDSTAMP_CONFORMANCE_MODE: '1',
          HANDSTAMP_ISSUER: 'https://id.example.com',
        }),
      ).toThrow(/HANDSTAMP_DEV_LOGIN/);
    });
  });
});

describe('parseTrustProxy', () => {
  it.each([
    ['', false],
    ['1', 1],
    ['10.0.0.0/8, 172.16.0.0/12', ['10.0.0.0/8', '172.16.0.0/12']],
  ])('parses %j', (input, expected) => expect(parseTrustProxy(input)).toEqual(expected));
});

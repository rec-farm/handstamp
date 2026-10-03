import { z } from 'zod';
import { parseRootKey } from '@handstamp/core';

const flag = z
  .enum(['0', '1', 'true', 'false'])
  .default('0')
  .transform((v) => v === '1' || v === 'true');
const positive = (fallback: number) => z.coerce.number().int().positive().default(fallback);

function isLocalHost(hostname: string) {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.test')
  );
}

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    DATABASE_URL: z.string().min(1, 'DATABASE_URL is required'),
    HANDSTAMP_ISSUER: z
      .url()
      .transform((value) => new URL(value))
      .refine((url) => url.pathname === '/' && !url.search && !url.hash, {
        message: 'HANDSTAMP_ISSUER must be a bare origin, such as https://id.example.com',
      })
      .refine((url) => url.protocol === 'https:' || isLocalHost(url.hostname), {
        message: 'HANDSTAMP_ISSUER must use https:// (http:// is only allowed for localhost)',
      }),
    HANDSTAMP_SECRET_KEY: z.string().min(1, 'HANDSTAMP_SECRET_KEY is required'),
    HOST: z.string().default('0.0.0.0'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    TRUST_PROXY: z.string().default(''),
    HANDSTAMP_INSTANCE_NAME: z.string().trim().min(1).max(60).default('Handstamp'),
    HANDSTAMP_CLIENTS_FILE: z.string().default(''),
    SESSION_MAX_DAYS: positive(14),
    REFRESH_TOKEN_DAYS: positive(14),
    ACCESS_TOKEN_MINUTES: positive(10),
    ID_TOKEN_MINUTES: positive(60),
    KEY_ROTATION_DAYS: z.coerce.number().int().min(0).default(90),
    KEY_STAGE_HOURS: positive(24),
    ALLOW_PRIVATE_NETWORKS: flag,
    RATE_LIMIT_SCALE: z.coerce.number().positive().max(1000).default(1),
    HANDSTAMP_DEV_LOGIN: flag,
    HANDSTAMP_CONFORMANCE_MODE: flag,
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  })
  .superRefine((env, ctx) => {
    try {
      parseRootKey(env.HANDSTAMP_SECRET_KEY);
    } catch {
      ctx.addIssue({
        code: 'custom',
        path: ['HANDSTAMP_SECRET_KEY'],
        message:
          'HANDSTAMP_SECRET_KEY must be base64 for at least 32 bytes (openssl rand -base64 32)',
      });
    }
    // The dev test account is a back door by design. It exists only for local work and the
    // conformance suite, and never on a real hostname (S17).
    if (env.HANDSTAMP_DEV_LOGIN) {
      const local = isLocalHost(env.HANDSTAMP_ISSUER.hostname);
      const allowed =
        env.NODE_ENV !== 'production' ? local : env.HANDSTAMP_CONFORMANCE_MODE && local;
      if (!allowed)
        ctx.addIssue({
          code: 'custom',
          path: ['HANDSTAMP_DEV_LOGIN'],
          message:
            'HANDSTAMP_DEV_LOGIN only works on localhost, *.localhost or *.test issuers, and in production only with HANDSTAMP_CONFORMANCE_MODE=1',
        });
    }
  });

export type Env = z.output<typeof schema> & {
  secretKey: Buffer;
  trustProxy: false | number | string[];
};

export function parseEnv(source: Record<string, string | undefined>): Env {
  const result = schema.safeParse(source);
  if (!result.success) {
    // Name the variables only. Values may be secrets.
    const problems = result.error.issues.map((i) => `  ${i.path.join('.') || 'env'}: ${i.message}`);
    throw new Error(`Handstamp can't start. Check these settings:\n${problems.join('\n')}`);
  }
  const env = result.data;
  return {
    ...env,
    secretKey: parseRootKey(env.HANDSTAMP_SECRET_KEY),
    trustProxy: parseTrustProxy(env.TRUST_PROXY),
  };
}

// Never `true`: trusting every hop would let any client spoof X-Forwarded-For and dodge rate limits.
export function parseTrustProxy(value: string): false | number | string[] {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  return trimmed
    .split(',')
    .map((part) => part.trim())
    .filter(Boolean);
}

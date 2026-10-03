import { randomBytes } from 'node:crypto';
import { sha256 } from './crypto/envelope.ts';

// Crockford base32: no I, L, O or U, so codes read aloud or retyped from logs survive.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

// The one-time setup code printed at first boot: HS-XXXXX-XXXXX-XXXXX-XXXXX (100 bits).
export function newSetupCode() {
  const bytes = randomBytes(20);
  const chars = [...bytes].map((b) => ALPHABET[b & 31]).join('');
  return `HS-${chars.match(/.{5}/g)!.join('-')}`;
}

// Forgiving about case, spaces, dashes and look-alike letters; strict about everything else.
export function normalizeSetupCode(input: string) {
  return input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/^HS/, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

export function hashSetupCode(input: string) {
  return sha256(`setup:${normalizeSetupCode(input)}`);
}

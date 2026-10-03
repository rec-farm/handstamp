import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

// Every secret stored at rest is sealed with a subkey derived from HANDSTAMP_SECRET_KEY, one per
// purpose, so a leaked ciphertext of one kind can never be opened as another.
export type KeyPurpose =
  | 'client-secrets'
  | 'signing-keys'
  | 'cookie-keys'
  | 'console-client'
  | 'upstream-secrets'
  | 'state-cookies'
  | 'csrf';

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export function parseRootKey(value: string): Buffer {
  const key = Buffer.from(value, 'base64');
  if (key.length < 32) throw new Error('HANDSTAMP_SECRET_KEY must decode to at least 32 bytes');
  return key;
}

export function deriveKey(root: Buffer, purpose: KeyPurpose, length = 32): Buffer {
  return Buffer.from(hkdfSync('sha256', root, 'handstamp', purpose, length));
}

// Layout: version (1) · iv (12) · tag (16) · ciphertext. `aad` binds the ciphertext to its row
// (e.g. the client ID), so swapping ciphertexts between rows fails to decrypt.
export function seal(key: Buffer, plaintext: Buffer | string, aad = ''): Buffer {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), body]);
}

export function open(key: Buffer, sealed: Buffer, aad = ''): Buffer {
  if (sealed.length < 1 + IV_BYTES + TAG_BYTES || sealed[0] !== VERSION)
    throw new Error('Unsupported sealed value');
  const iv = sealed.subarray(1, 1 + IV_BYTES);
  const tag = sealed.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(sealed.subarray(1 + IV_BYTES + TAG_BYTES)),
    decipher.final(),
  ]);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function sha256(value: string | Buffer): Buffer {
  return createHash('sha256').update(value).digest();
}

export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

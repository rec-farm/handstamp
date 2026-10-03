import { describe, expect, it } from 'vitest';
import { deriveKey, open, parseRootKey, randomToken, seal } from './envelope.ts';

const root = parseRootKey(Buffer.alloc(32, 7).toString('base64'));

describe('envelope', () => {
  it('round-trips a sealed value', () => {
    const key = deriveKey(root, 'client-secrets');
    expect(open(key, seal(key, 'hs_sec_value', 'paramtune'), 'paramtune').toString()).toBe(
      'hs_sec_value',
    );
  });

  it('refuses a ciphertext moved to another row', () => {
    const key = deriveKey(root, 'client-secrets');
    expect(() => open(key, seal(key, 'secret', 'paramtune'), 'stillup')).toThrow();
  });

  it('refuses a ciphertext opened with another purpose key', () => {
    const sealed = seal(deriveKey(root, 'client-secrets'), 'secret');
    expect(() => open(deriveKey(root, 'signing-keys'), sealed)).toThrow();
  });

  it('refuses a tampered ciphertext', () => {
    const key = deriveKey(root, 'cookie-keys');
    const sealed = seal(key, 'secret');
    sealed[sealed.length - 1] ^= 1;
    expect(() => open(key, sealed)).toThrow();
  });

  it('rejects a short root key', () => {
    expect(() => parseRootKey(Buffer.alloc(16).toString('base64'))).toThrow(/32 bytes/);
  });

  it('makes url-safe tokens', () => {
    expect(randomToken()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});

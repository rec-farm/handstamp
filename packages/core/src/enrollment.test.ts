import { describe, expect, it } from 'vitest';
import { hashSetupCode, newSetupCode, normalizeSetupCode } from './enrollment.ts';

describe('setup codes', () => {
  it('look like HS-XXXXX-XXXXX-XXXXX-XXXXX in Crockford base32', () => {
    expect(newSetupCode()).toMatch(/^HS-([0-9A-HJKMNP-TV-Z]{5}-){3}[0-9A-HJKMNP-TV-Z]{5}$/);
  });

  it('forgive case, spacing and look-alike letters', () => {
    const code = 'HS-0A1B2-C3D4E-F5G6H-J7K8M';
    expect(hashSetupCode(' hs-0a1b2 c3d4e-f5g6h-j7k8m ')).toEqual(hashSetupCode(code));
    expect(normalizeSetupCode('hs-oaib2')).toBe('0A1B2');
  });

  it('hash different codes differently', () => {
    expect(hashSetupCode(newSetupCode())).not.toEqual(hashSetupCode(newSetupCode()));
  });
});

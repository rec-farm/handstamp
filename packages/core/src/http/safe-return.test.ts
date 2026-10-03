import { describe, expect, it } from 'vitest';
import { safeReturnPath } from './safe-return.ts';

describe('safeReturnPath', () => {
  it.each([
    ['/admin/clients', '/admin/clients'],
    ['/account?tab=passkeys#add', '/account?tab=passkeys#add'],
    ['/a/../admin', '/admin'],
    // Percent-encoded CR/LF stays encoded, so it can't split a header.
    ['/%0d%0aLocation:evil', '/%0d%0aLocation:evil'],
  ])('keeps same-origin path %s', (input, expected) => {
    expect(safeReturnPath(input)).toBe(expected);
  });

  it.each([
    'https://evil.example',
    '//evil.example/path',
    '/\\evil.example',
    '\\\\evil.example',
    'javascript:alert(1)',
    '/\tadmin',
    'admin',
    '',
    undefined,
    42,
    '/' + 'a'.repeat(3000),
  ])('falls back for %s', (input) => {
    expect(safeReturnPath(input, '/fallback')).toBe('/fallback');
  });
});

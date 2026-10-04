import { describe, expect, it } from 'vitest';
import { passkeyUserName, relyingParty } from './passkeys.ts';

const rp = relyingParty(new URL('https://id.rec.farm'), 'Handstamp');

describe('passkey user name', () => {
  it('prefers the email, then the username', () => {
    expect(passkeyUserName(rp, { displayName: 'REC', email: 'r@rec.cool', username: 'rec' })).toBe(
      'r@rec.cool',
    );
    expect(passkeyUserName(rp, { displayName: 'REC', email: null, username: 'rec' })).toBe('rec');
  });

  it('names the instance host when there is no identifier', () => {
    expect(passkeyUserName(rp, { displayName: 'REC', email: '' })).toBe('REC (id.rec.farm)');
  });
});

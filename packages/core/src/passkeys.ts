import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';

export type { AuthenticationResponseJSON, RegistrationResponseJSON };

// Passkey policy (S12): user verification always, discoverable credentials always (sign-in has
// no username step), challenges single-use for 5 minutes, RP ID = the issuer's host.
export const CHALLENGE_TTL_SECONDS = 5 * 60;
const ALGORITHMS = [-7, -8, -257]; // ES256, EdDSA, RS256

export type RelyingParty = { id: string; name: string; origin: string };

export function relyingParty(issuer: URL, name: string): RelyingParty {
  return { id: issuer.hostname, name, origin: issuer.origin };
}

export class PasskeyError extends Error {
  constructor(
    readonly code: 'invalid' | 'counter' | 'unknown_credential',
    message: string,
  ) {
    super(message);
  }
}

export type StoredPasskey = {
  credentialId: string;
  publicKey: Uint8Array;
  signCount: number;
  transports: string[];
};

export function registrationOptions(
  rp: RelyingParty,
  user: { handle: string; name: string; displayName: string },
  existing: { credentialId: string; transports: string[] }[],
) {
  return generateRegistrationOptions({
    rpName: rp.name,
    rpID: rp.id,
    userID: Buffer.from(user.handle, 'base64url'),
    userName: user.name,
    userDisplayName: user.displayName,
    attestationType: 'none',
    excludeCredentials: existing.map((p) => ({ id: p.credentialId, transports: p.transports })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    supportedAlgorithmIDs: ALGORITHMS,
  });
}

export async function verifyRegistration(
  rp: RelyingParty,
  response: RegistrationResponseJSON,
  expectedChallenge: string,
) {
  let result;
  try {
    result = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      requireUserVerification: true,
      supportedAlgorithmIDs: ALGORITHMS,
    });
  } catch (error) {
    throw new PasskeyError('invalid', (error as Error).message);
  }
  if (!result.verified) throw new PasskeyError('invalid', 'The passkey could not be verified.');
  const info = result.registrationInfo;
  return {
    credentialId: info.credential.id,
    publicKey: Buffer.from(info.credential.publicKey),
    signCount: info.credential.counter,
    transports: info.credential.transports ?? [],
    aaguid: info.aaguid,
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
  };
}

export function authenticationOptions(rp: RelyingParty) {
  // Empty allowCredentials: the browser offers every passkey it has for this site.
  return generateAuthenticationOptions({ rpID: rp.id, userVerification: 'required' });
}

export async function verifyAuthentication(
  rp: RelyingParty,
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  stored: StoredPasskey,
) {
  let result;
  try {
    result = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: rp.origin,
      expectedRPID: rp.id,
      requireUserVerification: true,
      credential: {
        id: stored.credentialId,
        publicKey: new Uint8Array(stored.publicKey),
        counter: stored.signCount,
        transports: stored.transports as never,
      },
    });
  } catch (error) {
    throw new PasskeyError('invalid', (error as Error).message);
  }
  if (!result.verified) throw new PasskeyError('invalid', 'The passkey could not be verified.');
  const { newCounter, credentialBackedUp } = result.authenticationInfo;
  // Synced passkeys report 0 forever. A counter that goes backwards means a cloned authenticator.
  if ((newCounter > 0 || stored.signCount > 0) && newCounter <= stored.signCount)
    throw new PasskeyError('counter', 'This passkey reported an out-of-order counter.');
  return { signCount: newCounter, backedUp: credentialBackedUp };
}

// The challenge the browser signed, read from clientDataJSON, so we can find its stored record.
export function challengeOf(response: { response: { clientDataJSON: string } }) {
  try {
    const data = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString());
    return typeof data.challenge === 'string' ? (data.challenge as string) : undefined;
  } catch {
    return undefined;
  }
}

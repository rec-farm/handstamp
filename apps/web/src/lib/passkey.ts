import {
  browserSupportsWebAuthn,
  startAuthentication,
  startRegistration,
  WebAuthnError,
} from '@simplewebauthn/browser';

export const passkeysSupported = browserSupportsWebAuthn;

// Browser errors in plain words (§12: what happened, what to do next).
export function passkeyErrorMessage(error: unknown) {
  const name =
    error instanceof WebAuthnError ? (error.cause as Error)?.name : (error as Error)?.name;
  if (name === 'NotAllowedError' || name === 'AbortError')
    return 'The passkey prompt was closed. Try again when you are ready.';
  if (name === 'InvalidStateError') return 'This device already has a passkey for this account.';
  if (name === 'SecurityError')
    return "Passkeys don't work on this address. Open Handstamp at its usual URL.";
  return (
    (error as Error)?.message ||
    "Your browser couldn't use a passkey. Try again or use another device."
  );
}

export const signWithPasskey = (
  optionsJSON: Parameters<typeof startAuthentication>[0]['optionsJSON'],
) => startAuthentication({ optionsJSON });

export const createPasskey = (
  optionsJSON: Parameters<typeof startRegistration>[0]['optionsJSON'],
) => startRegistration({ optionsJSON });

// A sensible default name: "Passkey on Mac", "Passkey on iPhone", …
export function defaultPasskeyName() {
  const ua = navigator.userAgent;
  const device = /iPhone/.test(ua)
    ? 'iPhone'
    : /iPad/.test(ua)
      ? 'iPad'
      : /Android/.test(ua)
        ? 'Android'
        : /Mac/.test(ua)
          ? 'Mac'
          : /Windows/.test(ua)
            ? 'Windows'
            : /Linux/.test(ua)
              ? 'Linux'
              : 'this device';
  return `Passkey on ${device}`;
}

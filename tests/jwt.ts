const part = (jwt: string, index: number) =>
  JSON.parse(Buffer.from(jwt.split('.')[index], 'base64url').toString()) as Record<string, unknown>;

export const decodeProtectedHeader = (jwt: string) => part(jwt, 0);
export const decodeJwt = (jwt: string) => part(jwt, 1);

// Checks an RS256 JWS against the issuer's JWKS, the way a relying party would.
export async function verifyJws(jwt: string, issuer: string) {
  const { createPublicKey, verify } = await import('node:crypto');
  const { kid } = decodeProtectedHeader(jwt);
  const { keys } = (await (await fetch(`${issuer}/jwks`)).json()) as {
    keys: { kid: string }[];
  };
  const jwk = keys.find((k) => k.kid === kid);
  if (!jwk) return false;
  const [header, payload, signature] = jwt.split('.');
  return verify(
    'RSA-SHA256',
    Buffer.from(`${header}.${payload}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(signature, 'base64url'),
  );
}

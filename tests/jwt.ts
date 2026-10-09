const part = (jwt: string, index: number) =>
  JSON.parse(Buffer.from(jwt.split('.')[index], 'base64url').toString()) as Record<string, unknown>;

export const decodeProtectedHeader = (jwt: string) => part(jwt, 0);
export const decodeJwt = (jwt: string) => part(jwt, 1);

import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

// A software WebAuthn authenticator for tests: real P-256 keys, "none" attestation, user
// verification always on. Lets the integration tests run real passkey ceremonies.

function head(major: number, n: number) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

type Cbor = number | string | Buffer | Map<number | string, Cbor> | { [k: string]: Cbor };
function cbor(value: Cbor): Buffer {
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  const entries = value instanceof Map ? [...value] : Object.entries(value);
  return Buffer.concat([
    head(5, entries.length),
    ...entries.flatMap(([k, v]) => [cbor(k), cbor(v)]),
  ]);
}

const b64 = (b: Buffer) => b.toString('base64url');
const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest();

type Credential = { id: Buffer; key: KeyObject; userHandle: string; counter: number };

export class SoftAuthenticator {
  readonly credentials: Credential[] = [];

  constructor(
    public origin: string,
    public rpId = new URL(origin).hostname,
    // Synced passkeys always report counter 0; hardware keys count up.
    readonly counting = true,
  ) {}

  #authData(flags: number, counter: number, attested?: Buffer) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    return Buffer.concat([
      sha256(this.rpId),
      Buffer.from([flags]),
      count,
      ...(attested ? [attested] : []),
    ]);
  }

  create(options: { challenge: string; user: { id: string } }) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credential: Credential = {
      id: randomBytes(16),
      key: privateKey,
      userHandle: options.user.id,
      counter: 0,
    };
    this.credentials.push(credential);
    const cose = cbor(
      new Map<number, Cbor>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(jwk.x!, 'base64url')],
        [-3, Buffer.from(jwk.y!, 'base64url')],
      ]),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(credential.id.length);
    const attested = Buffer.concat([Buffer.alloc(16), idLength, credential.id, cose]);
    // UP | UV | AT
    const authData = this.#authData(0x01 | 0x04 | 0x40, 0, attested);
    const clientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.create',
        challenge: options.challenge,
        origin: this.origin,
      }),
    );
    return {
      id: b64(credential.id),
      rawId: b64(credential.id),
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64(clientData),
        attestationObject: b64(cbor({ fmt: 'none', attStmt: {}, authData })),
        transports: ['internal' as const],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform' as const,
    };
  }

  get(options: { challenge: string }, credential = this.credentials[0]) {
    if (this.counting) credential.counter += 1;
    const authData = this.#authData(0x01 | 0x04, credential.counter);
    const clientData = Buffer.from(
      JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: this.origin }),
    );
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientData)]), credential.key);
    return {
      id: b64(credential.id),
      rawId: b64(credential.id),
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64(clientData),
        authenticatorData: b64(authData),
        signature: b64(signature),
        userHandle: credential.userHandle,
      },
      clientExtensionResults: {},
    };
  }
}

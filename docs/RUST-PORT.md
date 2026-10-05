# Rust port

> Status: **spike (2026-10-05).** `backend/` boots on the same database as the Node server and serves health, discovery, JWKS and the SPA. Every OIDC and API endpoint answers `501`. The Node image (`Dockerfile`) is still the only deployable Handstamp.

Paramtune moved its backend to Rust (axum). This is the plan for doing the same here without giving up what makes Handstamp trustworthy: certified protocol behavior and one database that either runtime can run on.

## Why this is a separate track

Paramtune is an OIDC _client_, and the `openidconnect` crate covers that. Handstamp is the _provider_. Rust has no maintained, OpenID-certified provider library comparable to `oidc-provider`, so porting means writing `/auth`, `/token`, PKCE, refresh rotation, `/session/end`, back-channel logout and key rotation ourselves. CLAUDE.md forbids that today ("never hand-roll the protocol"). PLAN R19 keeps production on Node. The port can replace it only after it passes the gates below, and the owner then changes the hard rule on purpose.

## What the spike proves

| Area               | Rust (`backend/src`)                                                                               | Checked by                                               |
| ------------------ | -------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| Migrations         | Embeds `packages/db/migrations` at build time; same `handstamp_migrations` table and advisory lock | `rust-parity.test.ts`                                    |
| Sealed secrets     | HKDF-SHA256 per purpose + AES-256-GCM, same layout and AAD as `envelope.ts`                        | `crypto.rs` tests open a value sealed by Node            |
| Signing keys       | First-boot RS256 key, RFC 7638 `kid`, sealed private JWK; opens keys Node wrote                    | `keys.rs` tests, `rust-parity.test.ts` (both directions) |
| Discovery and JWKS | Same metadata; endpoint URLs follow the request like Koa (`TRUST_PROXY` → `X-Forwarded-*`)         | `rust-parity.test.ts` compares the documents             |
| SPA shell          | `UI_PATHS`, `/assets` immutable caching, the same CSP with inline-script hashes, base headers      | `rust-parity.test.ts` compares the CSP; `web.rs` tests   |
| Health             | `/healthz`, `/readyz` (503 without the database)                                                   | Container smoke test                                     |

Measured on the same machine against an empty database:

|                   | Node (`Dockerfile`) | Rust spike (`Dockerfile.rust`) |
| ----------------- | ------------------- | ------------------------------ |
| Image             | 205 MB              | 21 MB (2.6 MB binary)          |
| Ready (`/readyz`) | 0.48 s              | 0.37 s, including RSA keygen   |
| Memory after boot | ~103 MiB            | ~1.2 MiB                       |

The spike does almost nothing yet, so its memory figure is a floor, not a forecast.

## Still on Node

Port in this order. Each step lands with its tests, and every protocol step must keep the conformance suite green.

1. **Storage for protocol state**: the `oidc_payloads` adapter (sessions, grants, codes, tokens, interactions), cookie keys and their rotation, and the key-lifecycle scheduler (stage, promote, retire) under the same advisory lock.
2. **Clients**: the declared clients file, the `handstamp-console` client (HKDF-derived secret), secret verification for `client_secret_basic` and `client_secret_post`.
3. **Authorization code flow**: `/auth` (GET and POST), interactions, consent and first-party skip, PKCE S256, `prompt`, `max_age`, `id_token_hint`, `claims`, `iss` in the response, `form_post`.
4. **Tokens**: `/token` (code and refresh, with rotation and reuse detection), ID token and access token signing, `/me`, introspection, revocation.
5. **Logout**: `/session/end` with its confirm page, back-channel logout (private networks refused unless `ALLOW_PRIVATE_NETWORKS`).
6. **Interaction API**: passkeys (WebAuthn via `webauthn-rs`), enrollment, setup claim, recovery, upstream sign-in (via `openidconnect`), the dev test user.
7. **Console API**: `/api/me/*`, `/api/admin/*` (including the audit CSV), audit writes.
8. **Cross-cutting**: rate limits, log redaction (S9), cookies (`__Host-` and `__Secure-`), CSRF, conformance mode, the `handstamp` CLI, Postgres TLS (the spike connects without TLS).

Crates: axum and tokio, as in Paramtune; `tokio-postgres` + `deadpool-postgres`; `aes-gcm`, `hkdf` and `sha2` for the envelope. `rsa` generates keys only. For signing, prefer `aws-lc-rs` over `rsa` because of RUSTSEC-2023-0071 (Marvin). `webauthn-rs` for passkeys, `openidconnect` for upstream IdPs.

## Gates before Rust replaces Node

- [ ] `./conformance/run.sh full` passes against the `Dockerfile.rust` image, with no new entries in `conformance/expected-*.json`.
- [ ] `pnpm e2e` passes against the Rust server (claim, passkey sign-in, consent, logout, admin).
- [ ] Rollback is safe: Node and Rust run on one database in both directions for every table either one writes (`rust-parity.test.ts` grows with the port).
- [ ] Every security requirement in PLAN §4 (S1–S20) maps to a Rust test.
- [ ] The owner updates the CLAUDE.md hard rule and PLAN R19 in the same PR that switches `Dockerfile`.

## Working on it

```sh
pnpm backend:check   # cargo fmt --check + clippy -D warnings
pnpm backend:test    # cargo test, release build, then the Node/Rust parity test (needs the dev Postgres)
pnpm backend:build   # backend/target/release/handstamp-server
docker build -f Dockerfile.rust -t handstamp:rust .
```

The binary reads the same environment as the Node server (`HANDSTAMP_ISSUER`, `DATABASE_URL`, `HANDSTAMP_SECRET_KEY`, `HOST`, `PORT`, `TRUST_PROXY`), plus `HANDSTAMP_WEB_DIST` (default `../apps/web/dist`).

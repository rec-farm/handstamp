# Rust port

> Status: **done (2026-10-08).** The Node server (Fastify, `oidc-provider`, Drizzle) is gone. `backend/` is the whole server and CLI: one binary, 30 MB as an image. See PLAN R20.

Paramtune moved its backend to Rust. Handstamp followed, all the way: the OpenID provider itself is now Rust. That was the hard part, because Paramtune is an OIDC _client_ (the `openidconnect` crate does the work) while Handstamp is the _provider_, and Rust has no certified provider library comparable to `oidc-provider`. So the port is written to `oidc-provider` 9's behaviour, as Handstamp configured it, and held to the same evidence that made the Node server trustworthy.

## The bar it cleared

- **OpenID conformance**: `./conformance/run.sh full` against the Rust image: Config OP and the full Basic OP plan, 26 passed, 4 for review (screenshots), 4 skipped, 2 warnings. Identical to Node, with no change to `conformance/expected-*.json`.
- **Flow tests**: the 64 integration tests that drove the Node server (OIDC, passkeys, upstream sign-in, admin) now start the `handstamp` binary and talk to it over HTTP (`tests/`). The only test logic that changed: the two checks that faked the clock in-process for the 5-minute step-up window are now a Rust unit test (`console::tests::step_up_window_is_five_minutes`).
- **Browser tests**: `pnpm e2e` (claim, passkeys, sign-in to an app, sign out everywhere, admin) in Chromium with a virtual authenticator.
- **Security checklist**: every item in PLAN §4 points at Rust code and a test.
- **Existing data**: the schema is the one Node used (plus migration 005). Signing keys, client and upstream secrets open with the same HKDF + AES-256-GCM envelope (a unit test opens a value Node sealed), and the dev database Node created ran under the Rust server unchanged.

## Map

| Concern                                       | Node                                        | Rust (`backend/src`)                                               |
| --------------------------------------------- | ------------------------------------------- | ------------------------------------------------------------------ |
| HTTP, headers, rate limits                    | Fastify, `@fastify/rate-limit`              | axum, `app.rs`, `http.rs`                                          |
| Authorization endpoint, interactions, consent | `oidc-provider`                             | `oidc/authorize.rs`, `interaction.rs`                              |
| Token, userinfo, introspection, revocation    | `oidc-provider`                             | `oidc/token.rs`                                                    |
| Logout, back-channel logout                   | `oidc-provider`                             | `oidc/logout.rs`                                                   |
| Protocol storage                              | adapter over `oidc_payloads`                | `oidc/store.rs`, same table                                        |
| Signing keys                                  | `node:crypto` + `jose`                      | `keys.rs`, aws-lc-rs                                               |
| Passkeys                                      | SimpleWebAuthn                              | `webauthn.rs` (CBOR via ciborium, signatures via aws-lc-rs)        |
| Upstream sign-in                              | `openid-client`                             | `upstream/`, `openidconnect` crate (GitHub by hand: plain OAuth 2) |
| Console sign-in                               | `openid-client` against itself via `inject` | `console.rs`, code exchange in-process                             |
| Database                                      | Drizzle + node-postgres                     | tokio-postgres + deadpool, TLS via rustls                          |
| CLI                                           | `tsx src/cli.ts`                            | `handstamp <command>` (same binary)                                |

## Where behaviour differs from Node, on purpose

- **URLs come from the issuer.** Discovery, interaction redirects and logout actions use the configured issuer. `oidc-provider` built them from the request's Host header.
- **Codes, tokens and session IDs are stored hashed** (SHA-256), not as their value. Session cookies are 256 random bits, so they need no signing key; `cookie_keys` is no longer used.
- **Protocol state kinds are lowercase** (`session`, `grant`, …). Rows Node left behind are never read and expire: switching signs everyone out once and drops issued refresh tokens. Nothing else is lost.
- **`auth_time` is always in the ID token**, not only when requested. OIDC allows it, and apps that check it get it.
- **Back-channel logout** connects to exactly the address it checked (no DNS rebinding) and refuses more non-public ranges (CGNAT, multicast, NAT64, 6to4, IPv4-compatible IPv6).
- **Rate limits** are per route and client IP, with route keys drawn from a fixed vocabulary so random paths can't grow the table.
- **Migration 005**: a group an app requires can't be deleted from under it (`ON DELETE RESTRICT`). The admin API already refused; now the database does too.
- **CSV export** also neutralises cells starting with a tab or CR. **Recovery through an upstream provider** checks the link was really consumed, so two tabs can't both use it. **Admin-entered GitHub API URLs** must be https (or loopback).
- **Postgres TLS**: used when the server offers it, required with `?sslmode=require`, certificates checked against the Mozilla roots.
- **Logs** are JSON lines from `tracing` instead of pino; URLs are still logged by path only.
- A few validation messages that came from zod's defaults are now written out.

## Working on it

```sh
pnpm backend:check   # cargo fmt --check + clippy -D warnings
pnpm test            # Rust unit tests, then the flow tests against a debug build
pnpm e2e             # the real UI in Chromium
./conformance/run.sh full
```

Every protocol change keeps the full conformance run green with no new accepted gaps, and lands with a flow test (CLAUDE.md).

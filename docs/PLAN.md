# Handstamp v1 plan

> Status: **M5 done (2026-10-03); Rust server (2026-10-08).** The provider, APIs and CLI are one Rust binary now (R20, [RUST-PORT.md](RUST-PORT.md)), with the same conformance results. v1 scope complete: passkeys, upstream sign-in, recovery, the account page and admin console, a production image and compose file, deploy/integration/security docs, and full Basic OP + Config OP conformance. CI and the nightly conformance run are green on GitHub, and Paramtune signs in with Handstamp (§6.2). Post-v1 work is in §8.2.
> Handstamp is the passwordless OpenID Connect provider for the R.E.C. product family (RECIAM SAS).
> Siblings: Paramtune (config and schema management), StillUp (API uptime monitoring).

## 0. Summary of decisions and pushback

These are the decisions most worth reviewing. Each is explained in the section it links to.

| #   | Decision                                                                                                                                                                                                                                                                                                                                                    | Why                                                                                                                                                                                                                       |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | **One Rust process on one port.** It serves the OpenID provider (written to oidc-provider 9's behaviour), `/api/*` and the UI: a React SPA built with Vite, as static files. There is no Next.                                                                                                                                                              | The protocol endpoints and the UI share one origin, the UI has no need for server rendering, and there is no second process or internal proxy. See [§1.2](#12-single-origin-one-rust-process-serving-a-vite-spa) and R20. |
| D2  | **Handstamp's own account and admin UI is an OIDC client of itself** (a built-in `handstamp-console` client).                                                                                                                                                                                                                                               | We get one login UI, step-up through `max_age`, and "sign out everywhere" that also kills the console. We never read `oidc-provider` session internals. See [§1.3](#13-how-the-console-authenticates).                    |
| D3  | **PKCE is required by default and can be switched off per client.** It is on for every real client and off only for the conformance suite's test clients, if the suite needs that.                                                                                                                                                                          | The Basic OP plan may send requests without PKCE. To be confirmed in M1. See [§4](#4-security-checklist).                                                                                                                 |
| D4  | **`__Host-` cookies for every cookie we name.** For `oidc-provider`'s path-scoped interaction cookies we force `path=/`, and fall back to `__Secure-` if the library refuses.                                                                                                                                                                               | `__Host-` requires `Path=/`, but `oidc-provider` scopes `_interaction` to `/interaction/:uid`. To be confirmed in M1.                                                                                                     |
| D5  | **Client secrets are stored encrypted (AES-256-GCM), not hashed.** They are shown once, at creation or rotation.                                                                                                                                                                                                                                            | `oidc-provider` compares the plaintext secret for `client_secret_basic` and `client_secret_post`, and has no hook for hashed secrets.                                                                                     |
| D6  | **`groups` goes in the ID token (and userinfo) when the `groups` scope is granted. `profile` and `email` claims stay in userinfo only**, the spec default. _(Revised in M1: the first draft put every scope claim in the ID token, which the conformance suite flags under OIDC Core 5.4 because it exposes the email to anyone the ID token is shown to.)_ | The brief asks for `groups` in the ID token. Everything else follows the spec and shares less.                                                                                                                            |
| D7  | **Instance settings come from environment variables. Clients, groups and upstream providers live in the database** and are managed in the admin UI. Env vars can seed upstream providers, and `HANDSTAMP_CLIENTS_FILE` can declare clients. Seeded providers and declared clients are read-only in the UI.                                                  | "Everything through env" doesn't scale to clients created at runtime, but deploys should still be reproducible. See [§8](#8-resolved-decisions) R6.                                                                       |
| D8  | **Invite-only by default.** Self sign-up is opt-in per upstream provider, with an email-domain or GitHub-org allowlist.                                                                                                                                                                                                                                     | An open IdP lets anyone create an account in every app that trusts it. See R2.                                                                                                                                            |
| D9  | **The wordmark and mark are the outlined assets from `rec-brand` (brand v1.7.0, 2026-10-10).** _(Was live text in Archivo with a TODO until the mark existed.)_                                                                                                                                                                                             | DESIGN §2.9 forbids live-text wordmarks; `rec-brand/build.py` now generates the Handstamp mark, lockups and favicon.                                                                                                      |
| D10 | **v1 shipped as a single replica; more work since 2026-10-10.** Rate limits moved from memory to an unlogged Postgres table, and a booting replica keeps a setup code another printed in the last 30 seconds. Keys were already picked up by polling and maintenance already ran under an advisory lock.                                                    | Scaling out needed no redesign, as planned. See R5.                                                                                                                                                                       |

---

## 1. Architecture

### 1.1 Components

```mermaid
flowchart LR
  subgraph Browser
    UI[Sign-in / consent / account / admin pages]
    WA[WebAuthn API]
  end
  RP[REC app<br/>Paramtune · StillUp · …]
  subgraph Handstamp["Handstamp container (one public port)"]
    E[axum :3000<br/>headers · rate limits · routing]
    OP[OpenID provider<br/>/auth /token /me /jwks<br/>/session/end /.well-known]
    API[Interaction + console + admin API<br/>/interaction/:uid/* /api/*]
    N[Static UI · React SPA built by Vite<br/>/interaction/:uid /account /admin /setup]
    DB[(Postgres<br/>backend/migrations)]
  end
  UP[Upstream IdPs<br/>GitHub · Google · generic OIDC]

  Browser -- HTTPS --> E
  RP -- "/token, /me, /jwks (back channel)" --> E
  E --> OP
  E --> API
  E -- "index.html + /assets" --> N
  OP --> DB
  API --> DB
  API -- "openidconnect crate" --> UP
  OP -- "back-channel logout" --> RP
```

| Path                                                                                                                 | Owner (`backend/src`)              | Notes                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------- | ---------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `/.well-known/openid-configuration`, `/jwks`                                                                         | `oidc/discovery.rs`                | The issuer is a bare origin. Endpoint URLs always come from the configured issuer, never the Host header.                     |
| `/auth`, `/auth/:uid`                                                                                                | `oidc/authorize.rs`                | Request validation, session, grant, the login → access → consent policy, the code. `/auth/:uid` resumes after an interaction. |
| `/token`, `/me`, `/token/introspection`, `/token/revocation`                                                         | `oidc/token.rs`                    | Code exchange with PKCE, refresh rotation with reuse detection, userinfo, introspection, revocation.                          |
| `/session/end`, `/session/end/confirm`, `/session/end/success`                                                       | `oidc/logout.rs`                   | RP-initiated logout and back-channel logout.                                                                                  |
| `/interaction/:uid/*` (e.g. `/details`, `/dev-login`, `/consent`, `/abort`, passkeys, setup, enrollment)             | `interaction.rs`                   | JSON. CSRF-checked. Rate-limited. Under the interaction path because the interaction cookie is scoped to `/interaction/:uid`. |
| `/interaction/:uid/upstream/:slug`, `/upstream/:slug/callback`, `/interaction/:uid/upstream/complete`                | `upstream/routes.rs`               | Upstream OAuth/OIDC client, via the `openidconnect` crate (GitHub by hand: it is plain OAuth 2).                              |
| `/api/me/*`, `/api/instance`, `/api/enroll`                                                                          | `console.rs`, `interaction.rs`     | Requires the console session cookie (except `/api/instance` and `/api/enroll`).                                               |
| `/api/admin/*`                                                                                                       | `admin.rs`                         | Admins only; writes need CSRF and a recent passkey step-up.                                                                   |
| `/console/login`, `/console/callback`, `/console/logout`                                                             | `console.rs`                       | The console's own OIDC client. The code exchange runs in-process.                                                             |
| `/healthz`, `/readyz`                                                                                                | `app.rs`                           | Not rate-limited. No database details in the response.                                                                        |
| `/assets/*`                                                                                                          | `app.rs` (`tower-http` `ServeDir`) | Hashed Vite build output, `Cache-Control: immutable`.                                                                         |
| UI routes: `/`, `/interaction/:uid`, `/setup`, `/account`, `/admin/*`, `/logout`, `/signed-out`, `/error`, `/enroll` | `app.rs` (SPA)                     | Returns `index.html` with `no-store`. The SPA reads and writes only through `/api/*`. Unknown paths return 404.               |

Every route is in this explicit table. There is no catch-all, so a typo'd protocol path 404s instead of silently returning the SPA.

### 1.2 Single origin: one Rust process serving a Vite SPA

**Choice:** one process, one public port.

- **The server** (`backend/`, axum on tokio) listens on `PORT` (default 3000). It serves the OpenID provider, the JSON API and the static UI. Rate limits, `TRUST_PROXY`, security headers and log redaction sit in one place, in front of everything.
- **The UI** is a React 19 SPA built by Vite (`apps/web` → `apps/web/dist`), with Tailwind v4 via `@tailwindcss/vite`, lucide-react and React Router in library mode. Data goes through small `fetch` wrappers over `/api/*`. No server rendering.
- **Code splitting:** the sign-in, consent, claim and logout pages are one small chunk. The account and admin console is a separate chunk that the sign-in page never loads.
- **Auth gating** happens in the API: console routes return 401 and the SPA redirects to `/console/login`. The UI shell itself holds no data.
- **CSP:** a static bundle runs under `script-src 'self'` plus one hash for the inline theme script (DESIGN §14.2), with no per-request nonces.
- **Local development:** the `dev` script (`scripts/dev.ts`) runs the Rust server and the Vite dev server as one origin, like Paramtune: Vite owns the public port and serves the UI with hot reload, and proxies the protocol and API paths to the Rust server. Server-rendered views (logout, errors) are drawn from Vite's `index.html` (`HANDSTAMP_VITE_URL`), so cookies, WebAuthn and redirects behave as in production.
- **Production image:** `rust:alpine` builds a static binary; the runtime is Alpine with that binary and the SPA build. 30 MB (the Node image was 205 MB, and 644 MB before that), and the `handstamp` CLI is the same binary.

**Why not Next?** Nothing here needs server rendering or SEO: every page is a sign-in card or sits behind sign-in, and passkeys need JavaScript anyway. Next would mean either a second process with an internal proxy, or Next's custom-server API. Paramtune has since moved to the same Vite + React Router setup. The React components and the Tailwind tokens carry over unchanged either way.

**Why not put the UI in front (the StillUp model)?** `/token`, `/auth` and `/session/end` need exact headers, `WWW-Authenticate`, form bodies, redirects and cookies. A proxy in an app framework rewrites or buffers them. (Development is the exception: Vite's proxy passes them through untouched.)

### 1.3 How the console authenticates

`/account` and `/admin` are served by a built-in, non-deletable, confidential, first-party client called `handstamp-console`. Its secret is derived from `HANDSTAMP_SECRET_KEY` with HKDF.

1. When there is no console session, the API returns 401 and the SPA redirects to `/console/login`. That starts a normal `/auth` request with PKCE.
2. After the user signs in, `/console/callback` exchanges the code. It then sets `__Host-hs_console`, an encrypted cookie holding `{ sub, sid, auth_time, amr, exp }`.
3. On every `/api/me/*` and `/api/admin/*` request, the server checks that the OP session still exists. Signing out everywhere or revoking a session from the admin UI therefore also kills the console immediately.
4. **Step-up:** a sensitive action (link or unlink an identity, add or remove a passkey, mint a recovery link, rotate keys, edit a client) needs `auth_time` within the last 5 minutes. If it's older, the UI restarts `/auth` with `max_age=0` and the action resumes afterwards.

### 1.4 Request flows

#### A. A REC app signs a user in with a passkey

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant RP as REC app
  participant OP as OpenID provider
  participant API as Interaction API
  participant N as SPA
  participant DB as Postgres
  RP->>B: 302 /auth?client_id&redirect_uri&scope=openid profile email groups&state&nonce&code_challenge(S256)
  B->>OP: GET /auth
  OP->>DB: Client.find, exact redirect_uri match, PKCE check
  OP->>DB: save Interaction(uid)
  OP->>B: 303 /interaction/{uid} + __Host-hs_interaction
  B->>N: GET /interaction/{uid} (static index.html)
  N->>API: GET /interaction/{uid}
  API-->>N: client name, prompt, enabled providers, csrf token
  N-->>B: Sign-in card (passkey first, then upstreams)
  B->>API: POST /interaction/{uid}/passkey/options
  API->>DB: store challenge (bound to uid, 5 min, single use)
  API-->>B: PublicKeyCredentialRequestOptions (discoverable, UV required)
  B->>B: navigator.credentials.get()
  B->>API: POST /interaction/{uid}/passkey/verify
  API->>DB: consume challenge, load passkey by credential id, verify, bump counter
  API->>API: user active? in the client's required group?
  API->>OP: interactionResult({ login: { accountId, amr, remember } })
  API-->>B: { redirectTo: /auth/{uid} }
  B->>OP: GET /auth/{uid}
  alt first-party client
    OP->>OP: loadExistingGrant creates the grant automatically
  else third-party client
    OP->>B: 303 /interaction/{uid} (prompt=consent) → consent page → POST /interaction/{uid}/consent
  end
  OP->>B: 303 redirect_uri?code&state&iss
  RP->>OP: POST /token (client auth + code_verifier)
  OP-->>RP: id_token (RS256, kid) + access_token + refresh_token
  RP->>OP: GET /me (optional)
```

#### B. A REC app signs a user in through GitHub

The flow is the same as A up to the sign-in card. Then:

```mermaid
sequenceDiagram
  autonumber
  participant B as Browser
  participant API as Upstream client
  participant GH as GitHub
  participant OP as OpenID provider
  participant DB as Postgres
  B->>API: GET /api/upstream/github/start?interaction={uid}
  API->>DB: verify uid exists and is pending
  API->>B: 302 github.com/login/oauth/authorize (state, PKCE) + __Host-hs_upstream (encrypted: state, verifier, uid, purpose=login, 10 min)
  B->>GH: authorize
  GH->>B: 302 /api/upstream/github/callback?code&state
  B->>API: callback
  API->>API: state matches cookie, cookie uid still pending, cookie cleared
  API->>GH: exchange code, GET /user (numeric id), GET /user/emails, org check if configured
  API->>DB: find identity (issuer="https://github.com", subject=<numeric id>)
  alt identity found
    API->>API: user active? required group?
  else not found and sign-up allowed by provider policy
    API->>DB: create user + identity (email only if verified and not held by another user)
  else not found and sign-up closed
    API-->>B: 303 /interaction/{uid}?error=unlinked_identity
  end
  API->>OP: interactionResult({ login })
  API-->>B: 303 /auth/{uid}
  Note over B,OP: continues as A from step 15
```

An email match **never** links accounts. If the GitHub identity is unknown and sign-up is closed, the card says:
_"This GitHub account isn't connected to Handstamp yet. Sign in another way and link it from your account page, or ask your admin for an invite."_ The message is the same whether or not the email exists in Handstamp.

#### C. First-run setup

```mermaid
sequenceDiagram
  autonumber
  participant S as Server boot
  participant L as Logs
  participant B as Browser
  participant API as Interaction API
  participant DB as Postgres
  S->>DB: any admin? setup completed?
  alt not claimed
    S->>DB: store sha256(setup token), expires in 60 min (replaces any earlier token)
    S->>L: one banner line: "Open https://id.example.com/setup and enter HS-XXXX-XXXX-XXXX-XXXX"
  end
  B->>B: GET /setup → redirect to /console/login (a normal /auth for handstamp-console)
  B->>API: GET /interaction/{uid} → { mode: "claim" }
  Note over B: The card shows "Claim this instance" with the setup code field instead of sign-in options
  B->>API: POST /interaction/{uid}/setup/verify { token }  (5 attempts / 15 min / IP, constant-time compare)
  API->>DB: bind the setup attempt to uid
  B->>API: POST /interaction/{uid}/setup/passkey/options { displayName, email? }
  B->>B: navigator.credentials.create() (residentKey required, UV required)
  B->>API: POST /interaction/{uid}/setup/passkey/verify
  API->>DB: one transaction: create user (is_admin), passkey, consume token, set setup_completed_at, audit instance.claimed
  API-->>B: interactionResult(login) → /auth/{uid} → /console/callback → /admin
```

- The setup token is the **only** secret Handstamp ever logs. It is written once, by a dedicated logger outside request logging. It expires after 60 minutes, and a restart issues a new one.
- After the instance is claimed, `/setup` shows "This instance already has an admin." and stops accepting codes.
- If upstream providers are seeded from env, the claimant may use one of them instead of a passkey. Recovery still nudges them to add a passkey.

#### D. Logout

```mermaid
sequenceDiagram
  autonumber
  participant RP as REC app
  participant B as Browser
  participant OP as OpenID provider
  participant N as SPA
  participant RPs as Other RPs (backchannel_logout_uri)
  RP->>B: 302 /session/end?id_token_hint&post_logout_redirect_uri&state&client_id
  B->>OP: GET /session/end
  OP->>OP: validate hint, exact-match post_logout_redirect_uri
  OP->>B: logoutSource → 303 /logout + __Host-hs_logout (xsrf, client name; 5 min)
  B->>N: GET /logout → "Sign out of Paramtune?" (+ "Also sign out of Handstamp", checked by default)
  B->>OP: POST /session/end/confirm (xsrf, logout=yes|no)
  OP->>RPs: POST logout_token (sub, sid, events) to each client in this session
  OP->>B: 303 post_logout_redirect_uri?state  (or /session/end/success → branded page)
```

**Sign out everywhere** (account page) and **revoke session** (admin) work the same way. They destroy every `Session` payload for the account, revoke every grant (access and refresh tokens), and call back-channel logout for each `(client, sid)`. They also write an audit event.

---

## 2. Data model and adapter

Everything below lives in `backend/migrations/*.sql`, embedded in the binary. IDs are UUIDv4 unless noted. All timestamps are `timestamptz`.

### 2.1 Tables

| Table                 | Columns (main ones)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Keys and indexes                                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `users`               | `id uuid` (**this is `sub`**: random and opaque, never reused), `display_name`, `preferred_username citext null`, `email citext null`, `email_verified bool`, `email_identity_id uuid null` (which identity vouched for the email), `picture_url null`, `webauthn_user_handle bytea` (64 random bytes, not `sub`), `is_admin bool`, `status enum(active, disabled)`, `created_at`, `last_sign_in_at`                                                                                                                           | PK `id` · UNIQUE `preferred_username` · UNIQUE `webauthn_user_handle` · **partial UNIQUE `lower(email)` WHERE `email_verified`** |
| `identities`          | `id`, `user_id → users ON DELETE CASCADE`, `provider_id → upstream_providers ON DELETE RESTRICT`, `issuer text`, `subject text`, `email`, `email_verified`, `login_hint` (e.g. the GitHub login, for display only), `linked_at`, `last_used_at`                                                                                                                                                                                                                                                                                | PK `id` · **UNIQUE `(issuer, subject)`** · IDX `user_id`                                                                         |
| `passkeys`            | `id`, `user_id → users CASCADE`, `credential_id bytea`, `public_key bytea`, `sign_count bigint`, `transports text[]`, `aaguid uuid`, `device_type enum(single_device, multi_device)`, `backed_up bool`, `name`, `created_at`, `last_used_at`                                                                                                                                                                                                                                                                                   | PK `id` · **UNIQUE `credential_id`** · IDX `user_id`                                                                             |
| `webauthn_challenges` | `id`, `challenge bytea`, `purpose enum(authenticate, register, setup, step_up)`, `user_id null`, `interaction_uid null`, `expires_at`, `consumed_at`                                                                                                                                                                                                                                                                                                                                                                           | PK `id` · IDX `interaction_uid` · IDX `expires_at`                                                                               |
| `groups`              | `id`, `slug text` (the claim value, `^[a-z0-9][a-z0-9._:-]{0,63}$`), `name`, `description`, `created_at`                                                                                                                                                                                                                                                                                                                                                                                                                       | PK · UNIQUE `slug`                                                                                                               |
| `group_members`       | `group_id → groups CASCADE`, `user_id → users CASCADE`, `added_by`, `added_at`                                                                                                                                                                                                                                                                                                                                                                                                                                                 | PK `(group_id, user_id)` · IDX `user_id`                                                                                         |
| `oidc_clients`        | `client_id text` (operator-chosen slug, e.g. `paramtune`), `source enum(db, file, builtin)`, `name`, `client_secret_enc bytea null` (null means public client), `token_endpoint_auth_method`, `redirect_uris text[]`, `post_logout_redirect_uris text[]`, `allowed_scopes text[]`, `grant_types text[]`, `first_party bool`, `require_pkce bool default true`, `backchannel_logout_uri null`, `required_group_id null → groups SET NULL`, `enabled`, `builtin bool` (console), `secret_rotated_at`, `created_at`, `updated_at` | PK `client_id` · IDX `enabled`                                                                                                   |
| `upstream_providers`  | `id`, `slug`, `kind enum(github, google, oidc)`, `display_name`, `issuer text` (`https://github.com` for GitHub), `client_id`, `client_secret_enc`, `scopes text[]`, `allow_signup bool`, `allowed_email_domains text[]`, `github_allowed_orgs text[]`, `trust_email_verified bool`, `enabled`, `source enum(env, db)`, `sort_order`                                                                                                                                                                                           | PK · UNIQUE `slug` · UNIQUE `issuer` WHERE `enabled`                                                                             |
| `signing_keys`        | `kid text`, `alg text`, `private_jwk_enc bytea`, `public_jwk jsonb`, `state enum(staged, active, retiring, retired)`, `created_at`, `activated_at`, `retire_after`, `retired_at`                                                                                                                                                                                                                                                                                                                                               | PK `kid` · **partial UNIQUE `(alg)` WHERE `state='active'`**                                                                     |
| `cookie_keys`         | `id`, `key_enc bytea`, `state enum(active, retiring, retired)`, `created_at`                                                                                                                                                                                                                                                                                                                                                                                                                                                   | PK                                                                                                                               |
| `enrollment_tokens`   | `id`, `token_hash bytea` (sha256), `purpose enum(setup, invite, recovery)`, `user_id null` (recovery), `preset_group_ids uuid[]` (invites), `revoke_other_sessions bool`, `created_by null`, `expires_at`, `consumed_at`, `consumed_by_user_id`                                                                                                                                                                                                                                                                                | PK · UNIQUE `token_hash` · IDX `(purpose, expires_at)`                                                                           |
| `oidc_payloads`       | see §2.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |                                                                                                                                  |
| `session_meta`        | `sid text` (OP session uid), `user_id`, `created_at`, `last_seen_at`, `user_agent` (parsed summary), `ip_prefix inet` (/24 for v4, /48 for v6), `amr text[]`                                                                                                                                                                                                                                                                                                                                                                   | PK `sid` · IDX `user_id`                                                                                                         |
| `audit_log`           | `id bigserial`, `at`, `actor_type enum(user, admin, system, cli)`, `actor_user_id null`, `action text` (e.g. `auth.sign_in.succeeded`, `client.secret.rotated`), `target_type`, `target_id`, `client_id null`, `ip_prefix`, `user_agent`, `metadata jsonb` (allowlisted fields only, never secrets)                                                                                                                                                                                                                            | PK · IDX `at DESC` · IDX `(actor_user_id, at)` · IDX `(target_type, target_id, at)` · IDX `(action, at)`                         |
| `instance_settings`   | singleton: `instance_name`, `setup_completed_at`, `require_two_methods bool`, `updated_at`                                                                                                                                                                                                                                                                                                                                                                                                                                     | PK `id = 1` CHECK                                                                                                                |

Notes:

- **No password, OTP or shared-secret column exists for humans.** A CI check rejects columns named `*password*`, `*otp*` and `*totp*`.
- Email uniqueness is enforced **only among verified emails**. This protects relying parties that wrongly key users by email: two Handstamp users can never both present `alice@x.com` with `email_verified: true`. When an upstream sign-up asserts a verified email that another user already holds, the new account gets no email claim, and we write an audit event `user.email_conflict`.
- `audit_log` is append-only from the application. The only delete is the retention job (`AUDIT_RETENTION_DAYS`, default 365).

### 2.2 Protocol state

One generic table holds every protocol entity, with extracted columns for the lookups the provider and the console need (`backend/src/oidc/store.rs`):

```
oidc_payloads(
  kind text,            -- session, interaction, grant, code, access_token, refresh_token
  id text,              -- codes, tokens and session cookies: the SHA-256 of the value, never the value
  payload jsonb,
  grant_id text null,   -- revoke everything a grant issued (a grant row's grant_id is its own id)
  uid text null,        -- session and interaction uid
  user_code text null,  -- unused (no device flow)
  account_id text null, -- list sessions/grants per user, sign out everywhere
  expires_at timestamptz null,
  consumed_at timestamptz null,
  PRIMARY KEY (kind, id)
)
```

- **Clients** are not stored here: the provider reads `oidc_clients` (`backend/src/clients.rs`), decrypts the secret, and treats a disabled client as unknown. There is no dynamic registration.
- Lookups ignore expired rows, regardless of the sweeper. Codes and refresh tokens are single use through `consumed_at`; presenting a consumed one revokes the whole grant.
- Session-bound codes and tokens (no `offline_access`) are only honoured while their SSO session still exists and still holds that grant.
- The **scheduler** runs every 60 seconds under `pg_try_advisory_lock`: key lifecycle, and deleting expired protocol state and stale WebAuthn challenges.
- Kinds are lowercase. The Node server stored `Session`, `Grant`, … in the same table; those rows are never read and expire on their own, so the switch signed everyone out once and changed nothing else.

### 2.3 Signing keys and rotation with overlap

- The algorithm is **RS256** (mandatory to implement for OPs, and supported by every RP library). HS* algorithms are not implemented, so no ID token is ever signed with a client secret.
- Private JWKs are encrypted with a key derived from `HANDSTAMP_SECRET_KEY` (HKDF, `info="signing-keys"`).
- **Lifecycle:** `staged` (published in JWKS, not used for signing) → `active` (signs) → `retiring` (published, not signing) → `retired` (unpublished, private key wiped).
  1. `handstamp keys rotate`, or the admin UI, creates a **staged** key, so RPs can cache it before it signs anything.
  2. After `KEY_STAGE_HOURS` (default 24), the scheduler promotes staged to **active** and moves the old active key to **retiring**.
  3. Retiring keys stay published for `max(ID token TTL, logout token TTL) + 1h` (default 2h), then become **retired**.
  4. Automatic rotation runs every `KEY_ROTATION_DAYS` (default 90; `0` turns it off).
- **Nobody is logged out.** Sessions, refresh tokens and access tokens are opaque rows in Postgres, not JWTs signed with these keys. Only ID tokens and logout tokens are signed, and RPs check them once.
- Every signing or JWKS request checks the key set's fingerprint (one small query) and rebuilds the in-memory signer only when it changed, so changes made by the scheduler, the CLI or another replica apply immediately. Signing goes through aws-lc-rs.
- Session cookies carry 256 random bits and are stored hashed, so they need no signing key; the `cookie_keys` table is no longer used.

---

## 3. Account linking and recovery

### 3.1 Identity rules

1. **A sign-in identity is `(issuer, subject)`**, and nothing else. GitHub is OAuth2, not OIDC, so its identity is `("https://github.com", <numeric user id>)`, never the login, which users can rename.
2. **Email is a claim, not a key.** We never look users up by email when signing in or linking.
3. **Linking a second identity needs an authenticated console session**, with step-up done in the last 5 minutes (§1.3). The `link` purpose and the user's `sub` and `sid` go in the encrypted upstream state cookie. The callback checks that the console session still matches.
4. If the `(issuer, subject)` already belongs to **another** user, linking is refused ("That GitHub account is already connected to a different Handstamp account."). Accounts are never merged, and an admin has to resolve it.
5. Invites (`enrollment_tokens.purpose = invite`) let a new person register their first passkey or link their first upstream identity, even when sign-up is closed.
6. Generic OIDC providers have `trust_email_verified = false` by default. In that case `email_verified` from the upstream is stored but never passed on to RPs.

### 3.2 Recovery model (proposal)

Three layers, from the most common case to the last resort:

| Layer                      | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Trade-off                                                                                                                                                                                                   |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Multiple methods**    | The account page asks people to add a second method (another passkey, or an upstream identity) and shows a persistent banner until they do. Synced passkeys (`backed_up = true`) count as backed up and tone the banner down. Operators can make it **required** (`require_two_methods`): then, after the first sign-in, the user has to add a second method before going on to the RP. You can never remove your last method.                                                                                                           | A hard requirement adds friction at first sign-in, and some users only own one device. That's why it's a nudge by default (R3).                                                                             |
| **2. Admin recovery link** | An admin (with step-up) creates a single-use link for a user: 32 random bytes, stored as a sha256 hash, valid for 30 minutes by default. Opening it **does not sign anyone in by itself**. It lands on a card that requires registering a new passkey (or linking an upstream identity) first, and only then creates a session. The admin chooses whether to revoke the user's other sessions and passkeys, which is the default for "I lost my device". The admin hands the link over out of band. Handstamp sends no email in v1 (R4). | It relies on the admin checking who they're talking to. The audit log records who created the link, who used it, when, and the IP prefix. The user sees a "Recovery link used" event on their account page. |
| **3. Break-glass CLI**     | `docker exec handstamp handstamp recovery issue --user <sub or email>` prints a recovery link. This covers the lone admin who lost every method.                                                                                                                                                                                                                                                                                                                                                                                         | Shell access to the host is already the root of trust (it holds `HANDSTAMP_SECRET_KEY` and the database). It is audited as `actor_type=cli`.                                                                |

Guardrails: the last admin can't be demoted, disabled or deleted, and nobody can remove their own last sign-in method.

### 3.3 Threats

| Threat                                                                                                                              | Mitigations                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Account takeover via email.** The attacker controls an upstream account (or a sloppy generic IdP) that claims the victim's email. | Never link by email (§3.1). Verified-email uniqueness (§2.1). `trust_email_verified` off for generic issuers. Sign-up closed by default. The unknown-identity error is identical whether or not the email exists. The integration guide tells RPs to key on `(iss, sub)` and turn off email-based linking (§6).                                                                                                                                                                                                      |
| **Lost passkey.**                                                                                                                   | Layer 1 (second method), Layer 2 (admin link), Layer 3 (CLI). Sessions on other devices keep working until they're revoked. A recovery link can revoke the lost device's passkey and sessions in the same step.                                                                                                                                                                                                                                                                                                      |
| **Compromised upstream account.** An attacker signs in to Handstamp as the victim through their GitHub.                             | The attacker can only reach RPs, not change the account: adding or removing methods needs step-up, which goes to a **passkey when the user has one**. The account page lists sessions with sign-in method and time. The user or an admin can unlink the identity or disable it per user. Admins can disable a provider instance-wide. The `amr` claim tells RPs how the user signed in: present for passkeys, absent for federated sign-ins (R11). Letting RPs demand a passkey through `acr_values` comes after v1. |
| **Stolen session cookie.**                                                                                                          | `__Host-`, `HttpOnly`, `Secure`, `SameSite=Lax`. Idle timeout 24h and absolute lifetime 14 days (env). Step-up for sensitive actions. Session list with revoke. Sign out everywhere also sends back-channel logout to RPs. Admins can revoke any session.                                                                                                                                                                                                                                                            |
| **Stolen refresh token.**                                                                                                           | Rotation on every use. Reusing a consumed refresh token revokes the whole grant. Refresh tokens die with the user being disabled, the client being disabled, or sign-out-everywhere.                                                                                                                                                                                                                                                                                                                                 |
| **Code interception / injection.**                                                                                                  | PKCE S256 required. Codes live 60s and are single use. `iss` comes back in the authorization response (RFC 9207). Redirect URIs must match exactly.                                                                                                                                                                                                                                                                                                                                                                  |
| **Malicious admin, or a stolen admin session.**                                                                                     | Step-up on every admin mutation. Everything is audited. Client secrets can't be read back after creation. The admin can't read users' private keys or tokens.                                                                                                                                                                                                                                                                                                                                                        |
| **Setup token race** (someone else claims a fresh instance first).                                                                  | The token is only in the logs. It's rate-limited, expires after 60 minutes, and claiming is a single atomic transaction. The docs say to claim the instance before exposing it publicly.                                                                                                                                                                                                                                                                                                                             |

---

## 4. Security checklist

Every item points to the file that will own it, and has a test. Paths are relative to the repo root.

| #   | Control                                                                                                                                                                                                                                                                          | Code location                                                                                  | Test                                                                                                                        |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| S1  | PKCE S256 required (per-client `require_pkce`, default true; `plain` disallowed)                                                                                                                                                                                                 | `backend/src/oidc/authorize.rs` (`validate`), `oidc/token.rs` (`check_pkce`)                   | `tests/oidc.flow.test.ts` (no PKCE refused, opt-out client) + conformance                                                   |
| S2  | Exact-match `redirect_uris` and `post_logout_redirect_uris`. No wildcards. `https` only, except loopback (`http://localhost`, `*.localhost`, `127.0.0.1`, `[::1]`)                                                                                                               | `backend/src/clients.rs` (`redirect_uri_problem`), `oidc/authorize.rs`, `oidc/logout.rs`       | `clients::tests`, `tests/oidc.flow.test.ts` (exact match, unregistered post-logout URI)                                     |
| S3  | Code TTL 60s, single use. Access token 10m. ID token 1h. Refresh token 14d, rotating, with reuse detection                                                                                                                                                                       | `backend/src/oidc/authorize.rs` (`CODE_TTL`), `oidc/token.rs`, `config.rs`                     | `tests/oidc.flow.test.ts` (code used twice, refresh replay revokes the grant)                                               |
| S4  | `__Host-` session cookie (`__Secure-` for the path-scoped interaction cookies), `Secure`, `HttpOnly`; 256 random bits, stored hashed. Interaction cookies `SameSite=Lax`; the SSO session cookie `SameSite=None` on https issuers so POST to `/auth` works (R16)                 | `backend/src/oidc/mod.rs` (`cookie_names`, `session_cookie_options`)                           | `tests/oidc.flow.test.ts` (cookie attributes) + conformance `oidcc-ensure-post-request-succeeds`                            |
| S5  | CSRF on interaction and console APIs: `Origin` must equal the issuer origin, plus an HMAC token tied to the interaction uid or console session                                                                                                                                   | `backend/src/crypto.rs` (`csrf_token`), `interaction.rs` (`guard`), `console.rs` (`signed_in`) | `crypto::tests`, `tests/oidc.flow.test.ts` and `tests/passkeys.flow.test.ts` (cross-origin, missing token)                  |
| S6  | Upstream `state`, `nonce` and PKCE in an encrypted 10-minute cookie, bound to the interaction uid and cleared on use                                                                                                                                                             | `backend/src/upstream/routes.rs` (`hs_upstream`), `app.rs` (`write_sealed`)                    | `tests/upstream.flow.test.ts`                                                                                               |
| S7  | Rate limits per route and client IP: `/token`, `/auth`, `/interaction/:uid/*`, setup verify and link redeem (5 per 15 min), upstream callback. Keys use a closed route vocabulary                                                                                                | `backend/src/http.rs` (`RateLimiter`)                                                          | `http::tests::rate_limits_per_ip`, `tests/oidc.flow.test.ts` (rate limits)                                                  |
| S8  | No open redirects: every internal `returnTo` goes through `safe_return_path()` (relative path only, no `//`, no backslash). Only the authorization and logout endpoints redirect to RPs, to registered URIs                                                                      | `backend/src/console.rs` (`safe_return_path`)                                                  | `console::tests::return_paths_stay_on_this_origin`                                                                          |
| S9  | Secrets never logged: requests are logged by path with the query replaced, never headers or bodies. The setup banner is the only exception                                                                                                                                       | `backend/src/app.rs` (`log_url`, `access_log`)                                                 | `app::tests::logs_urls_without_query_strings`                                                                               |
| S10 | Secrets at rest: client secrets, upstream secrets and signing keys encrypted with AES-256-GCM under HKDF subkeys of `HANDSTAMP_SECRET_KEY`, byte-compatible with what Node wrote. Startup refuses a missing or short key                                                         | `backend/src/crypto.rs`, `config.rs`                                                           | `crypto::tests` (opens a value Node sealed), `config::tests`                                                                |
| S11 | Tokens stored hashed: enrollment and setup tokens (sha256), codes, access and refresh tokens and session IDs (sha256), compared in constant time where presented                                                                                                                 | `backend/src/enrollment.rs`, `crypto.rs`, `oidc/store.rs` (`token_id`)                         | `crypto::tests::setup_codes_are_forgiving_but_exact`, `tests/upstream.flow.test.ts` (link used once)                        |
| S12 | WebAuthn: RP ID = issuer host. Expected origin = issuer origin. `userVerification: required`, discoverable credentials required. Challenges single use, 5 min, bound to the interaction or console session. A counter that goes backwards is refused (synced passkeys stay at 0) | `backend/src/webauthn.rs`, `passkeys.rs`                                                       | `webauthn::tests`, `tests/passkeys.flow.test.ts` (phishing origin, replayed challenge, counter regression, unknown passkey) |
| S13 | Identity keyed by `(issuer, subject)`. No email lookup in sign-in or linking code paths                                                                                                                                                                                          | `backend/src/identities.rs`, `upstream/routes.rs`                                              | `tests/upstream.flow.test.ts` (account takeover via email)                                                                  |
| S14 | Step-up (`auth_time` ≤ 5 min, and a passkey for passkey holders) before changing sign-in methods and for every admin change; sign out everywhere deliberately needs none                                                                                                         | `backend/src/console.rs` (`recently_authenticated`, `signed_in`)                               | `console::tests::step_up_window_is_five_minutes`, `tests/upstream.flow.test.ts` (compromised upstream account)              |
| S15 | Security headers on every response: strict CSP (`script-src 'self'` + theme-script hash), `frame-ancestors 'none'`, HSTS, `Referrer-Policy: no-referrer`, `X-Content-Type-Options`                                                                                               | `backend/src/app.rs` (`security_headers`), `web.rs` (`html_csp`)                               | `web::tests`, `tests/oidc.flow.test.ts` (headers)                                                                           |
| S16 | `TRUST_PROXY` (hop count or CIDR list), never "trust everyone". Absolute URLs come from the configured issuer, never the Host header                                                                                                                                             | `backend/src/config.rs`, `http.rs` (`client_ip`)                                               | `config::tests::trust_proxy_forms`, `http::tests::ignores_forwarded_for_unless_trusted`                                     |
| S17 | Dev login refused in production, unless `HANDSTAMP_CONFORMANCE_MODE=1` and the issuer host is `localhost`, `*.test` or `*.localhost`                                                                                                                                             | `backend/src/config.rs`                                                                        | `config::tests::dev_login_only_on_local_issuers`                                                                            |
| S18 | Disabled user or client: the account stops existing for the provider, sessions and grants are revoked, back-channel logout sent                                                                                                                                                  | `backend/src/accounts.rs` (`find`), `admin.rs`, `sessions.rs`                                  | `tests/admin.flow.test.ts` (disabling a user ends their sessions)                                                           |
| S19 | Audit log covers sign-ins (success, failure, refusal and reason), method changes, every admin change (attributed to the admin), key rotation and recovery, with no secrets in `metadata`. CSV export neutralises formulas                                                        | `backend/src/audit.rs`, `admin.rs`                                                             | `tests/admin.flow.test.ts` (records every admin change, CSV)                                                                |
| S20 | Error pages reflect no user input: a fixed message per error code                                                                                                                                                                                                                | `backend/src/oidc/mod.rs` (`render_error`)                                                     | `tests/oidc.flow.test.ts` (error view), conformance error-page tests                                                        |
| S21 | Dependency hygiene: `Cargo.lock` and `pnpm-lock.yaml` committed, builds `--locked`; clippy `-D warnings` and `pnpm audit` in CI                                                                                                                                                  | `backend/Cargo.toml`, `.github/workflows/ci.yml`                                               | CI                                                                                                                          |

---

## 5. Repository layout and milestones

### 5.1 Layout

```
handstamp/
├── backend/             the server and CLI: one Rust binary (axum, tokio-postgres, aws-lc-rs)
│   ├── src/oidc/        the OpenID provider: authorize, token, logout, discovery, store
│   ├── src/             interaction, console and admin APIs, passkeys, upstream sign-in, keys
│   └── migrations/      SQL, embedded at build time
├── apps/web/            @handstamp/web   Vite + React SPA (interaction, setup, account, admin)
├── tests/               @handstamp/tests black-box flow tests and Chromium e2e against the binary
├── scripts/             dev (Vite + the Rust server as one origin), the CLI wrapper
├── conformance/         OIDF suite compose file, test-plan configs, runner script
├── examples/            a tiny relying party and a demo upstream IdP, for local tries
├── docs/                PLAN.md, RUST-PORT.md, INTEGRATING.md, DEPLOYING.md, SECURITY.md
├── Dockerfile · compose.yaml · .env.example · CLAUDE.md
```

The tooling follows Paramtune: Rust 1.92 (edition 2024, `cargo fmt`, clippy `-D warnings`), and a pnpm workspace for the UI and tests (Node ≥ 24, ESM, TypeScript 6, Prettier, Vitest). Postgres 17. License: Apache-2.0, like StillUp (R9).

### 5.2 Milestones

Each milestone ends with `pnpm check` green, a short demo script in `docs/`, and its tests. These notes record how M1–M5 were built, on the Node server of the time (Fastify, `oidc-provider`, Drizzle); the Rust server (R20) reproduces that behaviour.

**M1: Protocol skeleton (a dev-only test account passes a conformance smoke test)** · ✅ done

- Monorepo scaffold, `env.ts` with zod validation, `.env.example`, pino with redaction.
- `packages/db`: `oidc_payloads`, `oidc_clients`, `signing_keys`, `cookie_keys`, `users`, `audit_log` (minimal), migrations.
- `oidc-provider` mounted in Fastify, with discovery, JWKS, `/auth`, `/token`, `/me`, refresh, revocation, RP-initiated logout and back-channel logout.
- Vite SPA served by Fastify (§1.2). A bare interaction page and a **"Continue as test user"** button behind `HANDSTAMP_DEV_LOGIN=1` (S17). This is not a password.
- `HANDSTAMP_CLIENTS_FILE` (R6): declarative, read-only clients, used by the conformance setup from day one. Key rotation CLI (`keys rotate`, `keys list`).
- Spikes to settle in the first days, before any UI work: D3 (the suite and PKCE), D4 (interaction cookie path), client-cache invalidation, `Client.backchannelLogout` from outside a request, refresh-token reuse revoking the grant.
- **Exit:** the OIDF suite runs locally through `conformance/run.sh` with the `oidcc-config-certification-test-plan` all passing, plus a smoke subset of `oidcc-basic-certification-test-plan` (`oidcc-server`, `oidcc-refresh-token`, `oidcc-userinfo-get`, `oidcc-ensure-redirect-uri-in-authorization-request`, `oidcc-prompt-login`, `oidcc-max-age-1`, `oidcc-id-token-hint`) passing. The sign-in card can be plain at this stage.

**M2: Passkeys and first-run setup** · ✅ done

- `passkeys` and `webauthn_challenges` tables. Discoverable sign-in, plus conditional UI (autofill) where the browser supports it.
- Setup token flow (§1.4 C) and the console client with its cookie (§1.3).
- Account page v1: profile, passkeys (add, rename, remove; never the last one), sessions, sign out everywhere.
- `/` becomes a redirect (R17): unclaimed instance → `/setup`; signed out → console sign-in; signed in → `/account` (admins also see an **Admin** link).
- Step-up (S14). The sign-in, claim and consent cards fully designed per DESIGN (both themes, 375px to 1536px, §16 checklist).
- Tests: a software authenticator (`tests/authenticator.ts`: real P-256 keys, CBOR attestation) drives the integration tests, and `pnpm e2e` runs the real UI in Chromium with its virtual WebAuthn authenticator.
- **Exit:** a fresh database plus the setup code gives an admin with a passkey, and the example app (`examples/test-app`) signs in with that passkey. ✅
- **Deviations:** passkey autofill (conditional UI) is not used: sign-in has no username field, so the passkey button does the same job. The session list shows when, how and which apps; device names (user agent) are not recorded yet.

**M3: Upstream providers and linking** · ✅ done

- `upstream_providers` and `identities`. GitHub, Google and generic OIDC through `openid-client`. Seeding from env.
- Sign-up policy (closed, invite, domain or org allowlist), invites, linking from the account page, verified-email uniqueness, conflict handling.
- Recovery layers 1 to 3 (§3.2).
- Tests: a mock upstream OIDC issuer (an `oidc-provider` instance in tests) for login, sign-up, link, conflict and refusal. GitHub is mocked at the HTTP level.
- **Exit:** every threat row in §3.3 has at least one automated test named after it. ✅ Account takeover via email, compromised upstream account and lost passkey are `describe('threat: …')` blocks in `tests/upstream.flow.test.ts`; stolen session and refresh token live in `passkeys.flow.test.ts` and `oidc.flow.test.ts`; the setup token race is the "cannot be claimed twice" test. The malicious-admin row lands with the admin UI in M4.
- **Built beyond the list:** step-up requires a passkey when the user has one (a fresh upstream sign-in doesn't count), the account page's "Recent security activity", GitHub Enterprise support, `pnpm example:idp` (a demo upstream issuer for local testing), and userinfo fallback for issuers that keep email out of the ID token.
- **Moved:** groups and their claim move to M4, with the admin UI that manages them.

**M4: Admin UI and audit log** · ✅ done

- Admin pages: overview (stat tiles: users, active sessions, clients, providers), users (detail, groups, sessions, identities, disable, recovery link), groups, clients (create, rotate secret, show once, redirect URI editor, first-party flag, required group), upstream providers, signing keys (rotate, state timeline), audit log (filter by actor, action, target and time; CSV export).
- Every admin mutation is audited and needs step-up.
- **Exit:** the §16 checklist passes on every screen in both themes, with screenshots in the PR, and the audit log covers every row of S19. ✅ Screenshots of every admin screen in Dark and Paper (and 375px) come from `SCREENSHOT_DIR=… pnpm e2e`; S19 is the "records every admin change" test in `tests/admin.flow.test.ts`.
- **Also in M4:** groups and the `groups` claim (from M3); per-app required group (R7) enforced by an extra `access` prompt that runs on every authorization, SSO included, with a "No access to …" card; guardrails (no self-demotion, never zero admins); app secrets generated and shown once (and cleared from browser history); env/file/built-in entries read-only; CSV export neutralises spreadsheet formulas.

**M5: Docker, compose, Dokploy, full conformance and docs** · ✅ done

- One `Dockerfile` (multi-stage, Alpine, non-root, `tini`, one Node process running the bundled server, the built SPA copied in, `HEALTHCHECK` on `/readyz`). `compose.yaml` with the app and `postgres:17-alpine`. Migrations run at start behind an advisory lock.
- `docs/DEPLOYING.md` uses `id.rec.farm` as the worked example of a real deploy (R13).
- `docs/DEPLOYING.md`: Dokploy (Traefik in front, `TRUST_PROXY=1`, one domain, Postgres service, backups for the database **and** `HANDSTAMP_SECRET_KEY`).
- `docs/INTEGRATING.md` (§6 below, expanded), `docs/SECURITY.md` (threat model, how to report).
- **Full** Basic OP and Config OP plans pass. CI job `conformance.yml` runs nightly and on tags, and uploads the suite's exported logs as an artifact. A smoke subset runs on every PR, and a release is blocked unless the latest full run passed (R10).
- **Exit:** `docker compose up`, then claim the instance, then Paramtune signs in through the §6 example. ✅ for Handstamp: the image builds, starts from an empty database (migrations, setup banner, `/readyz`, discovery, the SPA under the strict CSP, running as `node`), and the full conformance run passes against it. The claim and sign-in flows are covered by `pnpm e2e` and the example app. Wiring Paramtune itself is Paramtune work; `docs/INTEGRATING.md` has the config, checked against Better Auth 1.7's `genericOAuth` types (it needs `authentication: 'basic'`, since Better Auth defaults to `client_secret_post`).
- **Also in M5:** a `handstamp` command in the image (`docker compose exec handstamp handstamp invite`); `handstamp help` no longer touches the database.

---

## 6. How a REC app integrates

A REC app only needs a standard OIDC client configuration. Nothing in it is specific to Handstamp, so the same values work with Authentik, Keycloak or Zitadel.

### 6.1 App env vars

| Variable             | Example                       | Meaning                                                                                             |
| -------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------- |
| `OIDC_ISSUER`        | `https://id.example.com`      | The issuer URL. Discovery is at `$OIDC_ISSUER/.well-known/openid-configuration`. No trailing slash. |
| `OIDC_CLIENT_ID`     | `paramtune`                   | The client ID created in Handstamp → Admin → Clients.                                               |
| `OIDC_CLIENT_SECRET` | `hs_sec_…`                    | Shown once at creation. Rotate it in the admin UI.                                                  |
| `OIDC_SCOPES`        | `openid profile email groups` | Add `offline_access` only if the app needs refresh tokens.                                          |
| `OIDC_ROLES_CLAIM`   | `groups`                      | The claim that holds group slugs (an array of strings).                                             |
| `OIDC_ADMIN_GROUP`   | `paramtune-admins`            | Members of this group become admins in the app.                                                     |
| `OIDC_DISPLAY_NAME`  | `Handstamp`                   | Button label: "Sign in with Handstamp".                                                             |

Rules for app authors:

- Key users on **`(iss, sub)`**. Don't link or merge accounts by email.
- Use PKCE (S256), and verify `iss` and `nonce`.
- Read roles from `OIDC_ROLES_CLAIM` at every sign-in, so group changes take effect on the next sign-in.
- Register a back-channel logout URI so sign-outs at Handstamp reach the app, and only redirect to own-origin paths after sign-in. [INTEGRATING.md](INTEGRATING.md#signing-out) has the `logout_token` contents and the return-path checks.

### 6.2 Worked example: Paramtune

Paramtune signs in with Handstamp since its Rust backend (Paramtune #267, roles from groups in #279, per-platform editors in #281). It uses the `openidconnect` crate with PKCE, keys users on `(iss, sub)`, and reads roles from the groups claim at every sign-in. Its own [DEPLOYMENT.md](https://github.com/rec-farm/paramtune/blob/master/docs/DEPLOYMENT.md) is the reference; this is the Handstamp side.

**In Handstamp** (Admin → Apps → Add app):

| Field                      | Value                                                         |
| -------------------------- | ------------------------------------------------------------- |
| Client ID                  | `paramtune`                                                   |
| Redirect URI               | `https://paramtune.example.com/api/auth/oauth2/callback/oidc` |
| Post-logout redirect URI   | `https://paramtune.example.com/`                              |
| Back-channel logout URI    | `https://paramtune.example.com/api/auth/backchannel-logout`   |
| Allowed scopes             | `openid profile email groups`                                 |
| First-party (skip consent) | on                                                            |
| Required group (optional)  | `paramtune-users`                                             |

Then create the groups Paramtune maps to roles (`paramtune-admins`, and optionally an editor group) and add people to them.

**In Paramtune** (`.env`):

```
OIDC_ISSUER=https://id.example.com
OIDC_CLIENT_ID=paramtune
OIDC_CLIENT_SECRET=hs_sec_…
OIDC_SCOPES="openid profile email groups"
OIDC_ROLES_CLAIM=groups
OIDC_ADMIN_GROUP=paramtune-admins
OIDC_EDITOR_GROUP=paramtune-editors      # optional: everyone else is view-only
OIDC_PLATFORM_EDITORS=ios:team-ios;web:team-web   # optional
OIDC_DISPLAY_NAME=Handstamp
```

Handstamp must be able to reach the back-channel URI from the server. Group changes take effect at the next sign-in, and signing out in either app signs out of the other.

### 6.3 Handstamp instance env vars (preview of `.env.example`)

| Variable                                                                                             | Default            | Notes                                                                                                                                   |
| ---------------------------------------------------------------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| `HANDSTAMP_ISSUER`                                                                                   | (required)         | Public origin, e.g. `https://id.example.com`. Also the WebAuthn origin. Changing it breaks existing passkeys, so pick it once.          |
| `HANDSTAMP_WEBAUTHN_RP_ID`                                                                           | issuer host        | Leave unset. A parent domain would let any site on a sibling subdomain request sign-ins with users' passkeys (R8). Documented as risky. |
| `HANDSTAMP_SECRET_KEY`                                                                               | (required)         | 32+ bytes, base64. `openssl rand -base64 32`. Back it up, because losing it loses client secrets and keys.                              |
| `DATABASE_URL`                                                                                       | (required)         | Postgres 17.                                                                                                                            |
| `HOST`, `PORT`                                                                                       | `0.0.0.0`, `3000`  | The only port.                                                                                                                          |
| `HANDSTAMP_CLIENTS_FILE`                                                                             | unset              | JSON file of declared clients (R6).                                                                                                     |
| `TRUST_PROXY`                                                                                        | unset              | Hop count or CIDR list. Required behind Dokploy or Traefik.                                                                             |
| `HANDSTAMP_INSTANCE_NAME`                                                                            | `Handstamp`        | Shown on the sign-in card.                                                                                                              |
| `SESSION_IDLE_HOURS` / `SESSION_MAX_DAYS`                                                            | `24` / `14`        |                                                                                                                                         |
| `REFRESH_TOKEN_DAYS` / `ACCESS_TOKEN_MINUTES` / `ID_TOKEN_MINUTES`                                   | `14` / `10` / `60` |                                                                                                                                         |
| `KEY_ROTATION_DAYS` / `KEY_STAGE_HOURS`                                                              | `90` / `24`        |                                                                                                                                         |
| `AUDIT_RETENTION_DAYS`                                                                               | `365`              |                                                                                                                                         |
| `HANDSTAMP_UPSTREAM_GITHUB_CLIENT_ID` / `_SECRET` / `_ALLOW_SIGNUP` / `_ALLOWED_ORGS`                | unset              | Seeds a read-only GitHub provider.                                                                                                      |
| `HANDSTAMP_UPSTREAM_GOOGLE_*`                                                                        | unset              | Same, with `_ALLOWED_DOMAINS`.                                                                                                          |
| `HANDSTAMP_UPSTREAM_OIDC_<SLUG>_ISSUER` / `_CLIENT_ID` / `_CLIENT_SECRET` / `_NAME` / `_TRUST_EMAIL` | unset              | Seeds any number of generic OIDC providers.                                                                                             |
| `HANDSTAMP_DEV_LOGIN` / `HANDSTAMP_CONFORMANCE_MODE`                                                 | `0`                | Dev only (S17).                                                                                                                         |
| `LOG_LEVEL`                                                                                          | `info`             |                                                                                                                                         |

---

## 7. Design system notes

- Brand source: `/Users/rec/Projects/reciam-brand/DESIGN.md`. The §14 token block is copied into `apps/web/app/globals.css` from the `v1.3.0` tag, with a header comment `REC brand v1.3.0`. No submodule or symlink (R1).
- A local `data-product="handstamp"` block adds the **Lilac** accent: `lilac-400` / `ink-950` / `lilac-950` / `lilac-400` in dark, and `lilac-300` / `deep-900` / `lilac-100` / `lilac-600` in Paper. Contrast is checked against §13 before use, and the block goes upstream to `rec-brand` §3.4 and §14 as a PR.
- **Lilac also means "pending / info"** in §3.2. In Handstamp, info callouts sit right next to the accent. We keep Lilac (§2.10 step 9 recommends it), and info callouts always carry their `info` icon and wording, so they never read as navigation (R12).
- Sign-in card: one centered card, `surface-1`, 1px border, `radius-sm`. Eyebrow with the instance name. Title "Sign in to Paramtune" with the purple period. Primary button **"Continue with a passkey"** (the only offset shadow on the page). Below it, secondary buttons per upstream ("Continue with GitHub"). Footer in `mono-sm`: the client ID and issuer host, so people can see exactly where they're signing in.
- Wordmark `HANDSTAMP`: Archivo wdth 125, 700, tracking 0.16em, live text for now, with `TODO(brand): replace with outlined asset from rec-brand/build.py (§2.10)`. Mark placeholder: an empty 48×48 slot with the same TODO. Sidebar footer: `HANDSTAMP · by REC` and `Handstamp v0.1.0` in mono.
- Machine data (`sub`, client IDs, issuer URLs, `kid`, scopes, timestamps) in Geist Mono. Human text in Figtree.

---

## 8. Resolved decisions

These answer the open questions from the first draft (rev 1).

| #   | Topic                              | Decision                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Reason                                                                                                                                                                                                                                                                         |
| --- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| R1  | Brand version                      | Copy tokens from the `rec-brand` **v1.3.0** tag and record `brand v1.3.0`.                                                                                                                                                                                                                                                                                                                                                                                          | The §14 tokens are identical to v1.2.0. The label should name the tag we actually copied from.                                                                                                                                                                                 |
| R2  | Sign-up policy                     | **Invite-only by default.** Self sign-up is opt-in per upstream provider, limited by an email-domain or GitHub-org allowlist.                                                                                                                                                                                                                                                                                                                                       | Every R.E.C. app trusts this server, so open sign-up would mean open access to all of them.                                                                                                                                                                                    |
| R3  | Second sign-in method              | **Nudge, don't require.** The `require_two_methods` instance setting stays for operators who want it.                                                                                                                                                                                                                                                                                                                                                               | Synced passkeys cover most lost-device cases and admin recovery links cover the rest. Requiring two methods adds friction at the first sign-in.                                                                                                                                |
| R4  | Email                              | **No email in v1.** Admins hand over invites and recovery links. The account page shows security events (method added or removed, recovery link used). Email notifications are a v1.1 candidate.                                                                                                                                                                                                                                                                    | SMTP brings credentials, deliverability, templates and bounces for little gain on a self-hosted team server.                                                                                                                                                                   |
| R5  | Replicas                           | **Any number, sharing Postgres (2026-10-10).** One replica in v1; rate limits now live in Postgres (`rate_limits`, migration 006), so N replicas share one budget per IP and route.                                                                                                                                                                                                                                                                                 | Traffic is tiny, and Postgres is the single point of failure anyway, so counting there costs one upsert per limited request. `tests/replicas.flow.test.ts` runs two processes on one database.                                                                                 |
| R6  | Where config lives                 | **Database plus admin UI, and a declarative clients file.** `HANDSTAMP_CLIENTS_FILE` lists clients (ID, name, redirect URIs, scopes, first-party, required group, and the _name_ of the env var holding the secret, e.g. `"secretEnv": "PARAMTUNE_OIDC_SECRET"`). Declared clients are synced at boot and read-only in the UI.                                                                                                                                      | M1 needs file-declared clients for the conformance suite anyway. It also gives reproducible Dokploy deploys for Paramtune and StillUp.                                                                                                                                         |
| R7  | Per-app access                     | **`required_group_id` ships in v1.** The check runs in the interaction before consent, with the message "Your account doesn't have access to Paramtune. Ask your admin to add you to `paramtune-users`."                                                                                                                                                                                                                                                            | About 20 lines of code, and it gives every R.E.C. app "who may use this app" without app code.                                                                                                                                                                                 |
| R8  | WebAuthn RP ID                     | **The issuer host** (e.g. `id.rec.farm`), never a parent domain. The env override exists but is documented as risky.                                                                                                                                                                                                                                                                                                                                                | A parent domain lets any site on a sibling subdomain request sign-ins with users' passkeys, so one compromised app could phish Handstamp. Pick the hostname once and keep it.                                                                                                  |
| R9  | License                            | **Apache-2.0**, like StillUp.                                                                                                                                                                                                                                                                                                                                                                                                                                       | Consistency across the family.                                                                                                                                                                                                                                                 |
| R10 | Conformance in CI                  | A **smoke subset on every PR**. The **full** Basic OP and Config OP plans run **nightly and on release tags**, and a release is blocked unless the latest full run passed.                                                                                                                                                                                                                                                                                          | Meets "passes in CI" without a 10–15 minute wait on every PR.                                                                                                                                                                                                                  |
| R11 | `amr` / `acr`                      | **`amr` ships in v1**: `["pop","user","mfa"]` for passkey sign-ins, absent for federated ones. **`acr` and `acr_values` shipped after v1 (2026-10-10)**: `phr` for passkey sign-ins, `0` for the rest, derived from `amr` so nothing new is stored. `acr_values=phr` (or `id_token.acr` in `claims`) makes a level-0 session sign in again with a passkey only, enforced on the server; the console's step-up uses the same request instead of a private parameter. | `amr` is a standard optional claim and costs nothing. It lets RPs tell passkey sign-ins from federated ones, which matters if an upstream account is compromised.                                                                                                              |
| R12 | Lilac accent                       | **Keep Lilac.** Info callouts always carry their `info` icon and wording.                                                                                                                                                                                                                                                                                                                                                                                           | DESIGN §2.10 step 9 recommends it, and the icon keeps info callouts from reading as navigation.                                                                                                                                                                                |
| R13 | Domains                            | Docs and examples use **`id.example.com`** (it's an open-source project). The R.E.C. deploy and `docs/DEPLOYING.md`'s worked example use **`id.rec.farm`**.                                                                                                                                                                                                                                                                                                         | Generic docs for self-hosters, plus one real reference deploy.                                                                                                                                                                                                                 |
| R14 | Single origin and UI stack         | **One process serving a Vite + React SPA** (§1.2). Replaced Next 16 from the brief; the process is the Rust server since R20.                                                                                                                                                                                                                                                                                                                                       | No server rendering is needed, the UI already talks only to `/api/*`, and it removes the second process, the internal proxy and per-request CSP nonces. Paramtune and StillUp may move to Vite later too.                                                                      |
| R15 | Refresh tokens                     | Any client allowed the `refresh_token` grant (its allowed scopes include `offline_access`) gets a refresh token. Without `offline_access` + `prompt=consent` that token is **bound to the SSO session** and dies at sign-out or sign out everywhere. A refresh token that outlives the session needs `offline_access` with `prompt=consent`, per the spec.                                                                                                          | Within the spec (an OAuth server may issue refresh tokens at its discretion), and safer by default: signing out actually signs out.                                                                                                                                            |
| R16 | POST at `/auth`                    | **Supported on https issuers.** OIDC Core requires it and the Basic OP plan tests it. `oidc-provider` allows it only when the SSO session cookie is `SameSite=None` (so a cross-site form POST still carries the session), which also needs `Secure`. Over plain http (local dev) it stays off and the cookie stays `Lax`.                                                                                                                                          | The cost is that browsers send the session cookie on cross-site requests. That's acceptable: codes only go to registered redirect URIs, logout confirmation has its own xsrf token, the interaction and console APIs check `Origin` plus a CSRF token, and framing is blocked. |
| R17 | What `/` does                      | **A redirect, not a page.** Unclaimed instance → `/setup`. Not signed in → Handstamp's own sign-in (as `handstamp-console`), then back. Signed in → `/account`, with an **Admin** link for admins.                                                                                                                                                                                                                                                                  | Apps send people straight to `/auth`, so only operators and users managing their account ever land on `/`.                                                                                                                                                                     |
| R18 | Outbound calls to private networks | **Refused by default; `ALLOW_PRIVATE_NETWORKS=true` allows them.** `oidc-provider` blocks back-channel logout calls to loopback and private addresses (SSRF protection). Apps on the same Docker network as Handstamp need the setting. Same name and meaning as in StillUp.                                                                                                                                                                                        | Safe default, explicit opt-in for the common self-hosted layout.                                                                                                                                                                                                               |
| R19 | Rust backend                       | **Superseded by R20.** First answer: stay on Node and ship a bundled server on Alpine, because Rust had no certified provider library and the hard rules forbade hand-rolling the protocol.                                                                                                                                                                                                                                                                         | The owner chose to go all-in on Rust (R20), holding the port to the same conformance bar instead.                                                                                                                                                                              |
| R20 | The server is Rust                 | **One Rust binary (`backend/`) replaces the Node server**, Paramtune-style: axum, tokio-postgres, aws-lc-rs, `openidconnect` for upstream IdPs. The provider is written to oidc-provider 9's behaviour as Handstamp configured it ([RUST-PORT.md](RUST-PORT.md)). The database schema is unchanged (plus migration 005), so users, passkeys, clients, keys, groups and identities carry over; sessions and tokens do not (everyone signs in once more).             | Before the switch: the full Basic OP + Config OP conformance run passes with the same accepted gaps, the 64 flow tests and the Chromium e2e tests pass against the binary, and every S-item maps to Rust code and a test (§4). The image is 30 MB instead of 205 MB.           |

### 8.1 Settled in M1

| #     | Question                         | Finding                                                                                                                                                            | What we did                                                                                                                                                                                                            |
| ----- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| M1-1  | D4: `__Host-` cookies            | `oidc-provider` always scopes the resume cookie to `/auth/:uid` and the interaction cookie to `/interaction/:uid`. Over plain http, browsers reject both prefixes. | Session cookie `__Host-hs_session`. Interaction and resume cookies `__Secure-hs_interaction` and `__Secure-hs_resume`. Unprefixed names only when the issuer is `http://localhost` (dev).                              |
| M1-2  | Where the interaction API lives  | The interaction cookie is only sent under `/interaction/:uid`.                                                                                                     | The interaction API is `/interaction/:uid/*`, not `/api/interaction/*`. The upstream callback (fixed URL at GitHub) will hand back to `/interaction/:uid/upstream/complete` in M3.                                     |
| M1-3  | Client cache                     | Clients loaded through the adapter are cached by a hash of their metadata.                                                                                         | Admin edits take effect on the next request. No invalidation code needed.                                                                                                                                              |
| M1-4  | Refresh-token reuse              | Reusing a consumed refresh token destroys it and revokes the grant.                                                                                                | Covered by `tests/oidc.flow.test.ts`.                                                                                                                                                                                  |
| M1-5  | `offline_access`                 | Per OIDC Core §11, `oidc-provider` drops `offline_access` unless the request also has `prompt=consent`.                                                            | **R15** below.                                                                                                                                                                                                         |
| M1-6  | Logout and error pages           | `logoutSource`, `postLogoutSuccessSource` and `renderError` must write the response themselves.                                                                    | They return the SPA's `index.html` with escaped `data-hs-*` attributes (view, xsrf, client, error code). No inline script, no extra cookie, and the real status code is kept.                                          |
| M1-7  | Conformance browser automation   | The suite clicks through pages with its own in-container browser, which may not run the React bundle.                                                              | In `HANDSTAMP_CONFORMANCE_MODE` only, sign-in, consent, logout and error are plain no-JS HTML forms. The CSRF token is still required; only the `Origin` requirement is relaxed. The protocol under test is unchanged. |
| M1-8  | D3: does the suite send PKCE?    | **No.** The Basic OP plan sends plain code requests without `code_challenge`, and Handstamp correctly refuses them.                                                | The two conformance clients set `requirePkce: false` (`conformance/clients.json`). Every other client still requires PKCE by default.                                                                                  |
| M1-9  | D6: scope claims in the ID token | With every scope claim in the ID token, the suite warns (`EnsureIdTokenDoesNotContainEmailForScopeEmail`, OIDC Core 5.4).                                          | D6 revised: only `groups` rides in the ID token.                                                                                                                                                                       |
| M1-10 | What browser the suite drives    | HtmlUnit, not real Chrome as first noted: it doesn't run JavaScript modules.                                                                                       | _Corrected 2026-10-10:_ the WebRunner is HtmlUnit, which doesn't run the SPA, so the conformance-mode forms (M1-7) are needed (§8.2 P1).                                                                               |

Back-channel logout outside a request, the last open M1 item, shipped with sign out everywhere in M2 (`sessions.rs`, `passkeys.flow.test.ts`).

### 8.2 After v1

| #   | Item                                    | Outcome                                                                                                                                                                                                                                                                                                          |
| --- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1  | M1-10: drive the real UI in conformance | **Not possible with the pinned suite (checked 2026-10-10).** Its WebRunner is HtmlUnit, not Chrome: the page source it captures is XHTML-serialised and `#root` stays empty, because it doesn't run the SPA's module bundle. The conformance-mode HTML forms stay. Revisit if the suite moves to a real browser. |
| P2  | `acr` / `acr_values` (R11)              | Shipped 2026-10-10.                                                                                                                                                                                                                                                                                              |
| P3  | The outlined mark and wordmark (D9)     | Shipped 2026-10-10, from rec-brand v1.7.0.                                                                                                                                                                                                                                                                       |
| P4  | More than one replica (D10, R5)         | Shipped 2026-10-10: rate limits in Postgres, setup code kept across replicas booting together.                                                                                                                                                                                                                   |

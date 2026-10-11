# Security

## Reporting a vulnerability

Please report it privately, not in a public issue, through GitHub private vulnerability reporting:
[report a vulnerability](https://github.com/rec-farm/handstamp/security/advisories/new).

Include what you found, how to reproduce it, and the version or commit. We'll acknowledge it,
keep you updated, and credit you in the advisory unless you'd rather not be.

Security fixes land on the default branch; run the latest version.

## What Handstamp protects, and how

Handstamp is the front door for every R.E.C. app, so a flaw in it is a flaw in all of them. The
design choices below are the ones that matter most. The full list, with where each is enforced
and tested, is the security checklist in [`PLAN.md` §4](PLAN.md#4-security-checklist).

**A protocol held to the conformance suite.** The OpenID provider is Rust
([`backend/`](../backend)), written to the behaviour of
[`oidc-provider`](https://github.com/panva/node-oidc-provider) 9, which Handstamp ran on before
([`RUST-PORT.md`](RUST-PORT.md)). It is not certified code from a third party, so it is held to
the same bar instead: every release passes the OpenID Foundation's Basic OP and Config OP
conformance tests ([`conformance/`](../conformance)) with the same short list of accepted gaps,
and every flow has a black-box test ([`tests/`](../tests)). Upstream sign-in uses the
[`openidconnect`](https://crates.io/crates/openidconnect) crate. Cryptography is
[aws-lc-rs](https://github.com/aws/aws-lc-rs) (signing, signature checks) and RustCrypto
(AES-GCM, HKDF); nothing is home-made below the protocol layer. Dependencies are locked.

**No passwords.** People sign in with a passkey (user verification required, bound to the
issuer's host, so a look-alike domain can't use it) or with an account they already have at
GitHub, Google or another OIDC issuer.

**Identity is `(issuer, subject)`, never email.** A GitHub or Google account is linked to a
Handstamp user by that provider's account id. Sign-in never looks a user up by email, so
controlling an address at some provider doesn't get you into someone's account. Sign-up through
a provider is off unless an admin turns it on, and can be limited to email domains or GitHub
organisations.

**Codes and tokens.** Authorization code flow only, PKCE S256 required, exact redirect URIs,
codes valid 60 seconds and single use, the `iss` parameter on responses (RFC 9207). Refresh tokens
rotate on every use; replaying a used one revokes the grant.

**Sessions and cookies.** `__Host-` and `__Secure-` cookies, `HttpOnly`, `Secure`, encrypted or
signed with keys derived from the root key. Every state-changing request needs a matching
`Origin` and a CSRF token. Adding or removing a passkey, and every admin change, need a fresh
sign-in (within 5 minutes, with a passkey when the person has one).

**Account recovery is designed in, not bolted on.** Three layers: a second sign-in method,
a one-time recovery link from an admin, and a command-line recovery link for the lone admin
who lost everything. A recovery link can revoke the lost device's passkeys and sessions in the
same step. Setup codes, invite and recovery links are stored hashed, expire, and work once.

**Secrets.** Client secrets, upstream secrets and signing keys are encrypted at rest with
AES-256-GCM under keys derived from `HANDSTAMP_SECRET_KEY`. Client secrets are shown once.
Logs redact cookies, authorization headers, codes, tokens and secrets; the first-run setup code
is the one deliberate exception.

**Everything is audited.** Sign-ins (including refusals and the reason), method changes,
recovery, key rotation and every admin change, attributed to who did it. The CSV export
neutralises spreadsheet formulas.

**Defence in depth.** Per-IP rate limits on sign-in, token and setup endpoints. A strict Content
Security Policy with no inline script except one hashed theme snippet, `frame-ancestors 'none'`,
HSTS. No open redirects: only the authorization and logout endpoints redirect to apps, and only to
registered URIs (exact match). Absolute URLs come from the configured issuer, never the Host header.
Outbound calls (back-channel logout) refuse private addresses unless an operator allows them.

## Threat model

| Threat                                                                                     | What stops it                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Account takeover via email**: an attacker's upstream account claims the victim's address | No linking by email. Verified emails are unique. Generic issuers' `email_verified` isn't trusted unless an admin says so. Sign-up is closed by default. Apps are told to key on `(iss, sub)` too.                                                                                                                                   |
| **Lost passkey**                                                                           | A second method, an admin recovery link, or the CLI. The recovery link can revoke the lost device.                                                                                                                                                                                                                                  |
| **Compromised upstream account** (someone's GitHub)                                        | It reaches apps but can't change the account: adding or removing methods needs a passkey when the person has one. The `acr` and `amr` claims tell apps whether a passkey was used, and an app can require one with `acr_values=phr`. People and admins see sessions and can end them, unlink the identity or turn the provider off. |
| **Stolen session cookie**                                                                  | Cookie hardening, a 14-day absolute lifetime, step-up for sensitive actions, a session list with revoke, and sign-out everywhere that also signs apps out through back-channel logout.                                                                                                                                              |
| **Stolen refresh token**                                                                   | Rotation with reuse detection. Refresh tokens die with the session, the user or the app being turned off.                                                                                                                                                                                                                           |
| **Code interception or injection**                                                         | PKCE, 60-second single-use codes, RFC 9207 `iss`, exact redirect URIs.                                                                                                                                                                                                                                                              |
| **Malicious admin or stolen admin session**                                                | Step-up on every admin change, a full audit trail, secrets that can't be read back, guardrails (no removing the last admin, no demoting yourself). Admins never see passkeys' private keys or people's tokens.                                                                                                                      |
| **Setup race**: someone claims a fresh instance first                                      | The code is only in the server logs, rate-limited, valid 60 minutes, and claiming is atomic. The deploy guide says to claim before exposing the URL.                                                                                                                                                                                |

Out of scope: someone with shell access to the host or the root key, which is already everything.
Protect the host, the database and `HANDSTAMP_SECRET_KEY` accordingly
([Deploying → Backups](DEPLOYING.md#backups)).

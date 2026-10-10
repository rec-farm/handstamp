# Connecting an app to Handstamp

Handstamp is a plain OpenID Connect provider. An app connects to it with a standard OIDC client
configuration, with nothing specific to Handstamp, so the same settings work with Authentik,
Keycloak or Zitadel. This guide uses `https://id.rec.farm` as the issuer and Paramtune as the
example app.

- [Register the app](#register-the-app)
- [App settings](#app-settings)
- [Rules for app authors](#rules-for-app-authors)
- [What the app receives](#what-the-app-receives)
- [Signing out](#signing-out)
- [Safe return paths](#safe-return-paths)
- [Worked example: Paramtune with Better Auth](#worked-example-paramtune-with-better-auth)
- [Endpoints](#endpoints)

## Register the app

In Handstamp, **Admin → Apps → Add an app**:

| Field                     | Example                                                    | Notes                                                                                                            |
| ------------------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Name                      | `Paramtune`                                                | Shown on the sign-in card.                                                                                       |
| Client ID                 | `paramtune`                                                | Lowercase, stable. It goes into the app's settings.                                                              |
| Redirect URIs             | `https://paramtune.rec.farm/api/auth/oauth2/callback/oidc` | Matched exactly: no wildcards, no prefixes. `https://` only, except `http://localhost` and `http://*.localhost`. |
| Post-logout redirect URIs | `https://paramtune.rec.farm/`                              | Where Handstamp may send people after signing out.                                                               |
| Scopes it may ask for     | `openid profile email groups`                              | Add `offline_access` only if the app needs refresh tokens.                                                       |
| Client type               | Server app, secret in the header                           | `client_secret_basic`, the default. "Public app" is for SPAs and native apps with no backend; it requires PKCE.  |
| Who may sign in           | Only members of Paramtune users                            | Optional. Anyone else is turned away at Handstamp with a clear message and never reaches the app.                |
| One of your own apps      | on                                                         | Skips the "Allow this app?" screen. Leave off for apps run by someone else.                                      |
| Require PKCE              | on                                                         | Leave on.                                                                                                        |
| Back-channel logout URI   | `https://paramtune.rec.farm/api/auth/backchannel-logout`   | Optional. See [Signing out](#signing-out).                                                                       |

The client secret is shown **once**, together with a ready-to-paste block of settings. Copy it
then; Handstamp only stores it encrypted and can't show it again. Lost it? **Rotate secret** on
the app's page issues a new one; the old one stops working at once.

Then create the groups the app cares about (**Admin → Groups**), for example `paramtune-admins`,
and add people to them.

Apps can also be declared in a file instead of the admin UI; see
[Deploying → Clients as code](DEPLOYING.md#operations-notes).

## App settings

Every R.E.C. app reads the same variables:

| Variable             | Example                       | Meaning                                                                                         |
| -------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------- |
| `OIDC_ISSUER`        | `https://id.rec.farm`         | The issuer. Discovery is at `$OIDC_ISSUER/.well-known/openid-configuration`. No trailing slash. |
| `OIDC_CLIENT_ID`     | `paramtune`                   | From the app's page in Handstamp.                                                               |
| `OIDC_CLIENT_SECRET` | `hs_sec_…`                    | Shown once when the app is created or its secret rotated.                                       |
| `OIDC_SCOPES`        | `openid profile email groups` | Must be a subset of the scopes the app may ask for.                                             |
| `OIDC_ROLES_CLAIM`   | `groups`                      | The claim that holds group slugs (an array of strings).                                         |
| `OIDC_ADMIN_GROUP`   | `paramtune-admins`            | Members of this group become admins in the app. Empty: nobody is promoted by Handstamp.         |
| `OIDC_DISPLAY_NAME`  | `Handstamp`                   | The button label: "Sign in with Handstamp".                                                     |

When `OIDC_ISSUER` or `OIDC_CLIENT_ID` is empty, the app should hide the button and keep working
with whatever other sign-in it has.

## Rules for app authors

1. **Key users on `(iss, sub)`.** `sub` is stable and never reused. Store the pair and look users
   up by it. **Don't link or merge accounts by email**: an email can change hands, and another
   provider may claim one it never checked. Turn off your auth library's automatic account
   linking.
2. **Use the authorization code flow with PKCE (S256)**, and verify the ID token: signature
   against the JWKS, `iss`, `aud`, `exp` and `nonce`. Handstamp only offers `response_type=code`.
3. **Read roles at every sign-in** from `OIDC_ROLES_CLAIM`, and overwrite what you stored. A
   group change in Handstamp then takes effect the next time the person signs in.
4. **Let Handstamp decide who gets in.** Use "Who may sign in" rather than checking groups in
   the app to refuse people. They get a clear message at Handstamp instead of a broken session in
   your app.
5. **Treat `email` as contact data, not identity.** `email_verified` is `true` only when
   Handstamp knows the address is real (it came from GitHub's or Google's verified emails, or a
   trusted issuer).
6. **Fetch the JWKS by `kid` and refresh it on an unknown `kid`.** Keys rotate every 90 days and
   are published a day before they're used, so any library that caches JWKS this way works.
7. **Sign people out properly**, below, and register a back-channel logout URI.
8. **Only redirect to your own paths** after sign-in. See [Safe return paths](#safe-return-paths).

## What the app receives

| Claim                                      | Where              | Scope     | Meaning                                                                                                             |
| ------------------------------------------ | ------------------ | --------- | ------------------------------------------------------------------------------------------------------------------- |
| `sub`                                      | ID token, userinfo | `openid`  | Stable, opaque user id. The identity, together with `iss`.                                                          |
| `acr`                                      | ID token           | `openid`  | `phr` for a passkey sign-in (phishing-resistant), `0` otherwise. See [Asking for a passkey](#asking-for-a-passkey). |
| `amr`                                      | ID token           | `openid`  | `["pop","user","mfa"]` when the person signed in with a passkey. Absent for GitHub/Google/OIDC sign-ins.            |
| `sid`                                      | ID token           | `openid`  | The Handstamp session, to match back-channel logouts. Sent to apps with a back-channel logout URI.                  |
| `auth_time`                                | ID token           | `openid`  | When the person last authenticated. Always sent.                                                                    |
| `groups`                                   | ID token, userinfo | `groups`  | Group slugs, e.g. `["paramtune-admins"]`. Always an array.                                                          |
| `name`, `preferred_username`, `updated_at` | userinfo           | `profile` | Display name and handle.                                                                                            |
| `email`, `email_verified`                  | userinfo           | `email`   | See rule 5.                                                                                                         |

Profile and email claims are in **userinfo**, not the ID token, as the OIDC spec intends for the
code flow. Most libraries call userinfo after the token exchange; make sure yours does (Better
Auth's `genericOAuth` does).

### Asking for a passkey

An app that needs a phishing-resistant sign-in (say, before showing billing or API keys) sends
`acr_values=phr` with the authorization request. Discovery lists `acr_values_supported:
["phr","0"]`.

- If the person's Handstamp session came from a passkey, they go straight through, as usual.
- If it came from GitHub, Google or another OIDC provider, Handstamp asks for their passkey and
  offers nothing else. It refuses any other method on the server too, not only on the card.
- With `prompt=none`, a session below the level gets `login_required` instead.
- `acr_values=phr 0` means "a passkey if there already is one, anything otherwise". Values
  Handstamp doesn't know are ignored.

`id_token.acr` in the `claims` parameter (`value` or `values`) works the same way. Check the
`acr` claim in the ID token either way: a request is only a request, and the token is what was
done. Add `max_age=0` to make someone sign in again even when they already have a passkey session.

Refresh tokens: an app allowed `offline_access` gets one with every sign-in. It rotates on every
use (reusing an old one revokes the whole grant) and ends when the person signs out of Handstamp,
is turned off, or the app is.

## Signing out

### From the app

Clear your own session, then send the browser to Handstamp's end-session endpoint so the
Handstamp session ends too:

```
https://id.rec.farm/session/end?client_id=paramtune
  &id_token_hint=<the ID token>
  &post_logout_redirect_uri=https://paramtune.rec.farm/
```

`post_logout_redirect_uri` must be one of the app's registered post-logout URIs, matched exactly.
Handstamp asks the person to confirm, with "Also sign out of Handstamp" ticked by default. Ticked,
every app in that Handstamp session is signed out; unticked, only yours is. Either way your own
back-channel logout URI is called too, so make that handler idempotent.

### From Handstamp: back-channel logout

An app with a back-channel logout URI hears about sign-outs that happen anywhere else, server to
server ([OpenID Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)).
Without one, the app's session simply lives on until it expires.

**Register the URI** in either place:

- **Admin UI:** Admin → Apps → the app → **Back-channel logout URI**.
- **Clients file** ([`HANDSTAMP_CLIENTS_FILE`](DEPLOYING.md#operations-notes)): add
  `"backchannelLogoutUri"` to the app's entry, then redeploy (the file is read at startup):

  ```json
  {
    "clientId": "paramtune",
    "name": "Paramtune",
    "redirectUris": ["https://paramtune.rec.farm/api/auth/oauth2/callback/oidc"],
    "postLogoutRedirectUris": ["https://paramtune.rec.farm/"],
    "backchannelLogoutUri": "https://paramtune.rec.farm/api/auth/backchannel-logout",
    "secretEnv": "PARAMTUNE_OIDC_CLIENT_SECRET"
  }
  ```

The URI follows the redirect URI rules: absolute, `https://` (plain `http://` only for
`localhost` and `*.localhost`), no wildcard, no `#fragment`, no credentials. Once it's set, ID
tokens for the app carry `sid`; discovery advertises `backchannel_logout_supported` and
`backchannel_logout_session_supported`.

**When Handstamp calls it.** Once for each Handstamp session that included your app:

| What happened                                                                                          | Apps that are told                |
| ------------------------------------------------------------------------------------------------------ | --------------------------------- |
| The person signs out at Handstamp with "Also sign out of Handstamp" (from any app or the account page) | Every app in that session         |
| The person signs out of one app and unticks "Also sign out of Handstamp"                               | That app only                     |
| Account page: **Sign out** on one device                                                               | Every app in that session         |
| Account page: **Sign out everywhere**                                                                  | Every app in every session        |
| Admin → Users → the person: **Sign out everywhere**, or **Turn off account**                           | Every app in every session        |
| A recovery link that removes the person's other sign-in methods is used                                | Every app in every session        |
| Someone else signs in on the same browser                                                              | Every app in the previous session |

Sessions that just expire (idle or maximum age) don't trigger a call, and neither does turning an
app off. Handstamp also revokes the grants behind those sessions, so the refresh tokens stop
working: on a sign-out at Handstamp (either way) and when someone else signs in, all but
`offline_access` ones, which outlive the session; from the account page, by an admin or by
recovery, all of them.

**The request.**

```http
POST /api/auth/backchannel-logout HTTP/1.1
Host: paramtune.rec.farm
User-Agent: Handstamp
Content-Type: application/x-www-form-urlencoded

logout_token=eyJhbGciOiJSUzI1NiIsInR5cCI6ImxvZ291dCtqd3QiLCJraWQiOiLigKYifQ.…
```

The `logout_token` is a JWT signed with the same keys as ID tokens. Header:
`{"alg":"RS256","typ":"logout+jwt","kid":"…"}`. Claims:

| Claim    | Value                                                                                                      |
| -------- | ---------------------------------------------------------------------------------------------------------- |
| `iss`    | The issuer, e.g. `https://id.rec.farm`.                                                                    |
| `aud`    | Your client ID, as a string.                                                                               |
| `iat`    | When it was issued.                                                                                        |
| `exp`    | `iat` + 120 seconds.                                                                                       |
| `jti`    | A random ID, unique per token.                                                                             |
| `sub`    | The person: the same `sub` as in your ID tokens.                                                           |
| `sid`    | The session, the same `sid` as in the ID token you got for it. It's per app: don't compare it across apps. |
| `events` | `{"http://schemas.openid.net/event/backchannel-logout": {}}`                                               |

There is never a `nonce`. Both `sub` and `sid` are always present.

**Handling it.**

1. Verify the token as the spec says (§2.6): signature against the JWKS by `kid` (refetch it on an
   unknown `kid`), `typ` is `logout+jwt`, `iss` is your issuer, `aud` is your client ID,
   `iat`/`exp` within a small clock skew, `events` has the back-channel logout member, and there's
   no `nonce`. Optionally remember `jti` until `exp` and reject repeats. Most OIDC libraries have a
   helper for this; don't reuse your ID-token check unchanged, because it would demand a `nonce`.
2. End your sessions for `(iss, sub, sid)`. If you don't store `sid`, end every session for
   `(iss, sub)`. Revoke any Handstamp refresh token you hold for them.
3. Answer `200` with `Cache-Control: no-store`, or `400` if the token is invalid. The body is
   ignored. Answer quickly: Handstamp waits 10 seconds.

The endpoint takes no cookie and no CSRF token: exempt it from your CSRF middleware and your
sign-in requirement. The signed token is the authentication.

**Reachability.** The call comes from the Handstamp server, not the person's browser, so the URI
must resolve and be reachable from wherever Handstamp runs. Handstamp:

- refuses loopback, private, link-local and other non-public addresses unless
  [`ALLOW_PRIVATE_NETWORKS`](DEPLOYING.md#operations-notes) is on, and connects to exactly the
  address it checked (no DNS rebinding);
- doesn't follow redirects: a `301` or `302` counts as a failure, so register the final URL;
- tries **once**. A failure (no answer, a timeout, a non-2xx status) is logged on Handstamp as
  `back-channel logout failed` with your client ID, and not retried. Keep your own sessions
  reasonably short so a missed call can't keep someone signed in forever.

## Safe return paths

Apps usually carry a "where to go after signing in" value through the flow (`returnTo`,
`callbackURL`, `next`). That's an app-side parameter, not part of OIDC, and an open redirect if
it's trusted: a link to your sign-in with `returnTo=//evil.example` lands someone on a look-alike
site right after a real sign-in. Store it with the flow state (not in the `redirect_uri`), and
accept only a path on your own origin. A prefix check like "starts with `/`" isn't enough. Reject,
and fall back to a fixed page, when the value:

- doesn't start with exactly one `/`: `//evil.example` and `https://evil.example` leave your
  origin (a network-path reference);
- contains a **backslash**: browsers treat `\` as `/`, so `/\evil.example` is `//evil.example`;
- contains **control characters** (`\t`, `\r`, `\n`, `\x00`–`\x1f`, `\x7f`): browsers drop tabs and
  newlines while parsing, so `/\t/evil.example` becomes `//evil.example`, and `\r\n` can split
  headers;
- has a `.` or `..` **dot segment**, also percent-encoded (`%2e`, `%2E`): normalization turns
  `/.//evil.example` into `//evil.example`, and `/./api/sign-out` into an API route.

The robust form: parse it against your own origin (`new URL(value, origin)`) after the checks
above, require the same origin, and require the normalized path not to start with `//`. Also keep
your own API and auth routes (`/api/…`) off the list of allowed targets. Paramtune's
`safe_return` ([`backend/src/auth.rs`](https://github.com/RodrigoEspinosa/paramtune/blob/master/backend/src/auth.rs))
and `safeReturnTo` ([`src/lib/returnTo.ts`](https://github.com/RodrigoEspinosa/paramtune/blob/master/src/lib/returnTo.ts))
do all of this, with a test for each case.

## Worked example: Paramtune with Better Auth

Better Auth 1.7, `genericOAuth` plugin. The provider ID is the generic `oidc`, not `handstamp`,
so moving to another IdP only means changing env vars.

```ts
// src/lib/auth.ts
import { betterAuth } from 'better-auth';
import { genericOAuth } from 'better-auth/plugins';

const oidcEnabled = Boolean(process.env.OIDC_ISSUER && process.env.OIDC_CLIENT_ID);
const rolesClaim = process.env.OIDC_ROLES_CLAIM ?? 'groups';
const adminGroup = process.env.OIDC_ADMIN_GROUP;

export const auth = betterAuth({
  // …existing database, baseURL, secret…
  user: { additionalFields: { role: { type: 'string', defaultValue: 'member', input: false } } },
  account: { accountLinking: { enabled: false } }, // rule 1: never link by email
  plugins: [
    ...(oidcEnabled
      ? [
          genericOAuth({
            config: [
              {
                providerId: 'oidc',
                discoveryUrl: `${process.env.OIDC_ISSUER}/.well-known/openid-configuration`,
                clientId: process.env.OIDC_CLIENT_ID!,
                clientSecret: process.env.OIDC_CLIENT_SECRET,
                scopes: (process.env.OIDC_SCOPES ?? 'openid profile email').split(/\s+/),
                // Better Auth sends the secret in the body by default; Handstamp apps default to
                // the header. Either pick 'basic' here, or "secret in the body" in Handstamp.
                authentication: 'basic',
                pkce: true,
                requireIdTokenVerification: true,
                overrideUserInfo: true, // rule 3: refresh name, email and role at every sign-in
                mapProfileToUser: (profile) => {
                  const groups = Array.isArray(profile[rolesClaim]) ? profile[rolesClaim] : [];
                  return {
                    name: profile.name ?? profile.preferred_username,
                    email: profile.email,
                    role: adminGroup && groups.includes(adminGroup) ? 'admin' : 'member',
                  };
                },
              },
            ],
          }),
        ]
      : []),
  ],
});
```

The button: `authClient.signIn.oauth2({ providerId: 'oidc', callbackURL: '/' })`, labelled
`Sign in with ${OIDC_DISPLAY_NAME}`. The callback URL to register in Handstamp is
`<app origin>/api/auth/oauth2/callback/oidc`.

Paramtune's `.env`:

```sh
OIDC_ISSUER=https://id.rec.farm
OIDC_CLIENT_ID=paramtune
OIDC_CLIENT_SECRET=hs_sec_…
OIDC_SCOPES=openid profile email groups
OIDC_ROLES_CLAIM=groups
OIDC_ADMIN_GROUP=paramtune-admins
OIDC_DISPLAY_NAME=Handstamp
```

Better Auth keys accounts on `(providerId, accountId)` with `accountId = sub`. That is rule 1 as
long as one `providerId` maps to one issuer: if you ever point `oidc` at a different issuer, the
old accounts won't match, which is the safe failure.

## Endpoints

All of them are in the discovery document; apps should read them from there.

| Endpoint      | Path                                |
| ------------- | ----------------------------------- |
| Discovery     | `/.well-known/openid-configuration` |
| Authorization | `/auth`                             |
| Token         | `/token`                            |
| Userinfo      | `/me`                               |
| JWKS          | `/jwks`                             |
| End session   | `/session/end`                      |
| Revocation    | `/token/revocation`                 |
| Introspection | `/token/introspection`              |

Try it end to end locally with the example app in [`examples/test-app`](../examples/test-app)
(`pnpm example`, see the README).

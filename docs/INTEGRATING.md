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
7. **Sign people out properly**, below.

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

**From the app.** Clear your own session, then send the browser to Handstamp's end-session
endpoint so the Handstamp session ends too:

```
https://id.rec.farm/session/end?client_id=paramtune
  &id_token_hint=<the ID token>
  &post_logout_redirect_uri=https://paramtune.rec.farm/
```

`post_logout_redirect_uri` must be one of the app's registered post-logout URIs.

**From Handstamp.** When someone signs out elsewhere, uses "Sign out everywhere", is turned off
by an admin, or has a session ended, Handstamp POSTs a signed `logout_token` to each app's
back-channel logout URI. The token carries `iss`, `aud`, `sub`, `sid` and the back-channel logout
event. Verify it like an ID token (same JWKS, no `nonce`), then end the app sessions that came
from that `sid` (or every session for that `sub` if you don't store `sid`). Answer `200`.

Back-channel calls come from the Handstamp server, not the browser, so the URI must be reachable
from it. For private addresses see
[`ALLOW_PRIVATE_NETWORKS`](DEPLOYING.md#operations-notes).

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

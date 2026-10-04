# Handstamp

The passwordless OpenID Connect provider for the R.E.C. product family (RECIAM SAS). Read `docs/PLAN.md` before changing anything.

## Design system (mandatory)

- Source of truth: `/Users/rec/Projects/reciam-brand/DESIGN.md` (repo `RodrigoEspinosa/rec-brand`, tokens copied at **brand v1.6.0**).
- **Every UI change must pass the review checklist in DESIGN.md §16** before it ships. Check Dark and Paper.
- Tokens: copy the §14 Tailwind v4 block into `apps/web/src/styles.css`. Don't use submodules or symlinks. Record `brand v1.6.0` wherever tokens or assets are copied.
- Signature accent: **Lilac** (`data-product="handstamp"`). It marks active nav and product identity only. Buttons, links and focus rings stay purple.
- Wordmark `HANDSTAMP`: Archivo wdth 125, 700, tracking 0.14–0.18em. Sidebar footer: `HANDSTAMP · by REC` and the version in mono.
- Mono for machine data (client IDs, `sub`, issuer URLs, key IDs, timestamps, scopes). Sans for human text. Page titles end with the purple period. Section labels are stamps.
- Don't draw the logo here. It is added to `rec-brand/build.py` (§2.10). Keep the placeholder and its TODO.

## Hard rules

- Never hand-roll the protocol: `oidc-provider` owns every OIDC endpoint, and `openid-client` handles upstream IdPs.
- Identity is `(issuer, subject)`. Never link or merge accounts by email.
- No passwords, OTP, SMS, magic links or any other human shared secret.
- Secrets never reach logs. The one-time setup banner is the only exception.

## Working notes

- The production CSP is `script-src 'self'` + one hash and `style-src 'self'`: no inline `<script>`, no React `style={…}` props. Use Tailwind classes.
- Protocol changes must keep the OpenID conformance suite green: `./conformance/run.sh` (smoke) or `./conformance/run.sh full`. Accepted gaps live in `conformance/expected-*.json`, each with a reason.
- `pnpm check` runs typecheck, tests and build. Integration tests need the dev Postgres (`compose.yaml`) and a `handstamp_test` database.

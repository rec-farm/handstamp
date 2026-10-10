# Handstamp

The passwordless OpenID Connect provider for the R.E.C. product family (RECIAM SAS). Read `docs/PLAN.md` before changing anything.

## Design system (mandatory)

- Source of truth: `/Users/rec/Projects/reciam-brand/DESIGN.md` (repo `RodrigoEspinosa/rec-brand`, tokens copied at **brand v1.6.0**).
- **Every UI change must pass the review checklist in DESIGN.md §16** before it ships. Check Dark and Paper.
- Tokens: copy the §14 Tailwind v4 block into `apps/web/src/styles.css`. Don't use submodules or symlinks. Record `brand v1.6.0` wherever tokens or assets are copied.
- Signature accent: **Lilac** (`data-product="handstamp"`). It marks active nav and product identity only. Buttons, links and focus rings stay purple.
- Wordmark `HANDSTAMP`: the outlined lockup (Archivo wdth 125, 700, tracking 0.16em), never live text. Sidebar footer: `HANDSTAMP · by REC` and the version in mono.
- Mono for machine data (client IDs, `sub`, issuer URLs, key IDs, timestamps, scopes). Sans for human text. Page titles end with the purple period. Section labels are stamps.
- The logo comes from `rec-brand/build.py` (brand v1.7.0). The SVGs in `apps/web/src/assets/brand/` are copies of `rec-brand/logos/handstamp-*`: replace them with new exports, never edit or redraw them here. `Lockup` in `components/ui.tsx` picks cream or ink per theme.

## Hard rules

- The provider is Rust (`backend/`), written to oidc-provider 9's behaviour (docs/RUST-PORT.md). Every protocol change keeps the full OpenID conformance run green with no new accepted gaps, and lands with a flow test in `tests/`. Upstream IdPs go through the `openidconnect` crate; don't hand-roll client-side OIDC.
- Identity is `(issuer, subject)`. Never link or merge accounts by email.
- No passwords, OTP, SMS, magic links or any other human shared secret.
- Secrets never reach logs. The one-time setup banner is the only exception.

## Working notes

- The production CSP is `script-src 'self'` + one hash and `style-src 'self'`: no inline `<script>`, no React `style={…}` props. Use Tailwind classes.
- Protocol changes must keep the OpenID conformance suite green: `./conformance/run.sh` (smoke) or `./conformance/run.sh full`. Accepted gaps live in `conformance/expected-*.json`, each with a reason.
- `pnpm check` runs `cargo fmt`/clippy (`-D warnings`), typecheck, the Rust unit tests, the flow tests in `tests/` (against a debug build of the binary) and the build. Flow tests need the dev Postgres (`compose.yaml`) and a `handstamp_test` database.
- The server is `backend/` (Rust, axum). The UI is `apps/web` (Vite); in development Vite fronts the Rust server on one origin (`scripts/dev.ts`). Migrations are `backend/migrations/*.sql`, embedded at build time; never edit a shipped one, add the next number.

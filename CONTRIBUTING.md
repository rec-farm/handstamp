# Contributing to Handstamp

Thanks for helping. Handstamp is the sign-in for every R.E.C. app, so changes are held to a high
bar: small, tested and standards-only. Everyone taking part follows the
[R.E.C. Code of Conduct](https://github.com/rec-farm/.github/blob/main/CODE_OF_CONDUCT.md).

Found a security issue? Don't open an issue: use
[private vulnerability reporting](https://github.com/rec-farm/handstamp/security/advisories/new).

## Prerequisites

Rust 1.92, Node 24, pnpm 11 (the version in `package.json`'s `packageManager`) and Docker.

## Run it locally

```sh
pnpm install
cp .env.example .env              # then set HANDSTAMP_SECRET_KEY (openssl rand -base64 32)
docker compose up db              # Postgres on 127.0.0.1:5438
docker compose exec db psql -U handstamp -c 'CREATE DATABASE handstamp_test'   # once, for the tests
pnpm dev                          # http://localhost:3000
```

The [README](README.md#develop) covers the example app, the demo identity provider and the CLI.
Read [`docs/PLAN.md`](docs/PLAN.md) before changing anything substantial.

## Before you open a pull request

Run the full check and make sure it passes:

```sh
pnpm check                        # cargo fmt + clippy, typecheck, Rust and flow tests, build
pnpm format:check                 # Prettier, as CI runs it
```

Protocol changes must also keep the OpenID conformance suite green (`./conformance/run.sh`) with
no new accepted gaps, and come with a flow test in `tests/`.

- **One change per pull request.** Keep unrelated fixes for another PR.
- **Conventional Commits**, as in `git log`: `feat(oidc): …`, `fix: …`, `docs(integrating): …`,
  `test: …`, `chore: …`.

## Rules that matter

- **No passwords**, OTP, SMS, magic links or any other human shared secret.
- **Identity is `(issuer, subject)`.** Never link or merge accounts by email.
- **Migrations are append-only** (`backend/migrations/*.sql`). Never edit one that has shipped; add
  the next number.
- **Secrets never reach logs or API responses**, beyond a one-time reveal.
- **CSP:** production is `script-src 'self'` (plus one hash) and `style-src 'self'`. No inline
  `<script>` and no React `style={…}` props; use Tailwind classes.
- **UI** follows the R.E.C. design system ([`rec-farm/rec-brand`](https://github.com/rec-farm/rec-brand)):
  check Dark and Paper. Don't edit or redraw the logos in `apps/web/src/assets/brand/`.

By contributing, you agree your contributions are licensed under the MIT License (see
[LICENSE](LICENSE)).

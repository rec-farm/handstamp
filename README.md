# Handstamp

The passwordless OpenID Connect provider for the R.E.C. product family. Small, self-hostable,
standards-only: any app that speaks OIDC can use it, and it can be swapped for Authentik, Keycloak
or Zitadel without touching the app. Product page: [rec.farm/handstamp](https://rec.farm/handstamp/).

> **Status: v1 (M5).** Passkeys, upstream sign-in, invites and recovery, the account page, the
> admin console, a production image, and full OpenID conformance (Basic OP, Config OP). See
> [`docs/PLAN.md`](docs/PLAN.md).

- **Run it:** [`docs/DEPLOYING.md`](docs/DEPLOYING.md) (Dokploy or plain Docker Compose)
- **Connect an app:** [`docs/INTEGRATING.md`](docs/INTEGRATING.md)
- **Security and reporting:** [`docs/SECURITY.md`](docs/SECURITY.md)

## Develop

Needs Rust 1.92, Node 24, pnpm 11 and Docker.

```sh
pnpm install
cp .env.example .env              # then set HANDSTAMP_SECRET_KEY (openssl rand -base64 32)
docker compose up db              # Postgres on 127.0.0.1:5438
pnpm dev                          # http://localhost:3000: Vite in front, the Rust server behind it
```

On first start Handstamp prints a one-time setup code. Open http://localhost:3000, enter it,
and create your passkey: you're the first admin. Lost the code? `pnpm handstamp setup-code`.

With `HANDSTAMP_DEV_LOGIN=1` the sign-in card offers "Continue as test user". It only works on
localhost, `*.localhost` and `*.test` issuers.

To try a full sign-in, run the example app (a plain OIDC client, like any R.E.C. app) and open
http://localhost:4000:

```sh
pnpm example                      # needs HANDSTAMP_CLIENTS_FILE=examples/clients.json and LOCAL_RP_CLIENT_SECRET in .env
```

To try "Continue with …" without registering a GitHub app, run the demo identity provider (its
settings are in `.env.example` under `HANDSTAMP_UPSTREAM_OIDC_DEMO_*` once you copy them in):

```sh
pnpm example:idp                  # http://localhost:4100, pick a person, no passwords
pnpm handstamp invite             # a one-time invite link
pnpm handstamp recovery <sub|email> [--revoke]   # a one-time recovery link
```

```sh
pnpm check                        # typecheck, tests, build
pnpm handstamp keys list          # signing keys and their state
pnpm handstamp keys rotate        # stage a new key (published now, signs after KEY_STAGE_HOURS)
pnpm e2e                          # the real UI in Chromium with a virtual passkey authenticator
./conformance/run.sh              # OpenID conformance suite, Config OP + Basic OP smoke subset
```

The integration tests need the test database: `docker compose exec db psql -U handstamp -c 'CREATE DATABASE handstamp_test'`.

## Layout

| Path                 | What                                                                               |
| -------------------- | ---------------------------------------------------------------------------------- |
| `backend`            | Rust (axum): the OpenID provider, the interaction, account and admin APIs, the CLI |
| `backend/migrations` | Postgres migrations, embedded in the binary                                        |
| `apps/web`           | Vite + React SPA: sign-in, consent, account, admin console                         |
| `tests`              | Black-box flow tests and Chromium e2e tests against the `handstamp` binary         |
| `conformance`        | Pinned OIDF conformance suite setup                                                |

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/rec-farm/handstamp/security/advisories/new),
not in a public issue. The security model is in [`docs/SECURITY.md`](docs/SECURITY.md).

## License

MIT · © 2026 Rodrigo Espinosa Curbelo. Names and logos: see [NOTICE](NOTICE).

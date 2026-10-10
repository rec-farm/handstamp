# Deploying Handstamp

Handstamp is one container (a single Rust binary serving the OIDC endpoints, the API and the web UI) plus
Postgres 17. It sits behind your TLS reverse proxy. This guide uses `https://id.rec.farm` as the
example issuer.

- [Before you start](#before-you-start)
- [Dokploy](#dokploy)
- [Plain Docker Compose](#plain-docker-compose)
- [Claim the instance](#claim-the-instance)
- [The command line](#the-command-line)
- [Backups](#backups)
- [Upgrades](#upgrades)
- [Signing keys](#signing-keys)
- [Operations notes](#operations-notes)
- [Go-live checklist](#go-live-checklist)

## Before you start

**Pick the issuer once.** `HANDSTAMP_ISSUER` is the OIDC issuer apps trust, and its host is the
WebAuthn relying party ID that every passkey is bound to. Changing it later breaks every passkey
and every app's configuration. Use a dedicated subdomain (`id.rec.farm`), with no path.

**Generate the root key and keep it safe.**

```sh
openssl rand -base64 32
```

This is `HANDSTAMP_SECRET_KEY`. It encrypts client secrets, upstream provider secrets, signing keys
and cookie keys in the database. Store it in your password manager **and** next to your database
backups ([Backups](#backups)). A database without its key can't be restored usefully.

The minimum `.env`:

```sh
HANDSTAMP_ISSUER=https://id.rec.farm
HANDSTAMP_SECRET_KEY=…                 # from openssl above
POSTGRES_PASSWORD=…                    # any long random string; compose wires DATABASE_URL from it
TRUST_PROXY=1                          # one reverse proxy hop (Traefik, Caddy, nginx)
HANDSTAMP_INSTANCE_NAME=R.E.C.
```

Every other setting is optional and documented in [`.env.example`](../.env.example).

### `TRUST_PROXY`

Handstamp needs the real client IP for rate limits and the audit log, and the original scheme
for its URLs. `TRUST_PROXY` says how many proxies to believe:

| Setup                                       | `TRUST_PROXY`                   |
| ------------------------------------------- | ------------------------------- |
| Dokploy (Traefik) or one Caddy/nginx        | `1`                             |
| Cloudflare (proxied) in front of Traefik    | `2`                             |
| Proxies with fixed addresses                | `10.0.0.2,10.0.0.3` (IPs/CIDRs) |
| Handstamp faces the internet directly (TLS) | empty                           |

It is never "trust everything": a client could then forge `X-Forwarded-For` and dodge rate limits.
Too low and every request looks like it comes from the proxy, so one person can rate-limit
everyone. Check after deploying: the IP column of the audit log (Admin → Audit log) should show
real addresses.

## Dokploy

1. **Create a Compose service** in your project. Source: this Git repository, compose path
   `./compose.yaml`. It builds the image from the `Dockerfile` and runs Postgres next to it.
2. **Environment:** paste the `.env` from above into the service's Environment tab. Dokploy
   writes it to `.env` next to `compose.yaml`, which is where `env_file` reads it.
3. **Domain:** in the Domains tab, add `id.rec.farm` → service `handstamp`, container port
   `3000`, HTTPS on with a Let's Encrypt certificate. Point the DNS record at your Dokploy host.
   Traefik reaches the container over Docker's network, so the `127.0.0.1` port binding in
   `compose.yaml` doesn't matter here.
4. **Deploy**, then open the logs of the `handstamp` service and [claim the instance](#claim-the-instance).

Dokploy's own health view uses the image's `HEALTHCHECK` (`/readyz`). One replica is plenty;
more work too ([replicas](#operations-notes)).

If you'd rather use a Dokploy-managed Postgres, deploy the `Dockerfile` as an Application
instead and set `DATABASE_URL` to the managed database's internal URL. The image already runs in
production mode on `0.0.0.0:3000`. Postgres TLS is used when the server offers it; add
`?sslmode=require` to insist on it (certificates are checked against the Mozilla root store).

## Plain Docker Compose

On any host with Docker and a TLS reverse proxy:

```sh
git clone <this repo> handstamp && cd handstamp
cp .env.example .env    # fill in the minimum above
docker compose up -d --build --wait
```

Handstamp listens on `127.0.0.1:3000` (set `HANDSTAMP_PORT` to change the host port). Point your
proxy at it. With Caddy:

```caddy
id.rec.farm {
	reverse_proxy 127.0.0.1:3000
}
```

`docker compose up db` alone runs only Postgres on `127.0.0.1:5438`, which is what local
development uses.

## Claim the instance

A fresh instance has no admin. On start it logs a one-time setup code:

```
  Handstamp has no admin yet. Open https://id.rec.farm/setup and enter this code:

      HS-FNZBH-7N242-Y3QVM-435JQ

  It works for 60 minutes. Restart Handstamp or run "handstamp setup-code" for a new one.
```

Open the issuer URL, enter the code, and create your passkey. You are the first admin. The code
works once and expires after 60 minutes; restart or run `handstamp setup-code` for a new one.

**Claim it before you tell anyone the URL.** Whoever enters the code first owns the instance.
The code only exists in the logs, so the risk is small, but it's zero once you've claimed it.

This banner is the only secret Handstamp ever logs.

## The command line

The image has a `handstamp` command. Run it inside the container:

```sh
docker compose exec handstamp handstamp help
```

| Command                            | What it does                                                                                              |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `setup-code`                       | A new first-run setup code (only before the instance is claimed).                                         |
| `invite`                           | A one-time invite link, valid 7 days.                                                                     |
| `recovery <sub or email>`          | A one-time recovery link, valid 30 minutes. Their passkeys keep working.                                  |
| `recovery <sub or email> --revoke` | The same, and using it removes their other passkeys and ends their sessions. For a lost or stolen device. |
| `keys list`                        | Signing keys and their state.                                                                             |
| `keys rotate` / `keys promote`     | See [Signing keys](#signing-keys).                                                                        |
| `migrate`                          | Apply database migrations (the server does this on start anyway).                                         |

`recovery` is the break-glass for the lone admin who lost every passkey: shell access to the host
already holds the root key and the database, so it is the root of trust. Every use is in the
audit log as done from the command line.

In Dokploy, run the same commands from the service's terminal (`handstamp invite`).

## Backups

Back up two things, together:

1. **The database.** Everything lives in Postgres: users, passkeys, apps, groups, sessions, keys
   and the audit log.

   ```sh
   docker compose exec -T db pg_dump -U handstamp -Fc handstamp > handstamp-$(date +%F).dump
   ```

   Restore into an empty database with `pg_restore -U handstamp -d handstamp --clean`.

2. **`HANDSTAMP_SECRET_KEY`.** Without it, a restored database can't decrypt its signing keys,
   client secrets or upstream secrets. You'd have to re-issue every app's secret and re-enter
   every provider's, and apps would see new signing keys. Passkeys and users would survive.

Keep the key somewhere other than the dump: a backup that holds both is as sensitive as the
running instance.

## Upgrades

```sh
git pull
docker compose up -d --build --wait
```

Migrations run automatically when the server starts, under a Postgres advisory lock. They only
move forward, so **take a backup first**: going back to an older version means restoring it.

Sessions survive a restart. People don't have to sign in again.

## Signing keys

ID tokens are signed with RS256 keys that rotate on their own:

- Every `KEY_ROTATION_DAYS` (90) a new key is **staged**: published in the JWKS but not used yet.
- After `KEY_STAGE_HOURS` (24) it becomes **active** and signs new tokens. Apps that cache the
  JWKS have had a day to pick it up.
- The old key stays published until the tokens it signed have expired, then retires.

To rotate now (for example after a suspected leak), use Admin → Signing keys, or:

```sh
docker compose exec handstamp handstamp keys rotate    # stage a new key now
docker compose exec handstamp handstamp keys promote   # start signing with it immediately
```

`KEY_ROTATION_DAYS=0` turns automatic rotation off.

## Operations notes

**Replicas.** One `handstamp` container is enough for the traffic an identity provider gets, and
restarts take a few seconds without losing anything: sessions live in Postgres. You can run more
behind the same proxy. Every replica keeps its state in Postgres: sessions, codes, tokens,
signing keys (picked up within a minute), rate-limit counts and the setup code. Maintenance runs on one
replica at a time. All replicas need the same `HANDSTAMP_SECRET_KEY`, `HANDSTAMP_ISSUER` and
database. Before the instance is claimed, a replica that starts within 30 seconds of another
keeps the setup code the first one printed, so look for the code in the first replica's logs.

**Health checks.** `GET /healthz` says the process is up. `GET /readyz` also checks the database
and returns 503 when it can't reach it. The image's `HEALTHCHECK` uses `/readyz`.

**Back-channel logout to apps on a private network.** When someone signs out, Handstamp calls
each app's back-channel logout URI. By default it refuses loopback and private addresses, so a
request can't be pointed at your internal network. If your apps run next to Handstamp on the same
Docker network and you register internal URLs, set `ALLOW_PRIVATE_NETWORKS=true`. Public URLs
don't need it. The URI must still be `https://` (plain `http://` is only accepted for `localhost`
and `*.localhost`), so an internal URL needs TLS on that network; otherwise register the app's
public URL. What apps receive is in [Integrating → Signing out](INTEGRATING.md#signing-out).

**Clients as code.** Apps can be declared in a JSON file instead of the admin UI
(`HANDSTAMP_CLIENTS_FILE`, see [`examples/clients.json`](../examples/clients.json)). Each entry
names the environment variable holding its secret; secrets never go in the file. `compose.yaml`
mounts `./config` read-only at `/config`, so put the file there and set:

```sh
HANDSTAMP_CLIENTS_FILE=/config/clients.json
PARAMTUNE_OIDC_CLIENT_SECRET=…          # whatever each entry's secretEnv names, 32+ characters
```

In Dokploy, add the file under the service's **Advanced → Mounts** as a file mount named
`clients.json` and set `HANDSTAMP_CONFIG_DIR=../files`, which is where Dokploy writes file mounts
for a Compose service. Redeploy after changing the file: it is synced at startup.

Those apps show up read-only in the admin UI.

**Logs.** JSON lines on stdout. Cookies, authorization headers, codes, tokens and secrets
are redacted. `LOG_LEVEL=debug` adds detail without exposing them.

## Go-live checklist

- [ ] `HANDSTAMP_ISSUER` is the final `https://` URL, and DNS and TLS work.
- [ ] `HANDSTAMP_SECRET_KEY` is stored outside the server.
- [ ] `TRUST_PROXY` matches your proxy hops, and the audit log shows real IPs.
- [ ] You claimed the instance and have a passkey on **two** devices (or a linked GitHub/Google
      account), so losing one doesn't lock you out.
- [ ] A second person is admin, or you know how to run `handstamp recovery`.
- [ ] Database backups run, and you've restored one once.
- [ ] `HANDSTAMP_DEV_LOGIN` is unset or `0`.

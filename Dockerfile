# One image, one process: the Rust server (backend/) serves the OpenID provider, the API and the
# built SPA (docs/PLAN.md §1.2). The runtime is a bare Alpine with one static binary.
FROM rust:1.92-alpine AS server
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY backend/Cargo.toml backend/Cargo.lock backend/build.rs backend/
COPY backend/migrations backend/migrations
COPY backend/src backend/src
RUN cargo build --release --locked --manifest-path backend/Cargo.toml

FROM node:24-alpine AS web
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN npm install --global pnpm@11.9.0
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile --filter @handstamp/web...
COPY tsconfig.base.json ./
COPY apps/web apps/web
RUN pnpm --filter @handstamp/web build

FROM alpine:3.23 AS runtime
LABEL org.opencontainers.image.title="Handstamp" \
      org.opencontainers.image.description="Passwordless OpenID Connect provider for the R.E.C. product family" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="RECIAM SAS"
RUN apk add --no-cache ca-certificates \
  && addgroup -S -g 1000 handstamp && adduser -S -u 1000 -G handstamp -h /app handstamp
# `docker compose exec handstamp handstamp invite` and friends (see docs/DEPLOYING.md).
COPY --from=server /app/backend/target/release/handstamp /usr/local/bin/handstamp
COPY --from=web /app/apps/web/dist /app/web/dist
ENV HANDSTAMP_ENV=production HANDSTAMP_WEB_DIST=/app/web/dist
USER handstamp
WORKDIR /app
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-3000}/readyz" || exit 1
CMD ["handstamp", "serve"]

# One image, one process: the Rust server (backend/) serves the OpenID provider, the API and the
# built SPA (docs/PLAN.md §1.2). The runtime is a bare Alpine with one static binary.
FROM rust:1.92-alpine AS server
# Cargo profile (and target/ subdirectory) to build: `dist` for the shipped image, `release` where
# build time matters more than whole-program LTO (the conformance run).
ARG CARGO_PROFILE=dist
RUN apk add --no-cache musl-dev
WORKDIR /app
# Build dependencies first, against a stub main and no migrations, so source and migration edits
# don't recompile them.
COPY backend/Cargo.toml backend/Cargo.lock backend/build.rs backend/
RUN mkdir -p backend/src backend/migrations && echo "fn main() {}" > backend/src/main.rs \
    && cargo build --profile "$CARGO_PROFILE" --locked --manifest-path backend/Cargo.toml && rm -rf backend/src
COPY backend/migrations backend/migrations
COPY backend/src backend/src
RUN touch backend/src/main.rs backend/build.rs \
    && cargo build --profile "$CARGO_PROFILE" --locked --manifest-path backend/Cargo.toml \
    && cp "backend/target/$CARGO_PROFILE/handstamp" /app/handstamp

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
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="RECIAM SAS"
RUN apk add --no-cache ca-certificates \
  && addgroup -S -g 1000 handstamp && adduser -S -u 1000 -G handstamp -h /app handstamp
# `docker compose exec handstamp handstamp invite` and friends (see docs/DEPLOYING.md).
COPY --from=server /app/handstamp /usr/local/bin/handstamp
COPY --from=web /app/apps/web/dist /app/web/dist
ENV HANDSTAMP_ENV=production HANDSTAMP_WEB_DIST=/app/web/dist
USER handstamp
WORKDIR /app
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-3000}/readyz" || exit 1
CMD ["handstamp", "serve"]

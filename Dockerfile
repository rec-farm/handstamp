# One image, one process: Node serves oidc-provider, the API and the built SPA (docs/PLAN.md §1.2).
# The server is bundled to plain ESM at build time, so the runtime is a bare Alpine plus the
# Node binary: no npm, no pnpm, no tsx, no node_modules.
FROM node:24-alpine AS build
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN npm install --global pnpm@11.9.0
WORKDIR /app
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/core/package.json packages/core/package.json
COPY packages/db/package.json packages/db/package.json
RUN pnpm install --frozen-lockfile --filter @handstamp/server... --filter @handstamp/web...
COPY tsconfig.base.json ./
COPY packages packages
COPY apps apps
RUN pnpm --filter @handstamp/web build && pnpm --filter @handstamp/server build

FROM node:24-alpine AS node

FROM alpine:3.23 AS runtime
LABEL org.opencontainers.image.title="Handstamp" \
      org.opencontainers.image.description="Passwordless OpenID Connect provider for the R.E.C. product family" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="RECIAM SAS"
ENV NODE_ENV=production
RUN apk add --no-cache libstdc++ libgcc tini \
  && addgroup -S -g 1000 node && adduser -S -u 1000 -G node -h /home/node node
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# Same layout as the repo (apps/server/dist next to apps/web/dist), so the bundle finds the SPA.
COPY --from=build /app/apps/server/dist /app/server/dist
COPY --from=build /app/apps/web/dist /app/web/dist
# `docker compose exec handstamp handstamp invite` and friends (see docs/DEPLOYING.md).
RUN printf '#!/bin/sh\nexec node --enable-source-maps /app/server/dist/cli.js "$@"\n' > /usr/local/bin/handstamp \
  && chmod 755 /usr/local/bin/handstamp
USER node
WORKDIR /app/server
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-3000}/readyz" || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "--enable-source-maps", "dist/main.js"]

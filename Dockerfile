# One image, one process: Fastify serves oidc-provider, the API and the built SPA (docs/PLAN.md §1.2).
FROM node:24-bookworm-slim AS base
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN npm install --global pnpm@11.9.0
WORKDIR /app

FROM base AS manifests
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/server/package.json apps/server/package.json
COPY apps/web/package.json apps/web/package.json
COPY packages/core/package.json packages/core/package.json
COPY packages/db/package.json packages/db/package.json

FROM manifests AS web-build
RUN pnpm install --frozen-lockfile --filter @handstamp/web...
COPY tsconfig.base.json ./
COPY apps/web apps/web
RUN pnpm --filter @handstamp/web build

FROM manifests AS runtime
LABEL org.opencontainers.image.title="Handstamp" \
      org.opencontainers.image.description="Passwordless OpenID Connect provider for the R.E.C. product family" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="RECIAM SAS"
ENV NODE_ENV=production
RUN apt-get update \
  && apt-get install --yes --no-install-recommends tini \
  && rm -rf /var/lib/apt/lists/*
RUN pnpm install --frozen-lockfile --prod --filter @handstamp/server...
COPY tsconfig.base.json ./
COPY packages packages
COPY apps/server apps/server
COPY --from=web-build /app/apps/web/dist apps/web/dist
# `docker compose exec handstamp handstamp invite` and friends (see docs/DEPLOYING.md).
RUN printf '#!/bin/sh\ncd /app/apps/server && exec node --import tsx src/cli.ts "$@"\n' > /usr/local/bin/handstamp \
  && chmod 755 /usr/local/bin/handstamp
USER node
WORKDIR /app/apps/server
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/readyz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
ENTRYPOINT ["tini", "--"]
CMD ["node", "--import", "tsx", "src/main.ts"]

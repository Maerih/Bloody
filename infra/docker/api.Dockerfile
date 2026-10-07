# syntax=docker/dockerfile:1.10
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Bloody control plane (apps/api) — production image.
#
#   docker build -f infra/docker/api.Dockerfile -t bloody/api:dev .
#
# Stages
#   base     Node + pinned pnpm (corepack)
#   fetch    pnpm store populated from the lockfile only (cached across source changes)
#   build      offline install → typecheck + tsup bundle (workspace packages bundled, npm deps external)
#   prod-deps  frozen-lockfile, offline, production-only install of the @bloody/api closure
#   runtime  distroless Node 22, non-root (65532), no shell / package manager, root-owned
#            read-only application files; works with readOnlyRootFilesystem (writes nothing).
#
# Runtime contract: listens on $PORT (default 4000), health at /api/v1/healthz, readiness at
# /api/v1/readyz, metrics at /api/v1/metrics. Migrations: run the same image with
# `dist/db/migrate.js` as the command (compose `migrate` service / Kubernetes `bloody-migrate` Job).

ARG NODE_VERSION=22.23.3
ARG DEBIAN_RELEASE=trixie
# Distroless tags are rolling; the digest is the pin (Renovate keeps it current).
ARG RUNTIME_IMAGE=gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c

# ─── base ──────────────────────────────────────────────────────────────────────────────────
FROM node:${NODE_VERSION}-${DEBIAN_RELEASE}-slim AS base
ARG PNPM_VERSION=10.28.0
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    CI=true \
    HUSKY=0
RUN corepack enable pnpm && corepack prepare "pnpm@${PNPM_VERSION}" --activate \
 && pnpm config set store-dir /pnpm/store
WORKDIR /repo

# ─── fetch: lockfile-only layer ──────────────────────────────────────────────────────────
FROM base AS fetch
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc package.json ./
RUN --mount=type=cache,id=bloody-pnpm-store,target=/pnpm/store \
    pnpm fetch --frozen-lockfile

# ─── build ───────────────────────────────────────────────────────────────────────────────
FROM fetch AS build
COPY . .
RUN --mount=type=cache,id=bloody-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline
# Workspace packages must be bundled into dist (tsup noExternal); the runtime ships no TS source.
RUN pnpm --filter @bloody/api run build \
 && if grep -rEq "(from|import\()[[:space:]]*['\"]@bloody/" apps/api/dist --include='*.js'; then \
      echo "error: apps/api/dist imports @bloody/* at runtime — bundle workspace packages (tsup noExternal)" >&2; exit 1; \
    fi \
 && test -f apps/api/dist/server.js \
 && mkdir -p apps/api/migrations

# ─── prod-deps: production closure of @bloody/api only, straight from the frozen lockfile ──
# shamefully-hoist exposes the closure at /repo/node_modules so the npm imports of the bundled
# workspace packages (nodemailer, pdfkit, yaml…) resolve from dist/. No devDependencies, no web deps.
# @bloody/* is bundled into dist/, so the workspace links, binaries, docs and tests are dropped.
FROM fetch AS prod-deps
COPY . .
RUN --mount=type=cache,id=bloody-pnpm-store,target=/pnpm/store \
    pnpm install --prod --frozen-lockfile --offline \
      --filter "@bloody/api..." --config.shamefully-hoist=true \
 && rm -rf node_modules/@bloody apps/api/node_modules/@bloody node_modules/.bin apps/api/node_modules/.bin \
 && find node_modules/.pnpm -type f \( -name '*.md' -o -name '*.markdown' -o \( -name '*.ts' ! -name '*.d.ts' \) \) -delete \
 && find node_modules/.pnpm -type d \( -name __tests__ -o -name test -o -name tests -o -name example -o -name examples \) -prune -exec rm -rf {} +

# ─── runtime ─────────────────────────────────────────────────────────────────────────────
FROM ${RUNTIME_IMAGE} AS runtime
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="bloody-api" \
      org.opencontainers.image.description="Bloody Security Operating Platform — control plane API" \
      org.opencontainers.image.vendor="Bloody" \
      org.opencontainers.image.licenses="LicenseRef-Bloody-Proprietary" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

WORKDIR /app/apps/api
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=4000 \
    BLOODY_MIGRATIONS_DIR=/app/apps/api/migrations \
    NODE_OPTIONS="--enable-source-maps"

# Root-owned, world-readable: the non-root runtime user cannot modify the application.
# Layout mirrors the workspace so Node resolution (dist → apps/api/node_modules → /app/node_modules)
# and pnpm's relative symlinks keep working.
COPY --from=prod-deps /repo/node_modules /app/node_modules
COPY --from=prod-deps /repo/apps/api/node_modules /app/apps/api/node_modules
COPY --from=build /repo/apps/api/package.json ./package.json
COPY --from=build /repo/apps/api/dist ./dist
COPY --from=build /repo/apps/api/migrations ./migrations
COPY infra/docker/healthcheck.mjs /app/healthcheck.mjs

USER 65532:65532
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/nodejs/bin/node", "/app/healthcheck.mjs"]
# distroless ENTRYPOINT is ["/nodejs/bin/node"]
CMD ["dist/server.js"]

# syntax=docker/dockerfile:1.10
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Bloody Command Center (apps/web) — static SPA served by unprivileged nginx.
#
#   docker build -f infra/docker/web.Dockerfile -t bloody/web:dev \
#     --build-arg VITE_SUPPORT_URL=https://support.example.com .
#
# Runtime: listens on 8080 as UID 101; secure headers (CSP, frame-ancestors none, nosniff…),
# SPA fallback, immutable caching for hashed assets, no source maps, and `/api/` reverse-proxied
# to $BLOODY_API_UPSTREAM (default http://api:4000) so the session/CSRF cookies stay first-party.
# Read-only root filesystem: mount writable emptyDirs at /tmp and /etc/nginx/conf.d.

ARG NODE_VERSION=22.23.3
ARG DEBIAN_RELEASE=trixie
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.30.5-alpine

# ─── base / fetch (identical to api.Dockerfile so BuildKit shares the cache) ────────────
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

FROM base AS fetch
COPY pnpm-lock.yaml pnpm-workspace.yaml .npmrc package.json ./
RUN --mount=type=cache,id=bloody-pnpm-store,target=/pnpm/store \
    pnpm fetch --frozen-lockfile

# ─── build ───────────────────────────────────────────────────────────────────────────────
FROM fetch AS build
# White-label / commercial links are baked at build time (apps/web/src/app/config.ts);
# unset values hide the link instead of pointing somewhere invented.
ARG VITE_SALES_CONTACT_URL=""
ARG VITE_SUPPORT_URL=""
ARG VITE_DOCS_URL=""
ARG VITE_FEEDBACK_URL=""
ARG VITE_HUB_URL=""
ENV VITE_SALES_CONTACT_URL=${VITE_SALES_CONTACT_URL} \
    VITE_SUPPORT_URL=${VITE_SUPPORT_URL} \
    VITE_DOCS_URL=${VITE_DOCS_URL} \
    VITE_FEEDBACK_URL=${VITE_FEEDBACK_URL} \
    VITE_HUB_URL=${VITE_HUB_URL}
COPY . .
RUN --mount=type=cache,id=bloody-pnpm-store,target=/pnpm/store \
    pnpm install --frozen-lockfile --offline
RUN pnpm --filter @bloody/web run build \
 && test -f apps/web/dist/index.html \
 && if find apps/web/dist -name '*.map' | grep -q .; then echo "error: source maps must not ship" >&2; exit 1; fi

# ─── runtime ─────────────────────────────────────────────────────────────────────────────
FROM ${NGINX_IMAGE} AS runtime
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG VERSION=0.1.0
LABEL org.opencontainers.image.title="bloody-web" \
      org.opencontainers.image.description="Bloody Command Center web application" \
      org.opencontainers.image.vendor="Bloody" \
      org.opencontainers.image.licenses="LicenseRef-Bloody-Proprietary" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}"

# Only BLOODY_* variables are substituted into templates, so nginx's own $variables are untouched.
ENV BLOODY_API_UPSTREAM=http://api:4000 \
    BLOODY_CLIENT_MAX_BODY_SIZE=25m \
    NGINX_ENVSUBST_FILTER=^BLOODY_ \
    NGINX_ENVSUBST_OUTPUT_DIR=/etc/nginx/conf.d

USER root
RUN rm -f /etc/nginx/conf.d/default.conf \
 && mkdir -p /etc/nginx/snippets \
 && chown 101:0 /etc/nginx/conf.d && chmod 0775 /etc/nginx/conf.d
COPY infra/docker/nginx/nginx.conf /etc/nginx/nginx.conf
COPY infra/docker/nginx/security-headers.conf /etc/nginx/snippets/security-headers.conf
COPY infra/docker/nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /repo/apps/web/dist /usr/share/nginx/html
USER 101

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1

# syntax=docker/dockerfile:1.10
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Velociraptor server (AGPL-3.0) — packaging only. Velocidex publishes signed release binaries but
# no official container image, so this image wraps the UNMODIFIED upstream release binary,
# verified against a pinned SHA-256. No Velociraptor source is copied, patched or linked; Bloody
# drives the server only through its API (packages/adapters/src/response/velociraptor.ts).
#
#   docker build -f infra/engines/velociraptor/Dockerfile \
#     --build-arg VELOCIRAPTOR_VERSION=0.76.3 \
#     --build-arg VELOCIRAPTOR_SHA256=<sha256 of velociraptor-v0.76.3-linux-amd64 from the release page> \
#     infra/engines/velociraptor
#
# The checksum is mandatory: the build fails closed rather than trusting an unverified download.
ARG DEBIAN_IMAGE=debian:13.4-slim
FROM ${DEBIAN_IMAGE}

ARG TARGETARCH
ARG VELOCIRAPTOR_VERSION=0.76.3
ARG VELOCIRAPTOR_SHA256=""
ARG VELOCIRAPTOR_URL=""

LABEL org.opencontainers.image.title="bloody-engine-velociraptor" \
      org.opencontainers.image.description="Unmodified Velociraptor release binary packaged for the Bloody engine layer" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VELOCIRAPTOR_VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    if [ -z "${VELOCIRAPTOR_SHA256}" ]; then \
      echo "error: VELOCIRAPTOR_SHA256 is required (copy it from the v${VELOCIRAPTOR_VERSION} release page)" >&2; exit 1; \
    fi; \
    url="${VELOCIRAPTOR_URL:-https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_VERSION}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-${TARGETARCH:-amd64}}"; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /usr/local/bin/velociraptor "$url"; \
    echo "${VELOCIRAPTOR_SHA256}  /usr/local/bin/velociraptor" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/velociraptor; \
    apt-get purge -y curl && apt-get autoremove -y

RUN useradd --system --uid 10010 --user-group --home-dir /var/lib/velociraptor --shell /usr/sbin/nologin velociraptor \
 && install -d -o velociraptor -g velociraptor -m 0750 /var/lib/velociraptor
COPY --chmod=0755 entrypoint.sh /usr/local/bin/bloody-velociraptor-entrypoint

USER velociraptor
WORKDIR /var/lib/velociraptor
EXPOSE 8000 8001 8889
ENTRYPOINT ["/usr/local/bin/bloody-velociraptor-entrypoint"]

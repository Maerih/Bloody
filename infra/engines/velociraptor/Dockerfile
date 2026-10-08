# syntax=docker/dockerfile:1.10
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Velociraptor server (AGPL-3.0) — packaging only. Velocidex publishes signed release binaries but
# no official container image, so this image wraps the UNMODIFIED upstream release binary,
# verified against a pinned SHA-256. No Velociraptor source is copied, patched or linked; Bloody
# drives the server only through its API (packages/adapters/src/response/velociraptor.ts).
#
#   docker build -t bloody/engine-velociraptor:0.77.2 infra/engines/velociraptor
#
# Upgrading: set VELOCIRAPTOR_VERSION and BOTH per-architecture checksums of the new release
# binaries (velociraptor-v<version>-linux-{amd64,arm64}); Renovate cannot do this unattended.
# The checksum is mandatory: the build fails closed rather than trusting an unverified download.
ARG DEBIAN_IMAGE=debian:13.4-slim
FROM ${DEBIAN_IMAGE}

ARG TARGETARCH
ARG VELOCIRAPTOR_VERSION=0.77.2
# SHA-256 of the upstream v0.77.2 release binaries (recorded 2026-10-07 from the GitHub release).
ARG VELOCIRAPTOR_SHA256_AMD64=6c4c23c466d892788ff56ddcd3a31f844e4c0d797ade454c5e2625eb9e427077
ARG VELOCIRAPTOR_SHA256_ARM64=54d36c23f374a572a4a60106d896e0e39bc6fcafd0d6150cf56aec6c49454ea0
ARG VELOCIRAPTOR_URL=""

LABEL org.opencontainers.image.title="bloody-engine-velociraptor" \
      org.opencontainers.image.description="Unmodified Velociraptor release binary packaged for the Bloody engine layer" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VELOCIRAPTOR_VERSION}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) sha="${VELOCIRAPTOR_SHA256_AMD64}" ;; \
      arm64) sha="${VELOCIRAPTOR_SHA256_ARM64}" ;; \
      *) echo "error: unsupported architecture $arch" >&2; exit 1 ;; \
    esac; \
    if ! printf '%s' "$sha" | grep -Eq '^[0-9a-f]{64}$'; then \
      echo "error: a SHA-256 for velociraptor v${VELOCIRAPTOR_VERSION} linux-$arch is required" >&2; exit 1; \
    fi; \
    url="${VELOCIRAPTOR_URL:-https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_VERSION}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-$arch}"; \
    curl -fsSL --proto '=https' --tlsv1.2 -o /usr/local/bin/velociraptor "$url"; \
    echo "$sha  /usr/local/bin/velociraptor" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/velociraptor; \
    apt-get purge -y curl && apt-get autoremove -y

RUN useradd --system --uid 10010 --user-group --home-dir /var/lib/velociraptor --shell /usr/sbin/nologin velociraptor \
 && install -d -o velociraptor -g velociraptor -m 0750 /var/lib/velociraptor
COPY --chmod=0755 entrypoint.sh /usr/local/bin/bloody-velociraptor-entrypoint

USER velociraptor
WORKDIR /var/lib/velociraptor
EXPOSE 8000 8001 8889
ENTRYPOINT ["/usr/local/bin/bloody-velociraptor-entrypoint"]

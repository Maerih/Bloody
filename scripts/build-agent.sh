#!/usr/bin/env bash
# Builds the native SCIAT Agent for Windows and Linux (amd64 + arm64) into dist/agent/, with
# SHA256SUMS. Static binaries (no cgo): they run on any supported Windows 10/11 / Server 2016+
# and on any Linux with systemd. Signing is a separate step (scripts/sign-agent.sh).
#
#   scripts/build-agent.sh [version]      # default: version from apps/agent/VERSION
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${1:-$(cat apps/agent/VERSION)}"
OUT="dist/agent/$VERSION"
rm -rf "$OUT" && mkdir -p "$OUT"
LDFLAGS="-s -w -X main.version=$VERSION"
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}" arch="${target#*/}"
  name="sciat-agent-$os-$arch"; [ "$os" = windows ] && name="$name.exe"
  ( cd apps/agent && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "../../$OUT/$name" ./cmd/sciat-agent )
  echo "built $OUT/$name ($(du -h "$OUT/$name" | cut -f1))"
done
( cd "$OUT" && sha256sum sciat-agent-* > SHA256SUMS )
echo "checksums: $OUT/SHA256SUMS"

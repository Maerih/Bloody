#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Generate Software Bills of Materials for Bloody.
#
#   scripts/sbom.sh [--out DIR] [--image REF]... [--no-source]
#
# Produces, in DIR (default: ./sbom):
#   bloody-source.cdx.json / .spdx.json  repository SBOM (pnpm lockfile + installed node_modules) via Syft
#   bloody-npm.cdx.json                  dependency-graph SBOM from scripts/license-check.mjs (always;
#                                        works offline, includes prod/dev scope + licence verdicts)
#   licenses.json                        licence gate report (same run)
#   <image>.cdx.json / .spdx.json        one per --image (container SBOMs incl. OS packages) via Syft
#
# Syft resolution order: local `syft` binary → `docker run anchore/syft` → (images only) fail.
# The repository SBOM falls back to the license-check graph when Syft is unavailable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/sbom"
SYFT_IMAGE="${SYFT_IMAGE:-anchore/syft:v1.54.1}"
IMAGES=()
SOURCE=1

usage() { sed -n '4,17p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"; shift 2 ;;
    --image) IMAGES+=("$2"); shift 2 ;;
    --no-source) SOURCE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "sbom.sh: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "${OUT}"

syft_cmd() {
  if command -v syft >/dev/null 2>&1; then
    syft "$@"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    # Mount the repository read-only; Docker socket only for image scans.
    docker run --rm \
      -v "${ROOT}:/src:ro" -v "${OUT}:/out" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -e SYFT_CHECK_FOR_APP_UPDATE=false \
      "${SYFT_IMAGE}" "$@"
  else
    return 127
  fi
}

# Map host paths to container paths when running Syft in Docker.
in_syft() {
  if command -v syft >/dev/null 2>&1; then printf '%s' "$1"; return; fi
  case "$1" in
    "${OUT}"*) printf '/out%s' "${1#"${OUT}"}" ;;
    "${ROOT}"*) printf '/src%s' "${1#"${ROOT}"}" ;;
    *) printf '%s' "$1" ;;
  esac
}

status=0

echo "▶ dependency graph SBOM + licence report (scripts/license-check.mjs)"
if ! node "${ROOT}/scripts/license-check.mjs" --quiet \
  --cyclonedx "${OUT}/bloody-npm.cdx.json" --json "${OUT}/licenses.json"; then
  echo "✖ licence gate failed — see ${OUT}/licenses.json" >&2
  status=1
fi

if [[ "${SOURCE}" == 1 ]]; then
  echo "▶ repository SBOM (Syft)"
  src="$(in_syft "${ROOT}")"
  out_dir="$(in_syft "${OUT}")"
  if syft_cmd scan "dir:${src}" \
      --exclude './**/dist/**' --exclude './**/.git/**' --exclude './sbom/**' \
      --source-name bloody --source-version "$(node -p "require('${ROOT}/package.json').version ?? '0.0.0'")" \
      -o "cyclonedx-json=${out_dir}/bloody-source.cdx.json" \
      -o "spdx-json=${out_dir}/bloody-source.spdx.json"; then
    :
  else
    rc=$?
    if [[ $rc == 127 ]]; then
      echo "ℹ Syft not available (no binary, no Docker daemon): bloody-npm.cdx.json is the repository SBOM."
    else
      echo "✖ Syft failed (exit ${rc})" >&2
      status=1
    fi
  fi
fi

for image in "${IMAGES[@]}"; do
  name="$(printf '%s' "${image}" | tr '/:@' '___')"
  echo "▶ image SBOM ${image}"
  out_dir="$(in_syft "${OUT}")"
  if ! syft_cmd scan "${image}" \
      -o "cyclonedx-json=${out_dir}/${name}.cdx.json" \
      -o "spdx-json=${out_dir}/${name}.spdx.json"; then
    echo "✖ could not produce an SBOM for ${image} (Syft unavailable or image not found)" >&2
    status=1
  fi
done

echo "SBOM artefacts in ${OUT}:"
ls -1 "${OUT}"
exit "${status}"

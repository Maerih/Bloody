#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Nuclei (MIT) scan runner for the ASM module. Scans ONLY the authorised, in-scope targets listed
# in $NUCLEI_TARGETS (one per line, maintained by Bloody's ASM scope management — never a guess),
# rate-limited, and writes JSONL findings that the collector ships to the nuclei adapter.
# An empty or missing targets file means "nothing is authorised": the runner idles.
set -eu

TARGETS="${NUCLEI_TARGETS:-/config/targets.txt}"
OUT_DIR="${NUCLEI_OUTPUT_DIR:-/logs/nuclei}"
INTERVAL="${NUCLEI_INTERVAL_SECONDS:-86400}"
RATE="${NUCLEI_RATE_LIMIT:-50}"
CONCURRENCY="${NUCLEI_CONCURRENCY:-10}"
SEVERITY="${NUCLEI_SEVERITY:-low,medium,high,critical}"
RETENTION_DAYS="${NUCLEI_RESULT_RETENTION_DAYS:-14}"

mkdir -p "$OUT_DIR"
while :; do
  if [ -s "$TARGETS" ] && grep -qv '^[[:space:]]*\(#\|$\)' "$TARGETS"; then
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    echo "nuclei-runner: scan $ts ($(grep -cv '^[[:space:]]*\(#\|$\)' "$TARGETS") targets)"
    nuclei -update-templates -silent || echo "nuclei-runner: template update failed; using cached templates" >&2
    # Exclude intrusive template classes by default (DoS, fuzzing, brute force).
    nuclei -list "$TARGETS" -jsonl -o "$OUT_DIR/nuclei-$ts.jsonl.partial" \
      -rate-limit "$RATE" -concurrency "$CONCURRENCY" -severity "$SEVERITY" \
      -exclude-tags dos,fuzz,intrusive,bruteforce -disable-update-check -no-color -silent \
      -omit-raw || echo "nuclei-runner: scan exited non-zero" >&2
    # Atomic hand-off to the collector (it only tails *.jsonl).
    [ -f "$OUT_DIR/nuclei-$ts.jsonl.partial" ] && mv "$OUT_DIR/nuclei-$ts.jsonl.partial" "$OUT_DIR/nuclei-$ts.jsonl"
    find "$OUT_DIR" -name 'nuclei-*.jsonl' -mtime "+$RETENTION_DAYS" -delete
  else
    echo "nuclei-runner: no authorised targets in $TARGETS — idle"
  fi
  sleep "$INTERVAL"
done

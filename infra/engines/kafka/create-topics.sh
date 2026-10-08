#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Bloody-Proprietary
# Copyright (c) 2026 Bloody. All rights reserved.
#
# Idempotently create the Bloody data-fabric topics (broker auto-create is disabled so a typo
# in a collector config can never silently create a topic).
#   bloody.raw.<adapter>     raw vendor records from collectors (Vector / OTel), one per adapter
#   bloody.events.ingested.v1  ingested Bloody Canonical Event batches, keyed by tenant — the topic
#                              name of the API's EventBus (apps/api/src/pipeline/event-bus.ts TOPICS)
#   bloody.dlq               records that failed normalisation (kept for replay; never dropped)
set -eu

BOOTSTRAP="${KAFKA_BOOTSTRAP:-kafka:9092}"
PARTITIONS="${BLOODY_TOPIC_PARTITIONS:-6}"
REPLICATION="${BLOODY_TOPIC_REPLICATION:-1}"
RAW_RETENTION_MS="${BLOODY_RAW_RETENTION_MS:-259200000}"   # 3 days: raw is re-derivable from engines
DLQ_RETENTION_MS="${BLOODY_DLQ_RETENTION_MS:-1209600000}"  # 14 days: time to fix an adapter and replay
ADAPTERS="${BLOODY_RAW_ADAPTERS:-wazuh zeek suricata osquery falco velociraptor opencanary nuclei trivy greenbone syslog cef keycloak aws_cloudtrail copilot}"
TOPICS=/opt/kafka/bin/kafka-topics.sh

i=0
until "$TOPICS" --bootstrap-server "$BOOTSTRAP" --list >/dev/null 2>&1; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && { echo "kafka-init: broker $BOOTSTRAP not reachable" >&2; exit 1; }
  sleep 2
done

create() {
  "$TOPICS" --bootstrap-server "$BOOTSTRAP" --create --if-not-exists --topic "$1" \
    --partitions "$PARTITIONS" --replication-factor "$REPLICATION" \
    --config compression.type=zstd --config "retention.ms=$2" --config max.message.bytes=4194304 \
    --config min.insync.replicas="$([ "$REPLICATION" -ge 3 ] && echo 2 || echo 1)"
}

for a in $ADAPTERS; do create "bloody.raw.$a" "$RAW_RETENTION_MS"; done
create bloody.events.ingested.v1 "$RAW_RETENTION_MS"
create bloody.dlq "$DLQ_RETENTION_MS"
echo "kafka-init: topics ready"
"$TOPICS" --bootstrap-server "$BOOTSTRAP" --list | grep '^bloody\.'

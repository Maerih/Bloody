import type { DetectionRuleInput } from "../detection/types.js";

/** Bloody built-in network (NDR) and threat-intelligence detections. Bloody-authored. */

const dnsQuery = (query: string, offsetSeconds: number) => ({
  category: "dns",
  source: { kind: "network", product: "zeek" },
  eventType: "dns_query",
  offsetSeconds,
  asset: { hostname: "ws-test-07" },
  network: { srcIp: "10.20.0.17", dstIp: "10.20.0.2", dnsQuery: query, protocol: "udp", dstPort: 53 },
});

export const DNS_BEACONING: DetectionRuleInput = {
  kind: "threshold",
  id: "bloody-ndr-dns-beaconing",
  name: "Periodic DNS beaconing",
  description: "One host resolves the same domain at least 12 times within an hour at near-constant intervals (coefficient of variation ≤ 0.25) — the timing signature of command-and-control check-ins.",
  version: 1,
  severity: "medium",
  confidence: 0.6,
  attack: [
    { id: "T1071.004", name: "DNS", tactic: "command-and-control" },
    { id: "T1568", name: "Dynamic Resolution", tactic: "command-and-control" },
  ],
  tags: ["ndr", "dns", "c2"],
  author: "Bloody Detection Engineering",
  falsePositives: ["Update / telemetry agents polling on fixed timers (suppress the domain or process)."],
  filter: {
    detection: {
      dns: { "network.dnsQuery|exists": true },
      filter_local: { "network.dnsQuery|endswith": [".in-addr.arpa", ".ip6.arpa", ".local", ".localdomain"] },
    },
    condition: "dns and not filter_local",
  },
  groupBy: ["asset.hostname", "network.dnsQuery"],
  threshold: 12,
  windowSeconds: 3600,
  regularity: { maxCoefficientOfVariation: 0.25, minIntervalSeconds: 10 },
  cooldownSeconds: 3600,
  tests: [
    { name: "query every 5 minutes", expect: "match", expectedMatches: 1, events: Array.from({ length: 12 }, (_, i) => dnsQuery("cdn-sync.badcdn.example", i * 300)) },
    {
      name: "bursty human browsing",
      expect: "no_match",
      events: [0, 5, 400, 410, 1500, 1520, 1530, 2400, 2405, 3000, 3100, 3500].map((t) => dnsQuery("news.example", t)),
    },
    { name: "reverse lookups are filtered", expect: "no_match", events: Array.from({ length: 12 }, (_, i) => dnsQuery("2.0.20.10.in-addr.arpa", i * 300)) },
  ],
};

export const SURICATA_HIGH_SEVERITY: DetectionRuleInput = {
  kind: "sigma",
  id: "bloody-ndr-suricata-high-severity",
  name: "High-severity network IDS alert",
  description: "Passes through high and critical Suricata alerts as Bloody detections (severity preserved, 5-minute per-host cooldown against alert storms).",
  version: 1,
  severity: "high",
  severityMode: "event",
  confidence: 0.6,
  attack: [],
  tags: ["ndr", "ids", "suricata"],
  author: "Bloody Detection Engineering",
  cooldownSeconds: 300,
  sigma: String.raw`
title: High-severity network IDS alert
id: 7819f141-92d8-4c7b-b857-a64d3c7a2022
status: stable
author: Bloody Detection Engineering
logsource:
  category: ids
detection:
  ids_engine:
    source.product: 'suricata'
  high_severity:
    severity:
      - 'high'
      - 'critical'
  condition: ids_engine and high_severity
level: high
`,
  tests: [
    {
      name: "critical Suricata alert",
      expect: "match",
      events: [
        {
          category: "detection",
          source: { kind: "network", product: "suricata" },
          eventType: "ids_alert",
          severity: "critical",
          asset: { hostname: "web-01" },
          network: { srcIp: "203.0.113.200", dstIp: "10.0.0.15", dstPort: 443, protocol: "tcp" },
          detection: { ruleId: "2034567", ruleName: "Exploit attempt against web application", engine: "suricata" },
        },
      ],
    },
    {
      name: "medium Suricata alert",
      expect: "no_match",
      events: [{ category: "detection", source: { kind: "network", product: "suricata" }, eventType: "ids_alert", severity: "medium", detection: { ruleName: "Policy: outdated TLS" } }],
    },
    {
      name: "alert storm on one host fires once",
      expect: "match",
      expectedMatches: 1,
      events: Array.from({ length: 5 }, (_, i) => ({
        offsetSeconds: i * 10,
        category: "detection",
        source: { kind: "network", product: "suricata" },
        eventType: "ids_alert",
        severity: "high",
        asset: { hostname: "web-01" },
        detection: { ruleName: "Scanner probing" },
      })),
    },
  ],
};

export const THREAT_INTEL_MATCH: DetectionRuleInput = {
  kind: "ioc",
  id: "bloody-cti-indicator-match",
  name: "Threat-intelligence indicator observed",
  description: "An observable in telemetry (destination IP, domain, URL, file hash, JA3 …) matches an active indicator of the tenant's threat-intelligence feeds (confidence ≥ 60).",
  version: 1,
  severity: "medium",
  severityMode: "max",
  confidence: 0.9,
  attack: [],
  tags: ["cti", "ioc"],
  author: "Bloody Detection Engineering",
  minConfidence: 60,
  tests: [
    {
      name: "connection to a known C2 address",
      expect: "match",
      indicators: [{ type: "ip", value: "198.51.100.23", confidence: 90, severity: "critical", source: "misp", threatActor: "TA-Example" }],
      events: [{ category: "network", source: { kind: "network", product: "zeek" }, eventType: "conn", asset: { hostname: "ws-test-03" }, network: { srcIp: "10.1.1.3", dstIp: "198.51.100.23", dstPort: 443 } }],
    },
    {
      name: "subdomain of a malicious domain",
      expect: "match",
      indicators: [{ type: "domain", value: "evil.example", confidence: 80, severity: "high", source: "opencti" }],
      events: [{ category: "dns", source: { kind: "network", product: "zeek" }, eventType: "dns_query", network: { dnsQuery: "beacon.cdn.evil.example" } }],
    },
    {
      name: "low-confidence indicator is ignored",
      expect: "no_match",
      indicators: [{ type: "ip", value: "198.51.100.24", confidence: 30, severity: "low", source: "community" }],
      events: [{ category: "network", eventType: "conn", network: { dstIp: "198.51.100.24" } }],
    },
    {
      name: "clean traffic",
      expect: "no_match",
      indicators: [{ type: "ip", value: "198.51.100.23", confidence: 90, severity: "critical", source: "misp" }],
      events: [{ category: "network", eventType: "conn", network: { dstIp: "192.0.2.80" } }],
    },
  ],
};

export const NETWORK_RULES: DetectionRuleInput[] = [DNS_BEACONING, SURICATA_HIGH_SEVERITY, THREAT_INTEL_MATCH];

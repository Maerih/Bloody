import { createDefaultRegistry } from "../registry.js";
import { ctx, fixtureText } from "./fixtures.js";
const reg = createDefaultRegistry();
const runs: Array<[string, string]> = [
  ["wazuh", "wazuh/alerts.jsonl"], ["wazuh", "wazuh/windows.jsonl"], ["zeek", "zeek/mixed.jsonl"], ["zeek", "zeek/conn.log"],
  ["suricata", "suricata/eve.json"], ["falco", "falco/alerts.jsonl"], ["osquery", "osquery/results.jsonl"],
  ["velociraptor", "velociraptor/pslist-collection.json"], ["velociraptor", "velociraptor/hunt-export.jsonl"], ["opencanary", "opencanary/events.jsonl"],
  ["trivy", "trivy/image-report.json"], ["trivy", "trivy/k8s-report.json"], ["nuclei", "nuclei/findings.jsonl"], ["greenbone", "greenbone/report.xml"],
  ["greenbone", "greenbone/results.json"], ["syslog", "syslog/messages.log"], ["cef", "syslog/messages.log"], ["keycloak", "keycloak/events.json"],
  ["keycloak", "keycloak/admin-events.json"], ["aws_cloudtrail", "cloudtrail/records.json"], ["aws_cloudtrail", "cloudtrail/eventbridge.json"],
];
for (const [k, f] of runs) {
  const r = reg.normalize(k, fixtureText(f), ctx());
  console.log(`\n=== ${k} ${f}: records=${r.records} events=${r.events.length} rejected=${JSON.stringify(r.rejected)} skipped=${JSON.stringify(r.skipped)}`);
  for (const e of r.events) console.log(`  ${e.timestamp} ${e.category} ${e.eventType} sev=${e.severity} out=${e.outcome ?? ""} act=${e.action ?? ""} host=${e.asset?.hostname ?? ""} attack=${e.attack.map((a) => a.id + ":" + (a.name ?? "") + ":" + (a.tactic ?? "")).join("|")} ind=${e.indicators.map((i) => i.type + "=" + i.value.slice(0, 40)).join(",")} msg=${(e.message ?? "").slice(0, 70)}`);
}

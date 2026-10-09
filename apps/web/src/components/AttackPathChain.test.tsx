import type { AttackPath, GraphEdge, GraphNode, RiskFactor } from "@bloody/contracts";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { attackPathFactorRows, pathChain, rankRemediations } from "../lib/attackPaths";
import { ORG_A } from "../test/fixtures";
import { mockApi, renderApp, renderWithSession } from "../test/utils";
import { makeMe } from "../test/fixtures";
import { AttackPathChain } from "./AttackPathChain";

const node = (id: string, kind: GraphNode["kind"], label: string, props: Record<string, unknown> = {}): GraphNode => ({ id, kind, key: label, label, organizationId: ORG_A, props });
const edge = (id: string, kind: GraphEdge["kind"], from: string, to: string): GraphEdge => ({ id, kind, from, to, props: {} });
const factor = (key: string, label: string, value: number, contribution: number, explanation: string): RiskFactor => ({ key, label, value, weight: contribution < 0 ? -1 : 1, contribution, explanation });

const INTERNET = node("n-internet", "internet", "Internet");
const WEB = node("n-web", "server", "web01.acme.test", { assetId: "a-web" });
const SVC = node("n-svc", "identity", "svc_backup", { identityId: "i-svc", privileged: true });
const DC = node("n-dc", "server", "dc01.acme.test", { assetId: "a-dc", criticality: "crown_jewel" });

export function makePath(overrides: Partial<AttackPath> = {}): AttackPath {
  return {
    id: "path-1",
    entry: INTERNET,
    target: DC,
    nodes: [INTERNET, WEB, SVC, DC],
    edges: [edge("e1", "exposes", "n-internet", "n-web"), edge("e2", "stores_credential_for", "n-web", "n-svc"), edge("e3", "admin_of", "n-svc", "n-dc")],
    risk: {
      score: 92,
      severity: "critical",
      likelihood: 0.8,
      impact: 0.95,
      summary: "Internet-exposed web server stores credentials of a domain admin service account.",
      modelVersion: "attack-path/1.2",
      factors: [
        factor("exploitability", "Exploitability", 0.9, 22, "CVE-2024-3400 is remotely exploitable without authentication."),
        factor("exposure", "Exposure", 1, 15, "web01 is reachable from the Internet on 443/tcp."),
        factor("asset_criticality", "Asset criticality", 1, 18, "dc01 is a crown jewel (domain controller)."),
        factor("identity_privilege", "Identity privilege", 0.9, 12, "svc_backup is a Domain Admin."),
        factor("known_exploitation", "Known exploitation", 1, 10, "The CVE is in CISA KEV."),
        factor("control_edr", "EDR coverage", 0.5, -6, "dc01 runs a protected EDR agent."),
      ],
    },
    remediations: [{ nodeId: "n-svc", action: "Remove the cached svc_backup credential from web01", pathsBroken: 3 }],
    ...overrides,
  };
}

describe("pathChain", () => {
  it("keeps engine-ordered paths entry → target with the edge used for each hop", () => {
    const steps = pathChain(makePath());
    expect(steps.map((s) => s.node.label)).toEqual(["Internet", "web01.acme.test", "svc_backup", "dc01.acme.test"]);
    expect(steps.map((s) => s.via?.kind ?? null)).toEqual([null, "exposes", "stores_credential_for", "admin_of"]);
  });

  it("rebuilds the order from edges when nodes arrive unordered, marking reversed edges", () => {
    const steps = pathChain(makePath({ nodes: [DC, SVC, INTERNET, WEB], edges: [edge("e1", "exposes", "n-internet", "n-web"), edge("e2", "has_access_to", "n-svc", "n-web"), edge("e3", "admin_of", "n-svc", "n-dc")] }));
    expect(steps.map((s) => s.node.id)).toEqual(["n-internet", "n-web", "n-svc", "n-dc"]);
    expect(steps[2]!.reversed).toBe(true);
  });
});

describe("attackPathFactorRows", () => {
  it("lists every canonical factor, marks unobserved ones and nets compensating controls", () => {
    const rows = attackPathFactorRows(makePath().risk);
    expect(rows.slice(0, 10).map((r) => r.label)).toEqual([
      "Exploitability",
      "Exposure",
      "Privilege escalation",
      "Asset criticality",
      "Identity privilege",
      "Known exploitation",
      "Threat intelligence",
      "Lateral movement",
      "Blast radius",
      "Compensating controls",
    ]);
    expect(rows.find((r) => r.key === "lateral_movement")).toMatchObject({ present: false, contribution: 0, explanation: "Not observed on this path." });
    expect(rows.find((r) => r.key === "compensating_controls")).toMatchObject({ present: true, contribution: -6 });
    expect(rows.find((r) => r.key === "identity_privilege")!.contribution).toBe(12);
    expect(rows.find((r) => r.key === "privilege")!.present).toBe(false);
  });
});

describe("rankRemediations", () => {
  it("prefers the API's greedy ranking and keeps the paths each fix breaks", () => {
    const p1 = makePath();
    const p2 = makePath({ id: "path-2" });
    const merged = rankRemediations([p1, p2]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ action: "Remove the cached svc_backup credential from web01", pathsBroken: 3, subject: "svc_backup", pathIds: ["path-1", "path-2"] });
    const provided = rankRemediations([p1], [
      { action: "Patch CVE-2024-3400 on web01", nodeId: "n-web", pathsBroken: 5, rank: 2 },
      { action: "Remove the cached svc_backup credential from web01", nodeId: "n-svc", pathsBroken: 7, rank: 1 },
    ]);
    expect(provided.map((r) => r.action)).toEqual(["Remove the cached svc_backup credential from web01", "Patch CVE-2024-3400 on web01"]);
  });
});

describe("AttackPathChain", () => {
  it("renders the horizontal chain Internet → … → crown jewel with relationships and pivots", () => {
    renderWithSession(<AttackPathChain path={makePath()} />);
    const chain = screen.getByTestId("attack-path-chain");
    expect(chain).toHaveAccessibleName("Attack path from Internet to dc01.acme.test");
    const nodes = within(chain).getAllByTestId("attack-path-node");
    expect(nodes.map((n) => n.textContent)).toEqual([expect.stringContaining("Internet"), expect.stringContaining("web01.acme.test"), expect.stringContaining("svc_backup"), expect.stringContaining("dc01.acme.test")]);
    expect(within(chain).getAllByTestId("attack-path-edge").map((e) => e.textContent)).toEqual(["exposes", "stores credential for", "admin of"]);
    expect(within(chain).getByLabelText("Crown jewel")).toBeInTheDocument();
    // Asset nodes open the asset; identity nodes the identity; others pivot into the graph.
    expect(within(chain).getByRole("link", { name: /web01\.acme\.test/ })).toHaveAttribute("href", "/assets/a-web");
    expect(within(chain).getByRole("link", { name: /svc_backup/ })).toHaveAttribute("href", "/ispm/identities?id=i-svc");
    expect(within(chain).getByRole("link", { name: /Internet/ })).toHaveAttribute("href", "/graph?node=n-internet");
  });
});

describe("Attack Paths page", () => {
  it("lists paths with explained risk and remediation priorities (fix this → breaks N paths)", async () => {
    const path = makePath();
    mockApi({
      "/auth/me": makeMe(),
      "/attack-paths": {
        paths: [path],
        remediations: [{ action: "Remove the cached svc_backup credential from web01", nodeId: "n-svc", pathsBroken: 1, rank: 1, effort: "low" }],
        summary: { totalPaths: 1, targetsAtRisk: 1, entryPoints: 1, maxRiskScore: 92, fixesToBreakAll: 1, shortestPathLength: 3 },
      },
      "/escalations": { items: [], nextCursor: null },
      "/response/actions": { items: [], nextCursor: null },
      "/incidents": { items: [], nextCursor: null },
    });
    renderApp(`/attack-paths?org=${ORG_A}`);
    const card = await screen.findByTestId("attack-path-card", {}, { timeout: 8000 });
    expect(within(card).getByText("Internet → dc01.acme.test")).toBeInTheDocument();
    expect(within(card).getByText("Crown jewel")).toBeInTheDocument();
    const priorities = screen.getAllByTestId("remediation-priorities")[0]!;
    expect(within(priorities).getByText("Fix this → breaks 1 path")).toBeInTheDocument();
    // First path is expanded by default: factor bars with every model factor.
    const factors = await within(card).findByTestId("attack-path-factors");
    expect(within(factors).getByRole("meter", { name: "Likelihood" })).toHaveAttribute("aria-valuenow", "80");
    expect(within(factors).getByText("Known exploitation")).toBeInTheDocument();
    expect(within(factors).getByText("Compensating controls")).toBeInTheDocument();
    fireEvent.click(within(card).getByRole("button", { name: "Hide explanation" }));
    await waitFor(() => expect(within(card).queryByTestId("attack-path-factors")).not.toBeInTheDocument());
  });
});

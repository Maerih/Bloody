import { describe, expect, it } from "vitest";
import { toSubgraph } from "./normalize";

const node = (id: string, kind = "endpoint") => ({ id, kind, label: id, props: {} });

describe("toSubgraph", () => {
  it("keeps the centre node of a neighbors response (root) so its edges survive", () => {
    const g = toSubgraph({
      root: node("ws-01"),
      nodes: [node("powershell", "process"), node("jdoe", "user")],
      edges: [
        { id: "e1", kind: "runs_on", from: "powershell", to: "ws-01", props: {} },
        { id: "e2", kind: "logged_into", from: "jdoe", to: "ws-01", props: {} },
        { id: "e3", kind: "x", from: "jdoe", to: "missing", props: {} },
      ],
      truncated: false,
      hidden: 0,
    });
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["jdoe", "powershell", "ws-01"]);
    expect(g.edges.map((e) => e.id).sort()).toEqual(["e1", "e2"]);
  });

  it("still accepts the older `node` field", () => {
    const g = toSubgraph({ node: node("a"), nodes: [node("b")], edges: [{ id: "e", kind: "k", from: "a", to: "b", props: {} }] });
    expect(g.edges).toHaveLength(1);
  });
});

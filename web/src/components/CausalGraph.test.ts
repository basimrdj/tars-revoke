import { describe, expect, it } from "vitest";

import type { CausalEdgeSnapshot, CausalNodeSnapshot } from "../types";
import { focusCausalGraph } from "./CausalGraph";

function node(id: string, kind: string, status: string): CausalNodeSnapshot {
  return { id, kind, status, label: id, depth: 0, lane: 0 };
}

function edge(
  id: string,
  source: string,
  target: string,
  affected: boolean
): CausalEdgeSnapshot {
  return { id, source, target, affected, kind: "requires", strength: "hard" };
}

describe("focusCausalGraph", () => {
  it("collapses action internals into the selective closure and Agent B branch", () => {
    const nodes = [
      node("premise-v1", "premise", "INVALIDATED"),
      node("warrant-agent-a-v1", "warrant", "REVOKED"),
      node("action-agent-a-db-v1", "action", "ROLLED_BACK"),
      node("effect-agent-a-db-v1", "effect", "ROLLED_BACK"),
      node("action-agent-a-model-v1", "action", "ROLLED_BACK"),
      node("effect-agent-a-model-v1", "effect", "ROLLED_BACK"),
      node("action-agent-a-push-v1", "action", "QUARANTINED"),
      node("effect-agent-a-push-v1", "effect", "QUARANTINED"),
      node("premise-observability", "premise", "ACTIVE"),
      node("warrant-agent-b-observability", "warrant", "AUTHORIZED"),
      node("action-agent-b-push", "action", "EXECUTED"),
      node("effect-agent-b-push", "effect", "EXECUTED"),
      node("warrant-agent-a-v2-repair", "warrant", "AUTHORIZED"),
      node("effect-agent-a-db-v2", "effect", "EXECUTED")
    ];
    const edges = [
      edge("a-pw", "premise-v1", "warrant-agent-a-v1", true),
      edge("a-wd", "warrant-agent-a-v1", "action-agent-a-db-v1", true),
      edge("a-de", "action-agent-a-db-v1", "effect-agent-a-db-v1", true),
      edge("a-wm", "warrant-agent-a-v1", "action-agent-a-model-v1", true),
      edge("a-me", "action-agent-a-model-v1", "effect-agent-a-model-v1", true),
      edge("a-wp", "warrant-agent-a-v1", "action-agent-a-push-v1", true),
      edge("a-pe", "action-agent-a-push-v1", "effect-agent-a-push-v1", true),
      edge("b-pw", "premise-observability", "warrant-agent-b-observability", false),
      edge("b-wa", "warrant-agent-b-observability", "action-agent-b-push", false),
      edge("b-ae", "action-agent-b-push", "effect-agent-b-push", false),
      edge("repair", "warrant-agent-a-v2-repair", "effect-agent-a-db-v2", false)
    ];

    const focused = focusCausalGraph(nodes, edges);

    expect(focused.nodes).toHaveLength(8);
    expect(focused.nodes.every((item) => item.kind !== "action")).toBe(true);
    expect(focused.nodes.some((item) => item.id === "effect-agent-a-db-v2")).toBe(false);
    expect(focused.edges).toHaveLength(6);
    expect(focused.edges.filter((item) => item.affected)).toHaveLength(4);
    expect(focused.edges.some((item) => item.source === "warrant-agent-b-observability" && item.target === "effect-agent-b-push")).toBe(true);
  });
});

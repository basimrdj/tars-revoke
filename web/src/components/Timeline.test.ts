import { describe, expect, it } from "vitest";

import type { EventSnapshot } from "../types";
import { displayCommand } from "./ExperimentPanel";
import { timelineMilestones } from "./Timeline";

function event(
  sequence: number,
  type: string,
  status?: string
): EventSnapshot {
  return {
    sequence,
    type,
    status,
    occurred_at: `2026-07-14T00:00:${String(sequence).padStart(2, "0")}Z`,
    summary: `${type} internal identifier that must never become a timeline label`
  };
}

describe("timelineMilestones", () => {
  it("reduces journal internals to the ten operator milestones", () => {
    const milestones = timelineMilestones([
      event(1, "run.created", "RUNNING"),
      event(2, "graph.edge_created"),
      event(3, "evidence.created", "VERIFIED"),
      event(4, "evidence.created", "VERIFIED"),
      event(5, "revocation_case.transitioned", "FROZEN"),
      event(6, "effect.transitioned", "ROLLED_BACK"),
      event(7, "effect.transitioned", "ROLLED_BACK"),
      event(8, "effect.transitioned", "QUARANTINED"),
      event(9, "experiment_run.transitioned", "PASSED"),
      event(10, "revocation_case.transitioned", "REPAIRING"),
      event(11, "test_run.transitioned", "PASSED"),
      event(12, "test_run.transitioned", "PASSED"),
      event(13, "revocation_case.transitioned", "RESUMED"),
      event(14, "receipt.transitioned", "VERIFIED")
    ]);

    expect(milestones.map((item) => item.label)).toEqual([
      "Prepared",
      "Evidence changed",
      "Scope frozen",
      "2 effects rolled back",
      "Push quarantined",
      "Decisive test passed",
      "Repair started",
      "Verification passed",
      "Branch resumed",
      "Receipt verified"
    ]);
    expect(milestones.map((item) => item.event.sequence)).toEqual([
      1, 4, 5, 7, 8, 9, 10, 12, 13, 14
    ]);
  });
});

describe("displayCommand", () => {
  it("does not expose operator home paths in the rendered command", () => {
    expect(
      displayCommand([
        "/Users/example/.pyenv/versions/3.10.11/bin/python3.10",
        "/Users/example/project/scripts/contract_probe.py",
        "--fixture",
        "examples/customer-v1.json"
      ])
    ).toBe("python …/scripts/contract_probe.py --fixture examples/customer-v1.json");
  });
});

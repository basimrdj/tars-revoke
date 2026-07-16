import { describe, expect, it } from "vitest";

import { shouldStreamRun } from "./useRunStream";

describe("shouldStreamRun", () => {
  it("keeps active cases connected", () => {
    expect(shouldStreamRun("EXPERIMENTING")).toBe(true);
    expect(shouldStreamRun("REPAIRING")).toBe(true);
  });

  it("does not reconnect terminal durable runs", () => {
    expect(shouldStreamRun("CLOSED")).toBe(false);
    expect(shouldStreamRun("ESCALATED")).toBe(false);
    expect(shouldStreamRun("FAILED")).toBe(false);
  });
});

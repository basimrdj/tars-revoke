import { describe, expect, it } from "vitest";

import { toneFor } from "./StatusMark";

describe("toneFor", () => {
  it("maps authoritative lifecycle states to stable visual semantics", () => {
    expect(toneFor("AUTHORIZED")).toBe("verified");
    expect(toneFor("REVOKE_PENDING")).toBe("revoked");
    expect(toneFor("FAILED")).toBe("revoked");
    expect(toneFor("INVALID")).toBe("revoked");
    expect(toneFor("ROLLED_BACK")).toBe("warning");
    expect(toneFor("EXPERIMENTING")).toBe("evidence");
  });

  it("does not imply success for unknown states", () => {
    expect(toneFor("NOT_YET_PROVEN")).toBe("neutral");
  });
});

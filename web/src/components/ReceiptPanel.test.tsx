import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ReceiptPanel } from "./ReceiptPanel";

describe("ReceiptPanel", () => {
  it("labels an invalid failure receipt without offering verification", () => {
    const html = renderToStaticMarkup(
      <ReceiptPanel
        receipt={{
          id: "failure-receipt",
          status: "INVALID",
          digest: "a".repeat(64),
          event_count: 42,
          proof_scope: [],
        }}
        onVerify={() => undefined}
      />
    );

    expect(html).toContain("Failure receipt · not verified");
    expect(html).toContain("stopped fail-closed");
    expect(html).not.toContain("Verify independently");
  });
});

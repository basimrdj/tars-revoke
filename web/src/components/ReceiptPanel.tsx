import { ExternalLink, FileCheck2, ShieldAlert, ShieldCheck } from "lucide-react";

import type { ReceiptSummary } from "../types";
import { StatusMark } from "./StatusMark";

function shortDigest(digest: string) {
  return digest.length > 26 ? `${digest.slice(0, 15)}…${digest.slice(-8)}` : digest;
}

export function ReceiptPanel({ receipt, onVerify }: { receipt?: ReceiptSummary | null; onVerify: () => void }) {
  const invalid = receipt?.status === "INVALID";
  return (
    <section className="proof-panel receipt-panel">
      <div className="proof-heading">
        <strong>Receipt</strong>
        {receipt ? <StatusMark status={receipt.status} /> : <span>Not issued</span>}
      </div>
      {!receipt ? (
        <div className="empty-copy">A canonical receipt is rebuilt from durable state after resume.</div>
      ) : (
        <div className="receipt-content">
          <div className={`receipt-seal ${invalid ? "is-invalid" : ""}`}>
            {invalid ? <ShieldAlert size={26} /> : <ShieldCheck size={26} />}
            <span>{invalid ? "Failure receipt · not verified" : "Scoped run proof"}</span>
          </div>
          <dl>
            <div><dt>Receipt ID</dt><dd><code>{receipt.id}</code></dd></div>
            <div><dt>Hash chain</dt><dd><code>{receipt.event_count} events</code></dd></div>
            <div><dt>Scope</dt><dd title={receipt.proof_scope.join(", ")}><code>{receipt.proof_scope.length} run requirements</code></dd></div>
            <div><dt>Digest</dt><dd><code title={receipt.digest}>{shortDigest(receipt.digest)}</code></dd></div>
          </dl>
          {invalid ? (
            <div className="empty-copy">The run stopped fail-closed. This receipt records failure evidence; it does not claim canonical proof.</div>
          ) : (
            <button className="secondary-action" onClick={onVerify}>
              <FileCheck2 size={14} /> Verify independently <ExternalLink size={12} />
            </button>
          )}
        </div>
      )}
    </section>
  );
}

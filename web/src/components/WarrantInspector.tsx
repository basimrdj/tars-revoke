import { Fingerprint, KeyRound, ShieldX } from "lucide-react";

import type { WarrantSnapshot } from "../types";
import { StatusMark } from "./StatusMark";

function short(value: string) {
  return value.length > 32 ? `${value.slice(0, 15)}…${value.slice(-10)}` : value;
}

export function WarrantInspector({ warrant }: { warrant?: WarrantSnapshot }) {
  return (
    <aside className="warrant-inspector" aria-label="Selected warrant">
      <div className="section-heading">
        <div>
          <strong>Selected warrant</strong>
          <small>Live authorization basis</small>
        </div>
        {warrant && <StatusMark status={warrant.status} />}
      </div>
      {!warrant ? (
        <div className="empty-copy">Select a causal warrant after the run begins.</div>
      ) : (
        <>
          <div className="inspector-block inspector-lead">
            <KeyRound size={16} />
            <div><span>Warrant ID</span><code>{warrant.id}</code></div>
          </div>
          <dl className="detail-list">
            <div><dt>Agent</dt><dd className="mono">{warrant.agent_id}</dd></div>
            <div><dt>Issued</dt><dd className="mono">{warrant.issued_at}</dd></div>
            <div><dt>Expires</dt><dd className="mono">{warrant.expires_at ?? "run-bound"}</dd></div>
            <div><dt>Lease epoch</dt><dd className="mono">{warrant.lease_epoch}</dd></div>
          </dl>
          <div className="inspector-block">
            <Fingerprint size={15} />
            <div>
              <span>Premise revisions</span>
              {warrant.premise_ids.map((id) => <code key={id}>{short(id)}</code>)}
            </div>
          </div>
          <div className="inspector-block">
            <Fingerprint size={15} />
            <div>
              <span>Evidence</span>
              {warrant.evidence_ids.map((id) => <code key={id}>{short(id)}</code>)}
            </div>
          </div>
          <div className="inspector-table">
            <span>Artifact hashes</span>
            {Object.entries(warrant.artifact_hashes).map(([path, digest]) => (
              <div key={path}><code>{path}</code><code>{short(digest)}</code></div>
            ))}
          </div>
          <div className="inspector-table">
            <span>Required tests</span>
            {warrant.required_tests.map((test) => <code key={test}>• {test}</code>)}
          </div>
          {warrant.revoked_reason && (
            <div className="revoke-stamp">
              <ShieldX size={25} />
              <strong>REVOKED</strong>
              <span>{warrant.revoked_reason}</span>
            </div>
          )}
        </>
      )}
    </aside>
  );
}

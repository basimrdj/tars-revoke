import { ArchiveRestore, Ban, GitBranch } from "lucide-react";

import type { EffectSnapshot } from "../types";
import { StatusMark } from "./StatusMark";

function EffectIcon({ effect }: { effect: EffectSnapshot }) {
  if (effect.state.toLowerCase() === "quarantined") return <Ban size={14} />;
  if (effect.compensated_at || effect.state.toLowerCase() === "rolled_back") {
    return <ArchiveRestore size={14} />;
  }
  return <GitBranch size={14} />;
}

export function EffectInventory({ effects }: { effects: EffectSnapshot[] }) {
  return (
    <section className="proof-panel effect-panel">
      <div className="proof-heading">
        <strong>Effect inventory</strong>
        <span>{effects.length} durable effects</span>
      </div>
      <div className="effect-list">
        {effects.length === 0 ? (
          <div className="empty-copy">No durable mutations recorded.</div>
        ) : effects.map((effect, index) => (
          <div className="effect-row" key={effect.id}>
            <span className="effect-number">{index + 1}</span>
            <EffectIcon effect={effect} />
            <div>
              <strong>{effect.label}</strong>
              <code>{effect.target}</code>
            </div>
            <StatusMark status={effect.state} />
          </div>
        ))}
      </div>
    </section>
  );
}

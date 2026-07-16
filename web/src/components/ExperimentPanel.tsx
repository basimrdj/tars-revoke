import { FlaskConical, Gauge, TerminalSquare } from "lucide-react";

import type { ExperimentSnapshot } from "../types";
import { StatusMark } from "./StatusMark";

export function displayCommand(command: string[]) {
  return command.map((part, index) => {
    if (index === 0 && /(^|\/)python(?:3(?:\.\d+)?)?$/.test(part)) return "python";
    if (!part.startsWith("/")) return part;
    const segments = part.split("/").filter(Boolean);
    return `…/${segments.slice(-2).join("/")}`;
  }).join(" ");
}

export function ExperimentPanel({ experiment }: { experiment?: ExperimentSnapshot | null }) {
  const chosen = experiment?.candidates.find((candidate) => candidate.selected);
  return (
    <section className="proof-panel experiment-panel">
      <div className="proof-heading">
        <strong>Decisive experiment</strong>
        {experiment ? <StatusMark status={experiment.status} /> : <span>Awaiting dispute</span>}
      </div>
      {!experiment ? (
        <div className="empty-copy">Codex candidates and deterministic cost ordering appear here.</div>
      ) : (
        <div className="experiment-layout">
          <div className="candidate-list">
            {experiment.candidates.map((candidate) => (
              <div className={candidate.selected ? "candidate chosen" : "candidate"} key={candidate.id}>
                <FlaskConical size={13} />
                <span>{candidate.label}</span>
                <code>({candidate.risk_rank}, {candidate.touched_files}, {candidate.estimated_runtime_ms}, {candidate.command_count})</code>
              </div>
            ))}
          </div>
          {chosen && (
            <div className="chosen-experiment">
              <div><Gauge size={14} /><span>Chosen safe minimum</span></div>
              <code title={chosen.command.join(" ")}>
                <TerminalSquare size={13} /> {displayCommand(chosen.command)}
              </code>
              <small>Predictions recorded for {Object.keys(chosen.predictions).length} hypotheses</small>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

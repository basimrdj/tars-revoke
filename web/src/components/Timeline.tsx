import { Check, Circle, X } from "lucide-react";

import type { EventSnapshot } from "../types";
import { toneFor } from "./StatusMark";

interface Milestone {
  event: EventSnapshot;
  label: string;
}

function hasStatus(event: EventSnapshot, status: string) {
  return event.status?.toUpperCase() === status;
}

function first(events: EventSnapshot[], type: string, status?: string) {
  return events.find((event) => event.type === type && (!status || hasStatus(event, status)));
}

function last(events: EventSnapshot[], type: string, status?: string) {
  return [...events]
    .reverse()
    .find((event) => event.type === type && (!status || hasStatus(event, status)));
}

export function timelineMilestones(events: EventSnapshot[]): Milestone[] {
  const rolledBack = events.filter(
    (event) => event.type === "effect.transitioned" && hasStatus(event, "ROLLED_BACK")
  );
  const candidates: Array<Milestone | null> = [
    first(events, "run.created") ? { event: first(events, "run.created")!, label: "Prepared" } : null,
    last(events, "evidence.created")
      ? { event: last(events, "evidence.created")!, label: "Evidence changed" }
      : null,
    first(events, "revocation_case.transitioned", "FROZEN")
      ? { event: first(events, "revocation_case.transitioned", "FROZEN")!, label: "Scope frozen" }
      : null,
    rolledBack.length > 0
      ? {
          event: rolledBack.at(-1)!,
          label: `${rolledBack.length} effect${rolledBack.length === 1 ? "" : "s"} rolled back`
        }
      : null,
    first(events, "effect.transitioned", "QUARANTINED")
      ? { event: first(events, "effect.transitioned", "QUARANTINED")!, label: "Push quarantined" }
      : null,
    first(events, "experiment_run.transitioned", "PASSED")
      ? { event: first(events, "experiment_run.transitioned", "PASSED")!, label: "Decisive test passed" }
      : null,
    first(events, "revocation_case.transitioned", "REPAIRING")
      ? { event: first(events, "revocation_case.transitioned", "REPAIRING")!, label: "Repair started" }
      : null,
    last(events, "test_run.transitioned", "PASSED")
      ? { event: last(events, "test_run.transitioned", "PASSED")!, label: "Verification passed" }
      : null,
    first(events, "revocation_case.transitioned", "RESUMED")
      ? { event: first(events, "revocation_case.transitioned", "RESUMED")!, label: "Branch resumed" }
      : null,
    first(events, "receipt.transitioned", "VERIFIED")
      ? { event: first(events, "receipt.transitioned", "VERIFIED")!, label: "Receipt verified" }
      : null
  ];
  return candidates.filter((candidate): candidate is Milestone => candidate !== null);
}

function eventTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? value : parsed.toISOString().slice(11, 19);
}

function EventIcon({ status }: { status: string }) {
  const tone = toneFor(status);
  if (tone === "verified") return <Check size={12} />;
  if (tone === "revoked") return <X size={12} />;
  return <Circle size={9} fill="currentColor" />;
}

export function Timeline({ events }: { events: EventSnapshot[] }) {
  const visible = timelineMilestones(events);
  return (
    <section className="timeline" aria-label="Run timeline">
      <div className="timeline-title">Run timeline</div>
      <div className="timeline-track">
        {visible.length === 0 ? (
          <div className="timeline-empty">Events will appear from the hash-chained journal.</div>
        ) : (
          visible.map(({ event, label }) => {
            const status = event.status ?? event.type;
            return (
              <div className={`timeline-event timeline-${toneFor(status)}`} key={event.sequence}>
                <span className="timeline-dot"><EventIcon status={status} /></span>
                <strong>{label}</strong>
                <code>#{event.sequence} · {eventTime(event.occurred_at)}</code>
              </div>
            );
          })
        )}
      </div>
    </section>
  );
}

import type { StatusTone } from "../types";

const STATUS_TONES: Record<string, StatusTone> = {
  active: "verified",
  authorized: "verified",
  completed: "verified",
  executed: "verified",
  passed: "verified",
  pushed: "verified",
  restored: "verified",
  resumed: "verified",
  running: "verified",
  verified: "verified",
  invalidated: "revoked",
  invalid: "revoked",
  failed: "revoked",
  cancelled: "revoked",
  escalated: "revoked",
  quarantined: "revoked",
  revoke_pending: "revoked",
  revoked: "revoked",
  rolled_back: "warning",
  containment_required: "warning",
  disputed: "warning",
  prepared: "evidence",
  experimenting: "evidence",
  repairing: "evidence"
};

export function toneFor(status: string): StatusTone {
  return STATUS_TONES[status.toLowerCase()] ?? "neutral";
}

export function StatusMark({ status }: { status: string }) {
  return <span className={`status-mark status-${toneFor(status)}`}>{status.replaceAll("_", " ")}</span>;
}

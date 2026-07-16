import { Play, ShieldCheck } from "lucide-react";

import type { ReceiptSummary, RunInfo } from "../types";
import { StatusMark } from "./StatusMark";

interface Props {
  run: RunInfo | null;
  receipt: ReceiptSummary | null | undefined;
  isConnected: boolean;
  isStarting: boolean;
  onStart: () => void;
  onVerify: () => void;
}

function elapsed(startedAt?: string, closedAt?: string | null) {
  if (!startedAt) return "00:00";
  const end = closedAt ? Date.parse(closedAt) : Date.now();
  const seconds = Math.max(0, Math.floor((end - Date.parse(startedAt)) / 1000));
  return `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}

export function RunControl({ run, receipt, isConnected, isStarting, onStart, onVerify }: Props) {
  const executionLabel = run?.execution_mode === "live-codex"
    ? "CODEX LIVE"
    : run?.execution_mode === "scripted"
      ? "SCRIPTED"
      : "LOCAL";
  return (
    <header className="app-header">
      <div className="brand" aria-label="TARS REVOKE">
        <span className="brand-shield">T</span>
        <span>TARS REVOKE</span>
      </div>
      <div className="run-identity">
        <span className={`connection-dot ${isConnected ? "is-live" : ""}`} />
        <strong className={`mode-${run?.execution_mode ?? "unknown"}`}>{executionLabel}</strong>
        <span>{run?.scenario ?? "external-schema-v2"}</span>
      </div>
      <div className="header-spacer" />
      <div className="elapsed mono">Elapsed {elapsed(run?.started_at, run?.closed_at)}</div>
      <button className="primary-action" disabled={isStarting} onClick={onStart}>
        <Play size={15} fill="currentColor" />
        {isStarting ? "Starting…" : "Run live demo"}
      </button>
      <button
        className="receipt-state"
        disabled={!run || !receipt || receipt.status === "INVALID"}
        onClick={onVerify}
      >
        <ShieldCheck size={17} />
        <span>
          <small>Receipt verification</small>
          {receipt ? <StatusMark status={receipt.status} /> : <b>Not issued</b>}
        </span>
      </button>
    </header>
  );
}

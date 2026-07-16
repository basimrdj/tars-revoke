export type StatusTone = "neutral" | "evidence" | "warning" | "revoked" | "verified";

export interface RunInfo {
  id: string;
  scenario: string;
  execution_mode: "live-codex" | "scripted" | "unknown";
  status: string;
  revocation_status?: string | null;
  started_at: string;
  closed_at?: string | null;
  sequence: number;
}

export interface AgentSnapshot {
  id: string;
  name: string;
  task: string;
  status: string;
  thread_id?: string | null;
  worktree?: string | null;
  warrant_id?: string | null;
  lease_id?: string | null;
  last_heartbeat_at?: string | null;
  pushed_at?: string | null;
}

export interface CausalNodeSnapshot {
  id: string;
  kind: string;
  label: string;
  detail?: string | null;
  status: string;
  depth: number;
  lane: number;
}

export interface CausalEdgeSnapshot {
  id: string;
  source: string;
  target: string;
  kind: string;
  strength: "hard" | "soft";
  affected: boolean;
}

export interface WarrantSnapshot {
  id: string;
  agent_id: string;
  status: string;
  issued_at: string;
  expires_at?: string | null;
  lease_epoch: number;
  premise_ids: string[];
  evidence_ids: string[];
  artifact_hashes: Record<string, string>;
  required_tests: string[];
  revoked_reason?: string | null;
}

export interface EffectSnapshot {
  id: string;
  agent_id: string;
  action_id: string;
  label: string;
  effect_type: string;
  target: string;
  state: string;
  reversibility: string;
  before_hash?: string | null;
  after_hash?: string | null;
  compensated_at?: string | null;
}

export interface ExperimentCandidateSnapshot {
  id: string;
  label: string;
  command: string[];
  risk_rank: number;
  touched_files: number;
  estimated_runtime_ms: number;
  command_count: number;
  validation_status: string;
  selected: boolean;
  predictions: Record<string, string>;
}

export interface ExperimentSnapshot {
  status: string;
  candidates: ExperimentCandidateSnapshot[];
  chosen_id?: string | null;
  exit_code?: number | null;
  result_digest?: string | null;
}

export interface EventSnapshot {
  sequence: number;
  type: string;
  occurred_at: string;
  summary: string;
  status?: string | null;
}

export interface ReceiptSummary {
  id: string;
  status: string;
  digest: string;
  event_count: number;
  proof_scope: string[];
  verified_at?: string | null;
  path?: string | null;
}

export interface FailureSummary {
  status: "FAILED" | "CANCELLED";
  error_type: string;
  message: string;
  stage: string;
  occurred_at: string;
  receipt_digest?: string | null;
  finalization_errors: string[];
}

export interface RunSnapshot {
  run: RunInfo;
  agents: AgentSnapshot[];
  graph: {
    nodes: CausalNodeSnapshot[];
    edges: CausalEdgeSnapshot[];
  };
  warrants: WarrantSnapshot[];
  effects: EffectSnapshot[];
  experiment?: ExperimentSnapshot | null;
  events: EventSnapshot[];
  receipt?: ReceiptSummary | null;
  failure?: FailureSummary | null;
  selected_warrant_id?: string | null;
}

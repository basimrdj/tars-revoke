import { Activity, GitBranch, TimerReset } from "lucide-react";

import type { AgentSnapshot, EffectSnapshot } from "../types";
import { StatusMark, toneFor } from "./StatusMark";

interface Props {
  agents: AgentSnapshot[];
  effects: EffectSnapshot[];
}

function Field({ label, value }: { label: string; value?: string | null }) {
  const visible = label === "Worktree" && value?.startsWith("/")
    ? `…/${value.split("/").filter(Boolean).slice(-2).join("/")}`
    : value;
  return (
    <div className="agent-field">
      <span>{label}</span>
      <code title={value ?? "—"}>{visible ?? "—"}</code>
    </div>
  );
}

export function AgentLanes({ agents, effects }: Props) {
  return (
    <aside className="agent-rail panel-border-right" aria-label="Agent execution lanes">
      <div className="rail-title">
        <Activity size={15} /> Concurrent agents
      </div>
      {agents.length === 0 ? (
        <div className="empty-copy">Start the live demo to create two isolated Codex sessions.</div>
      ) : (
        agents.map((agent, index) => {
          const tone = toneFor(agent.status);
          const agentEffects = effects.filter((effect) => effect.agent_id === agent.id);
          return (
            <section className={`agent-lane lane-${tone}`} key={agent.id}>
              <div className="agent-heading">
                <span className="agent-letter">{String.fromCharCode(65 + index)}</span>
                <div>
                  <strong>{agent.name}</strong>
                  <small>{agent.task}</small>
                </div>
                <StatusMark status={agent.status} />
              </div>
              <Field label="Codex thread" value={agent.thread_id} />
              <Field label="Worktree" value={agent.worktree} />
              <Field label="Lease" value={agent.lease_id} />
              <Field label="Warrant" value={agent.warrant_id} />
              <Field label="Heartbeat" value={agent.last_heartbeat_at} />
              <div className="lane-effects">
                {agentEffects.slice(0, 4).map((effect) => (
                  <div key={effect.id}>
                    <GitBranch size={12} />
                    <span>{effect.label}</span>
                    <StatusMark status={effect.state} />
                  </div>
                ))}
                {agentEffects.length === 0 && (
                  <div className="lane-waiting"><TimerReset size={12} /> Waiting for effects</div>
                )}
              </div>
            </section>
          );
        })
      )}
    </aside>
  );
}

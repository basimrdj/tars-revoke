import { useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps
} from "@xyflow/react";
import { Database, FileCode2, GitCommit, ShieldAlert } from "lucide-react";

import type { CausalEdgeSnapshot, CausalNodeSnapshot } from "../types";
import { StatusMark, toneFor } from "./StatusMark";

function iconFor(kind: string) {
  if (kind.includes("evidence")) return <Database size={15} />;
  if (kind.includes("effect") || kind.includes("action")) return <GitCommit size={15} />;
  if (kind.includes("warrant") || kind.includes("premise")) return <ShieldAlert size={15} />;
  return <FileCode2 size={15} />;
}

function displayLabel(snapshot: CausalNodeSnapshot) {
  const id = snapshot.id.toLowerCase();
  if (snapshot.kind === "premise") {
    return id.includes("observability") ? "Observability premise" : "UUID premise";
  }
  if (snapshot.kind === "warrant") {
    return id.includes("agent-b") ? "Agent B warrant" : "Agent A warrant";
  }
  if (snapshot.kind === "effect") {
    if (id.includes("agent-b")) return "Agent B push";
    if (id.includes("db-v1")) return "DB migration";
    if (id.includes("model-v1")) return "Model patch";
    if (id.includes("push-v1")) return "Pending push";
  }
  return snapshot.label;
}

function CausalNode({ data }: NodeProps<Node<{ snapshot: CausalNodeSnapshot }>>) {
  const snapshot = data.snapshot;
  return (
    <div className={`causal-node node-${toneFor(snapshot.status)}`}>
      <Handle type="target" position={Position.Left} />
      <div className="causal-node-title">
        {iconFor(snapshot.kind)}
        <span>{displayLabel(snapshot)}</span>
      </div>
      {snapshot.detail && <code>{snapshot.detail}</code>}
      <StatusMark status={snapshot.status} />
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { causal: CausalNode };

function isAgentB(id: string) {
  const normalized = id.toLowerCase();
  return normalized.includes("agent-b") || normalized.includes("observability");
}

export function focusCausalGraph(
  nodes: CausalNodeSnapshot[],
  edges: CausalEdgeSnapshot[]
): { nodes: CausalNodeSnapshot[]; edges: CausalEdgeSnapshot[] } {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const outgoing = new Map<string, CausalEdgeSnapshot[]>();
  for (const edge of edges) {
    outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge]);
  }

  const focusedEdges: CausalEdgeSnapshot[] = [];
  for (const edge of edges) {
    const source = byId.get(edge.source);
    const target = byId.get(edge.target);
    if (!source || !target) continue;
    const inScope = edge.affected || (isAgentB(edge.source) && isAgentB(edge.target));
    if (!inScope) continue;
    if (source.kind !== "action" && target.kind !== "action") {
      focusedEdges.push(edge);
      continue;
    }
    if (source.kind !== "action" && target.kind === "action") {
      for (const next of outgoing.get(target.id) ?? []) {
        const collapsedTarget = byId.get(next.target);
        if (!collapsedTarget || collapsedTarget.kind === "action") continue;
        if (!(edge.affected && next.affected) && !(isAgentB(edge.source) && isAgentB(next.target))) {
          continue;
        }
        focusedEdges.push({
          ...next,
          id: `collapsed:${edge.id}:${next.id}`,
          source: edge.source,
          affected: edge.affected || next.affected
        });
      }
    }
  }
  const included = new Set(focusedEdges.flatMap((edge) => [edge.source, edge.target]));
  return {
    nodes: nodes.filter((node) => included.has(node.id) && node.kind !== "action"),
    edges: focusedEdges
  };
}

function buildNodes(snapshots: CausalNodeSnapshot[]): Node<{ snapshot: CausalNodeSnapshot }>[] {
  const affectedEffects = snapshots.filter(
    (snapshot) => snapshot.kind === "effect" && !isAgentB(snapshot.id)
  );
  return snapshots.map((snapshot, index) => ({
    id: snapshot.id,
    type: "causal",
    data: { snapshot },
    position: isAgentB(snapshot.id)
      ? {
          x: snapshot.kind === "premise" ? 22 : snapshot.kind === "warrant" ? 252 : 482,
          y: 360
        }
      : {
          x: snapshot.kind === "premise" ? 22 : snapshot.kind === "warrant" ? 252 : 482,
          y: snapshot.kind === "effect"
            ? affectedEffects.findIndex((effect) => effect.id === snapshot.id) * 112 + 2
            : 114 + (index % 2) * 2
        },
    draggable: false,
    selectable: false
  }));
}

function buildEdges(snapshots: CausalEdgeSnapshot[]): Edge[] {
  return snapshots.map((edge) => ({
    id: edge.id,
    source: edge.source,
    target: edge.target,
    type: "smoothstep",
    animated: edge.affected,
    className: edge.affected ? "edge-affected" : "edge-unrelated",
    label: edge.kind,
    labelStyle: { fill: "#7f8b90", fontSize: 9, fontFamily: "monospace" },
    style: {
      stroke: edge.affected ? "#ff5c47" : "#42d58b",
      strokeDasharray: edge.strength === "soft" ? "5 5" : undefined,
      strokeWidth: edge.affected ? 1.6 : 1.2
    }
  }));
}

export function CausalGraph({ nodes, edges }: { nodes: CausalNodeSnapshot[]; edges: CausalEdgeSnapshot[] }) {
  const focused = useMemo(() => focusCausalGraph(nodes, edges), [nodes, edges]);
  const flowNodes = useMemo(() => buildNodes(focused.nodes), [focused.nodes]);
  const flowEdges = useMemo(() => buildEdges(focused.edges), [focused.edges]);

  return (
    <section className="graph-panel panel-border-right" aria-label="Live causal graph">
      <div className="section-heading">
        <div>
          <strong>Causal graph</strong>
          <small>Persisted hard dependencies drive revocation</small>
        </div>
        <div className="graph-legend">
          <span><i className="legend-evidence" /> evidence</span>
          <span><i className="legend-revoked" /> affected</span>
          <span><i className="legend-live" /> unrelated</span>
        </div>
      </div>
      {nodes.length === 0 ? (
        <div className="empty-graph">
          <ShieldAlert size={28} />
          <strong>No active causal run</strong>
          <span>The graph is computed from persisted dependencies when the demo starts.</span>
        </div>
      ) : (
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.18 }}
          minZoom={0.45}
          maxZoom={1.3}
          nodesConnectable={false}
          elementsSelectable={false}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#162126" gap={28} size={1} variant={BackgroundVariant.Dots} />
        </ReactFlow>
      )}
    </section>
  );
}

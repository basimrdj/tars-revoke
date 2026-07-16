import { useEffect, useMemo, useState } from "react";

import { startDemo, verifyReceipt } from "./api";
import { AgentLanes } from "./components/AgentLanes";
import { CausalGraph } from "./components/CausalGraph";
import { EffectInventory } from "./components/EffectInventory";
import { ExperimentPanel } from "./components/ExperimentPanel";
import { ReceiptPanel } from "./components/ReceiptPanel";
import { RunControl } from "./components/RunControl";
import { Timeline } from "./components/Timeline";
import { WarrantInspector } from "./components/WarrantInspector";
import { useRunStream } from "./hooks/useRunStream";

export default function App() {
  const { snapshot, setSnapshot, error, isConnected, refresh } = useRunStream();
  const [selectedWarrantId, setSelectedWarrantId] = useState<string | null>(null);
  const [isStarting, setStarting] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    if (!snapshot) return;
    const preferred = snapshot.selected_warrant_id ?? snapshot.warrants.find((item) => item.status === "revoked")?.id;
    setSelectedWarrantId((current) => current ?? preferred ?? snapshot.warrants[0]?.id ?? null);
  }, [snapshot]);

  const selectedWarrant = useMemo(
    () => snapshot?.warrants.find((item) => item.id === selectedWarrantId) ?? snapshot?.warrants[0],
    [selectedWarrantId, snapshot]
  );

  async function handleStart() {
    setStarting(true);
    setActionError(null);
    try {
      setSnapshot(await startDemo(true));
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : "Unable to start live demo");
    } finally {
      setStarting(false);
    }
  }

  async function handleVerify() {
    if (!snapshot) return;
    setActionError(null);
    try {
      setSnapshot(await verifyReceipt(snapshot.run.id));
    } catch (caught) {
      setActionError(caught instanceof Error ? caught.message : "Receipt verification failed");
    }
  }

  return (
    <div className="app-shell">
      <RunControl
        run={snapshot?.run ?? null}
        receipt={snapshot?.receipt}
        isConnected={isConnected}
        isStarting={isStarting}
        onStart={() => void handleStart()}
        onVerify={() => void handleVerify()}
      />
      {(error || actionError) && (
        <div className="connection-error" role="alert">
          <span>{actionError ?? error}</span>
          <button onClick={() => void refresh()}>Retry</button>
        </div>
      )}
      {snapshot?.failure && (
        <div className="failure-summary" role="status">
          <strong>{snapshot.failure.status} · fail-closed</strong>
          <span>{snapshot.failure.message}</span>
          <code>
            stage {snapshot.failure.stage}
            {snapshot.run.revocation_status ? ` · case ${snapshot.run.revocation_status}` : ""}
          </code>
        </div>
      )}
      <main className="primary-grid">
        <AgentLanes agents={snapshot?.agents ?? []} effects={snapshot?.effects ?? []} />
        <CausalGraph nodes={snapshot?.graph.nodes ?? []} edges={snapshot?.graph.edges ?? []} />
        <div onClick={() => selectedWarrant && setSelectedWarrantId(selectedWarrant.id)}>
          <WarrantInspector warrant={selectedWarrant} />
        </div>
      </main>
      <Timeline events={snapshot?.events ?? []} />
      <section className="proof-grid">
        <EffectInventory effects={snapshot?.effects ?? []} />
        <ExperimentPanel experiment={snapshot?.experiment} />
        <ReceiptPanel receipt={snapshot?.receipt} onVerify={() => void handleVerify()} />
      </section>
    </div>
  );
}

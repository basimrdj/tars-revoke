import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError, getHealth, getSnapshot } from "../api";
import type { RunSnapshot } from "../types";

const TERMINAL_RUN_STATES = new Set(["cancelled", "closed", "completed", "escalated", "failed"]);

export function shouldStreamRun(status: string) {
  return !TERMINAL_RUN_STATES.has(status.toLowerCase());
}

export function useRunStream(runId = "current") {
  const [snapshot, setSnapshot] = useState<RunSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isConnected, setConnected] = useState(false);
  const sequence = useRef(0);

  const refresh = useCallback(async () => {
    try {
      const resolvedRunId = runId === "current" ? (await getHealth()).current_run_id : runId;
      if (!resolvedRunId) {
        sequence.current = 0;
        setSnapshot(null);
        setError(null);
        return null;
      }
      const next = await getSnapshot(resolvedRunId);
      sequence.current = next.run.sequence;
      setSnapshot(next);
      setError(null);
      return next;
    } catch (caught) {
      if (runId === "current" && caught instanceof ApiError && caught.status === 404) {
        setSnapshot(null);
        setError(null);
        return null;
      }
      setError(caught instanceof Error ? caught.message : "Unable to load run");
      return null;
    }
  }, [runId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!snapshot || !shouldStreamRun(snapshot.run.status)) {
      setConnected(false);
      return;
    }
    const streamRunId = runId === "current" ? snapshot.run.id : runId;
    const source = new EventSource(
      `/api/runs/${encodeURIComponent(streamRunId)}/stream?after=${sequence.current}`
    );
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.addEventListener("snapshot", (event) => {
      const next = JSON.parse((event as MessageEvent<string>).data) as RunSnapshot;
      if (next.run.sequence < sequence.current) return;
      sequence.current = next.run.sequence;
      setSnapshot(next);
      setError(null);
    });
    return () => {
      source.close();
      setConnected(false);
    };
  }, [runId, snapshot?.run.id]);

  return { snapshot, setSnapshot, error, isConnected, refresh };
}

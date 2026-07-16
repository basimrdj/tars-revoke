import type { RunSnapshot } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface HealthSnapshot {
  ok: boolean;
  product: string;
  current_run_id: string | null;
}

async function decode<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const body = await response.text();
    let message = body;
    try {
      const decoded = JSON.parse(body) as { detail?: unknown };
      if (typeof decoded.detail === "string") message = decoded.detail;
    } catch {
      // A non-JSON error body is already the most useful message available.
    }
    throw new ApiError(message || `Request failed with ${response.status}`, response.status);
  }
  return response.json() as Promise<T>;
}

export async function getSnapshot(runId = "current"): Promise<RunSnapshot> {
  return decode(await fetch(`/api/runs/${encodeURIComponent(runId)}`));
}

export async function getHealth(): Promise<HealthSnapshot> {
  return decode(await fetch("/api/health"));
}

export async function startDemo(liveCodex: boolean): Promise<RunSnapshot> {
  return decode(
    await fetch("/api/runs/demo", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ scenario: "external-schema-v2", live_codex: liveCodex })
    })
  );
}

export async function verifyReceipt(runId: string): Promise<RunSnapshot> {
  return decode(
    await fetch(`/api/runs/${encodeURIComponent(runId)}/verify`, { method: "POST" })
  );
}

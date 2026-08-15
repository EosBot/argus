"use client";

import { useEffect, useRef, useState } from "react";
import { getAccessToken } from "../lib/auth";

export type ProgressStatus = "queue" | "running" | "done";

export interface InvestigationProgressState {
  /** Progress percentage 0–100 */
  progress: number;
  /** Mapped status, compatible with ScanCard's ScanStatus */
  status: ProgressStatus;
  /** Whether the WebSocket is currently open */
  isConnected: boolean;
}

const INITIAL_STATE: InvestigationProgressState = {
  progress: 0,
  status: "queue",
  isConnected: false,
};

const RECONNECT_DELAYS_MS = [5_000, 10_000, 20_000];
const HEARTBEAT_INTERVAL_MS = 30_000;

/** Map backend investigation states onto the ScanCard status union. */
function mapBackendState(state: string | undefined): ProgressStatus {
  switch (state) {
    case "running":
    case "planning":
      return "running";
    case "completed":
    case "done":
    case "failed":
    case "timeout":
      return "done";
    default:
      return "queue";
  }
}

function extractProgress(data: Record<string, unknown> | undefined): number | undefined {
  if (!data) return undefined;
  const pct = data.progress_percentage;
  if (typeof pct === "number") return pct;
  const progress = data.progress;
  if (typeof progress === "number") return progress;
  return undefined;
}

function extractState(data: Record<string, unknown> | undefined): string | undefined {
  if (!data) return undefined;
  const state = data.state;
  return typeof state === "string" ? state : undefined;
}

/**
 * Live investigation progress over the backend WebSocket.
 *
 * Connects to `ws(s)://{host}/ws/investigations/{investigationId}`, streams
 * progress/state updates, auto-reconnects with backoff (5s → 10s → 20s) and
 * sends a ping heartbeat every 30s. Returns `{ progress, status, isConnected }`.
 */
export function useInvestigationProgress(investigationId: string): InvestigationProgressState {
  const [state, setState] = useState<InvestigationProgressState>(INITIAL_STATE);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const heartbeatTimerRef = useRef<number | null>(null);
  const closedRef = useRef(false);

  useEffect(() => {
    if (!investigationId) return;

    closedRef.current = false;

    const clearHeartbeat = () => {
      if (heartbeatTimerRef.current !== null) {
        window.clearInterval(heartbeatTimerRef.current);
        heartbeatTimerRef.current = null;
      }
    };

    const connect = () => {
      if (closedRef.current) return;

      const wsHost = process.env.NEXT_PUBLIC_WS_URL?.replace(/^wss?:\/\//, "") || "localhost:8000";
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(
        `${protocol}//${wsHost}/ws/investigations/${investigationId}?token=${encodeURIComponent(getAccessToken() ?? "")}`,
      );
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttemptRef.current = 0;
        setState((prev) => ({ ...prev, isConnected: true }));
        heartbeatTimerRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, HEARTBEAT_INTERVAL_MS);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data as string) as {
            type?: string;
            data?: Record<string, unknown>;
          };
          const data = message.data;
          // "progress" carries InvestigationProgress.to_dict() directly;
          // "connected"/"status" carry status_data with progress nested.
          const progressData =
            message.type === "progress"
              ? data
              : (data?.progress as Record<string, unknown> | undefined) ?? data;
          const pct = extractProgress(progressData);
          const rawState = extractState(progressData) ?? extractState(data);
          setState((prev) => ({
            progress: pct ?? prev.progress,
            status: rawState ? mapBackendState(rawState) : prev.status,
            isConnected: true,
          }));
        } catch {
          // Ignore malformed frames; keep the connection alive.
        }
      };

      ws.onclose = () => {
        setState((prev) => ({ ...prev, isConnected: false }));
        clearHeartbeat();
        if (closedRef.current) return;
        const attempt = reconnectAttemptRef.current;
        const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
        reconnectAttemptRef.current = attempt + 1;
        reconnectTimerRef.current = window.setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      closedRef.current = true;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      clearHeartbeat();
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [investigationId]);

  return state;
}

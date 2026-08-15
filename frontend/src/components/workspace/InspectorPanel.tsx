"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

type ConnStatus = "connecting" | "connected" | "disconnected" | "closed";

interface PayloadEvent {
  id: number;
  type: string;
  content: string;
  timestamp: number;
}

interface InspectorPanelProps {
  /** WebSocket URL to listen to (same as terminal). */
  wsUrl?: string;
  /** Max events to keep in the list. */
  maxEvents?: number;
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

const DEFAULT_WS_PATH = "/ws/v1/terminal";
const TRUNCATE_AT = 240;

const TYPE_COLOR: Record<string, string> = {
  chat: "var(--accent-secondary, #00F0FF)",
  token: "var(--accent-primary, #00FF41)",
  done: "var(--accent-primary, #00FF41)",
  error: "var(--status-danger, #FF3B30)",
  stderr: "var(--status-danger, #FF3B30)",
  info: "var(--accent-secondary, #00F0FF)",
  stdout: "var(--accent-primary, #00FF41)",
  clear: "var(--status-warning, #FFB020)",
};

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function defaultWsUrl(): string {
  if (typeof window === "undefined") return "";
  const proto = window.location.protocol === "https:" ? "wss://" : "ws://";
  return `${proto}${window.location.host}${DEFAULT_WS_PATH}`;
}

function colorForType(type: string): string {
  return TYPE_COLOR[type] ?? "var(--text-muted, #64748b)";
}

function fmtTime(ts: number): string {
  const d = new Date(ts);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/**
 * Parse a raw WS message into a type + content pair.
 * Mirrors TerminalPane's handleMessage logic so the inspector shows
 * the same payload shape the terminal renders.
 */
function parseMessage(raw: string): { type: string; content: string } | null {
  let text = raw;
  if (text.startsWith("data: ")) text = text.slice(6);
  text = text.replace(/\n\n$/, "");
  if (!text) return null;

  let type = "stdout";
  let data = text;
  try {
    const parsed: unknown = JSON.parse(text);
    if (parsed && typeof parsed === "object") {
      const obj = parsed as {
        type?: unknown;
        content?: unknown;
        data?: unknown;
        message?: unknown;
      };
      if (typeof obj.type === "string") type = obj.type;
      const content = obj.content ?? obj.data ?? obj.message;
      if (content !== undefined && content !== null) data = String(content);
    }
  } catch {
    /* plain text -> stdout */
  }
  return { type, content: data };
}

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export default function InspectorPanel({
  wsUrl,
  maxEvents = 200,
}: InspectorPanelProps) {
  const [events, setEvents] = useState<PayloadEvent[]>([]);
  const [status, setStatus] = useState<ConnStatus>("closed");
  const wsRef = useRef<WebSocket | null>(null);
  const idRef = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const autoScrollRef = useRef(true);
  const urlRef = useRef(wsUrl ?? defaultWsUrl());

  /* ---- auto-scroll on new events ---- */
  useEffect(() => {
    if (autoScrollRef.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  /* ---- pause auto-scroll if user scrolls up ---- */
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    autoScrollRef.current = atBottom;
  }, []);

  /* ---- websocket connection (listen-only) ---- */
  useEffect(() => {
    urlRef.current = wsUrl ?? defaultWsUrl();
    const url = urlRef.current;
    if (!url) return;

    setStatus("connecting");
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setStatus("connected");

    ws.onmessage = (ev: MessageEvent) => {
      const handle = async (raw: unknown) => {
        let text: string;
        if (typeof raw === "string") text = raw;
        else if (raw instanceof Blob) text = await raw.text();
        else if (raw instanceof ArrayBuffer)
          text = new TextDecoder().decode(raw);
        else text = String(raw);
        const parsed = parseMessage(text);
        if (!parsed) return;
        idRef.current += 1;
        setEvents((prev) => {
          const next = [
            ...prev,
            {
              id: idRef.current,
              type: parsed.type,
              content: parsed.content,
              timestamp: Date.now(),
            },
          ];
          return next.length > maxEvents
            ? next.slice(next.length - maxEvents)
            : next;
        });
      };
      void handle(ev.data);
    };

    ws.onclose = () => {
      wsRef.current = null;
      setStatus("closed");
    };

    ws.onerror = () => setStatus("disconnected");

    return () => {
      ws.onclose = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.close();
      wsRef.current = null;
    };
  }, [wsUrl, maxEvents]);

  const clearEvents = useCallback(() => {
    setEvents([]);
    idRef.current = 0;
  }, []);

  /* ---- status dot color ---- */
  const statusColor =
    status === "connected"
      ? "var(--accent-primary, #00FF41)"
      : status === "connecting"
        ? "var(--status-warning, #FFB020)"
        : "var(--status-danger, #FF3B30)";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: "var(--surface-1, #0b1120)",
        fontFamily:
          "var(--font-mono, 'JetBrains Mono', 'Fira Code', monospace)",
        fontSize: 12,
        color: "var(--text-primary, #f8fafc)",
      }}
    >
      {/* ---- Header ---- */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 10px",
          borderBottom:
            "1px solid var(--border-subtle, rgba(148,163,184,0.10))",
          background: "var(--surface-2, #111a2e)",
          flex: "none",
        }}
      >
        <img
          src="/logo-mark.svg"
          alt=""
          width={16}
          height={16}
          style={{ flex: "none", opacity: 0.85 }}
          aria-hidden="true"
        />
        <span
          style={{
            fontWeight: 700,
            letterSpacing: "0.10em",
            fontSize: 11,
            color: "var(--accent-primary, #00FF41)",
            flex: "none",
          }}
        >
          INSPECTOR
        </span>
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: "50%",
            background: statusColor,
            flex: "none",
            boxShadow:
              status === "connected"
                ? "0 0 6px rgba(0,255,65,0.6)"
                : "none",
          }}
          title={`ws: ${status}`}
          aria-label={`connection ${status}`}
        />
        <span style={{ flex: 1, minWidth: 0 }} />
        <span
          style={{
            fontSize: 10,
            color: "var(--text-muted, #64748b)",
            flex: "none",
            letterSpacing: "0.04em",
          }}
        >
          {events.length} evt{events.length !== 1 ? "s" : ""}
        </span>
        <button
          type="button"
          onClick={clearEvents}
          title="Clear events"
          style={{
            background: "transparent",
            border: "1px solid transparent",
            color: "var(--text-secondary, #94a3b8)",
            fontFamily: "inherit",
            fontSize: 11,
            padding: "2px 8px",
            borderRadius: 4,
            cursor: "pointer",
            letterSpacing: "0.02em",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "var(--surface-3, #1a2438)";
            e.currentTarget.style.color = "var(--text-primary, #f8fafc)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "var(--text-secondary, #94a3b8)";
          }}
        >
          Clear
        </button>
      </div>

      {/* ---- Event list ---- */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        style={{
          flex: 1,
          minHeight: 0,
          overflowY: "auto",
          padding: "4px 0",
        }}
      >
        {events.length === 0 ? (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              height: "100%",
              color: "var(--text-muted, #64748b)",
              fontSize: 11,
              letterSpacing: "0.06em",
              textAlign: "center",
              padding: 16,
            }}
          >
            {status === "connected"
              ? "Listening for payloads…"
              : status === "connecting"
                ? "Connecting…"
                : "Disconnected — events will appear when the terminal WS is active"}
          </div>
        ) : (
          events.map((ev) => (
            <div
              key={ev.id}
              style={{
                display: "flex",
                gap: 8,
                padding: "3px 10px",
                borderLeft: `2px solid ${colorForType(ev.type)}`,
                lineHeight: 1.45,
              }}
            >
              <span
                style={{
                  color: "var(--text-muted, #64748b)",
                  fontSize: 10,
                  flex: "none",
                  minWidth: 56,
                  opacity: 0.7,
                }}
              >
                {fmtTime(ev.timestamp)}
              </span>
              <span
                style={{
                  color: colorForType(ev.type),
                  flex: "none",
                  minWidth: 52,
                  fontSize: 10,
                  fontWeight: 700,
                  letterSpacing: "0.04em",
                  textTransform: "uppercase",
                }}
              >
                {ev.type}
              </span>
              <span
                style={{
                  color: "var(--text-secondary, #94a3b8)",
                  wordBreak: "break-word",
                  whiteSpace: "pre-wrap",
                }}
              >
                {ev.content.length > TRUNCATE_AT
                  ? `${ev.content.slice(0, TRUNCATE_AT)}…`
                  : ev.content}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

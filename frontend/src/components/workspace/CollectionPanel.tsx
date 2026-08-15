"use client";

/* ============================================================
   ARGUS — CollectionPanel
   Lists collection jobs, creates new ones, polls running ones.
   Backend contract (parallel agent):
     POST /api/collections              -> { id, status, agent, ... }
     GET  /api/collections              -> { items: [...] }
     GET  /api/collections/{id}         -> { id, status, result?, error? }
   ============================================================ */

import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../../lib/api";
import { useInvestigations } from "../../hooks/useInvestigations";

type JobStatus = "pending" | "running" | "done" | "error";

interface CollectionJob {
  id: string;
  status: JobStatus;
  agent: string;
  query?: string;
  result?: unknown;
  error?: string;
  investigationId?: string;
  autonomous?: boolean;
}

const AGENTS = [
  { value: "osint_collector", label: "OSINT Collector" },
  { value: "dark_web_crawler", label: "Dark Web Crawler" },
];

const POLL_INTERVAL_MS = 2000;

export default function CollectionPanel() {
  const { investigations, isLoading: investigationsLoading } = useInvestigations();
  const [items, setItems] = useState<CollectionJob[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [agent, setAgent] = useState<string>(AGENTS[0].value);
  const [query, setQuery] = useState("");
  const [investigationId, setInvestigationId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [autonomous, setAutonomous] = useState(true);
  const [submitError, setSubmitError] = useState<string | null>(null);

  const pollTimers = useRef<Map<string, ReturnType<typeof setInterval>>>(new Map());

  const stopPolling = useCallback((id: string) => {
    const t = pollTimers.current.get(id);
    if (t !== undefined) {
      clearInterval(t);
      pollTimers.current.delete(id);
    }
  }, []);

  const pollOne = useCallback(async (id: string) => {
    try {
      if (id.startsWith("autonomous:")) {
        const investigationId = id.split(":")[1];
        const status = await apiFetch<{ state: string; progress?: unknown; plan?: unknown }>(`/api/investigations/${investigationId}/status`);
        const mapped: JobStatus = status.state === "completed" ? "done" : status.state === "failed" ? "error" : "running";
        setItems((prev) => prev.map((it) => it.id === id ? { ...it, status: mapped, result: { progress: status.progress, plan: status.plan } } : it));
        if (mapped === "done" || mapped === "error") stopPolling(id);
        return;
      }
      const job = await apiFetch<CollectionJob>(`/api/collections/${id}`);
      setItems((prev) =>
        prev.map((it) => (it.id === id ? { ...it, ...job } : it)),
      );
      if (job.status === "done" || job.status === "error") {
        stopPolling(id);
      }
    } catch {
      stopPolling(id);
    }
  }, [stopPolling]);

  const startPolling = useCallback((id: string) => {
    if (pollTimers.current.has(id)) return;
    const t = setInterval(() => {
      pollOne(id);
    }, POLL_INTERVAL_MS);
    pollTimers.current.set(id, t);
  }, [pollOne]);

  const loadList = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);
      const data = await apiFetch<{ items: CollectionJob[] }>("/api/collections");
      setItems(data.items ?? []);
      (data.items ?? []).forEach((it) => {
        if (it.status === "running" || it.status === "pending") {
          startPolling(it.id);
        }
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load collections");
    } finally {
      setIsLoading(false);
    }
  }, [startPolling]);

  useEffect(() => {
    loadList();
    return () => {
      pollTimers.current.forEach((t) => clearInterval(t));
      pollTimers.current.clear();
    };
  }, [loadList]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) {
      setSubmitError("Query is required");
      return;
    }
    if (autonomous && !investigationId) {
      setSubmitError("Selecione uma investigação para a pesquisa autônoma");
      return;
    }
    setSubmitting(true);
    setSubmitError(null);
    try {
      let created: CollectionJob;
      if (autonomous) {
        const params = new URLSearchParams({ goal: query });
        await apiFetch(`/api/investigations/${investigationId}/run?${params.toString()}`, {
          method: "POST",
          body: JSON.stringify({ target: query, autonomous: true }),
        });
        created = { id: `autonomous:${investigationId}:${Date.now()}`, status: "running", agent: "prometheus", query, investigationId, autonomous: true };
      } else {
        created = await apiFetch<CollectionJob>("/api/collections", {
          method: "POST",
          body: JSON.stringify({ agent, query, investigation_id: investigationId || null }),
        });
      }
      setItems((prev) => [created, ...prev]);
      if (created.status === "running" || created.status === "pending") {
        startPolling(created.id);
      }
      setQuery("");
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Failed to create collection");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      {/* New Collection form */}
      <div
        style={{
          padding: "8px 10px",
          borderBottom: "1px solid var(--border-subtle)",
          display: "flex",
          flexDirection: "column",
          gap: 6,
        }}
      >
        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label className="flex items-center gap-2 rounded border border-[var(--border-subtle)] bg-[var(--surface-1)] p-2 text-xs text-[var(--text-secondary)]">
            <input type="checkbox" checked={autonomous} onChange={(event) => setAutonomous(event.target.checked)} />
            Pesquisa autônoma: planejar, coletar, analisar, correlacionar e gerar relatório
          </label>
          <label htmlFor="collection-agent" className="text-[10px] text-[var(--text-muted)]">Agente de coleta</label>
          <select
            id="collection-agent" name="collection-agent"
            value={agent}
            onChange={(e) => setAgent(e.target.value)}
            disabled={autonomous}
            style={{
              background: "var(--surface-1)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 4,
              padding: "4px 6px",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
            }}
          >
            {AGENTS.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </select>
          <label htmlFor="collection-query" className="text-[10px] text-[var(--text-muted)]">O que deve ser pesquisado</label>
          <input
            id="collection-query" name="collection-query" autoComplete="off"
            type="text"
            placeholder="Ex.: domínio example.com…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              background: "var(--surface-1)",
              color: "var(--text-primary)",
              border: "1px solid var(--border-subtle)",
              borderRadius: 4,
              padding: "4px 6px",
              fontSize: 12,
              fontFamily: "var(--font-mono)",
            }}
          />
          <label htmlFor="collection-investigation" className="text-[10px] text-[var(--text-muted)]">Investigação {autonomous ? "(obrigatória)" : "(opcional)"}</label>
          <select id="collection-investigation" value={investigationId} onChange={(event) => setInvestigationId(event.target.value)} disabled={investigationsLoading} className="rounded border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2 py-1 font-mono text-xs text-[var(--text-primary)]">
            <option value="">{investigationsLoading ? "Carregando casos…" : "Selecione um caso"}</option>
            {investigations.map((investigation) => <option key={investigation.id} value={investigation.id}>{investigation.title}</option>)}
          </select>
          <button
            type="submit"
            disabled={submitting}
            style={{
              background: "transparent",
              color: "var(--text-muted)",
              border: "1px dashed var(--border-subtle)",
              borderRadius: 4,
              padding: "4px 8px",
              fontSize: 12,
              cursor: submitting ? "not-allowed" : "pointer",
              fontFamily: "var(--font-mono)",
            }}
          >
            {submitting ? "Iniciando…" : autonomous ? "Iniciar investigação autônoma" : "+ Nova coleta"}
          </button>
        </form>
        {submitError && (
          <div style={{ color: "#ef4444", fontSize: 11, fontFamily: "var(--font-mono)" }}>
            {submitError}
          </div>
        )}
      </div>

      {/* List */}
      <div style={{ flex: 1, overflow: "auto", padding: "8px 10px" }}>
        {isLoading && (
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontFamily: "var(--font-mono)" }}>
            Loading collections…
          </div>
        )}
        {!isLoading && error && (
          <div style={{ color: "#ef4444", fontSize: 12, fontFamily: "var(--font-mono)" }}>
            {error}
          </div>
        )}
        {!isLoading && !error && items.length === 0 && (
          <div style={{ color: "var(--text-muted)", fontSize: 12, fontFamily: "var(--font-mono)" }}>
            Nenhuma coleta ainda. Informe um objetivo acima para iniciar.
          </div>
        )}
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 }}>
          {items.map((it) => (
            <li
              key={it.id}
              style={{
                border: "1px solid var(--border-subtle)",
                borderRadius: 6,
                padding: 8,
                background: "var(--surface-1)",
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  marginBottom: 4,
                }}
              >
                <span style={{ fontSize: 12, color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
                  {it.agent}
                </span>
                <StatusBadge status={it.status} />
              </div>
              {it.query && (
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)", wordBreak: "break-all" }}>
                  {it.query}
                </div>
              )}
              <div style={{ fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: 2 }}>
                {it.id}
              </div>
              {(it.status === "done" || it.status === "error") && (
                <pre
                  style={{
                    marginTop: 6,
                    padding: 6,
                    background: "var(--surface-1)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: 4,
                    fontSize: 10,
                    fontFamily: "var(--font-mono)",
                    color: "var(--text-muted)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    maxHeight: 160,
                    overflow: "auto",
                  }}
                >
                  {it.error ? it.error : JSON.stringify(it.result ?? null, null, 2)}
                </pre>
              )}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function StatusBadge({ status }: { status: JobStatus }) {
  const color =
    status === "done"
      ? "#22c55e"
      : status === "running"
        ? "#3b82f6"
        : status === "error"
          ? "#ef4444"
          : "var(--text-muted)";
  return (
    <span
      style={{
        fontSize: 10,
        fontFamily: "var(--font-mono)",
        color,
        border: `1px solid ${color}`,
        borderRadius: 3,
        padding: "1px 5px",
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {status}
    </span>
  );
}

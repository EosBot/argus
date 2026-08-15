"use client";

import { FormEvent, useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import { useInvestigations } from "../../hooks/useInvestigations";

interface BrowseResponse {
  url: string;
  status?: string;
  result?: Record<string, unknown>;
  evidence_id?: string | null;
}

interface HistoryItem { id: string; investigation_id: string; investigation_title: string; url: string; content_hash?: string; created_at: string; metadata: Record<string, unknown> }

export default function SafeBrowserPanel({ initialUrl = "" }: { initialUrl?: string }) {
  const { investigations, isLoading: investigationsLoading } = useInvestigations();
  const [url, setUrl] = useState("");
  const [investigationId, setInvestigationId] = useState("");
  const [data, setData] = useState<BrowseResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  useEffect(() => {
    if (initialUrl) setUrl(initialUrl);
  }, [initialUrl]);

  async function loadHistory() {
    try {
      const response = await apiFetch<{ items: HistoryItem[] }>("/api/operations/browser/history");
      setHistory(response.items);
    } catch {
      setHistory([]);
    }
  }

  useEffect(() => { void loadHistory(); }, []);

  async function navigate(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const response = await apiFetch<BrowseResponse>("/api/operations/browser/navigate", {
        method: "POST",
        body: JSON.stringify({ url, investigation_id: investigationId || null }),
      });
      setData(response);
      void loadHistory();
    } catch (cause) {
      setData(null);
      setError(cause instanceof Error ? cause.message : "Falha na navegação isolada");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex h-full flex-col gap-3 overflow-auto bg-[var(--surface-1)] p-3 text-xs">
      <div>
        <h3 className="font-semibold text-[var(--text-primary)]">Navegador Tor isolado</h3>
        <p className="mt-1 text-[11px] leading-relaxed text-[var(--text-muted)]">A página é buscada pelo backend via Tor e devolvida como evidência sanitizada. Scripts e conteúdo ativo não são executados no seu navegador.</p>
      </div>
      <form className="space-y-2" onSubmit={navigate}>
        <label className="block text-[10px] uppercase tracking-wider text-[var(--text-muted)]" htmlFor="safe-browser-url">Endereço .onion</label>
        <input id="safe-browser-url" required type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="http://exemplo.onion/caminho" autoComplete="off" className="w-full rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-2 font-mono text-[var(--text-primary)]" />
        <label className="block text-[10px] uppercase tracking-wider text-[var(--text-muted)]" htmlFor="safe-browser-investigation">Salvar na investigação (opcional)</label>
        <select id="safe-browser-investigation" value={investigationId} onChange={(event) => setInvestigationId(event.target.value)} disabled={investigationsLoading} className="w-full rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-2 font-mono text-[var(--text-primary)]">
          <option value="">Não vincular</option>
          {investigations.map((investigation) => <option key={investigation.id} value={investigation.id}>{investigation.title}</option>)}
        </select>
        <button type="submit" disabled={loading} className="rounded bg-[var(--accent-primary)] px-3 py-2 font-medium text-white disabled:opacity-50">{loading ? "Buscando via Tor…" : "Navegar com isolamento"}</button>
      </form>
      {error && <div role="alert" className="rounded border border-red-500/30 p-3 text-red-300">{error}</div>}
      {data && <section aria-label="Conteúdo coletado" className="min-h-0 rounded border border-[var(--border-subtle)] bg-black/20 p-3">
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1 break-all font-mono text-[var(--accent-primary)]">{String(data.result?.url ?? data.url)}</div>
          <button type="button" title="Copiar URL" aria-label="Copiar URL da evidência" className="shrink-0 rounded border border-[var(--border-subtle)] px-2 py-1 text-[10px] text-[var(--text-muted)] hover:bg-[var(--surface-3)] hover:text-[var(--text-primary)]" onClick={() => { void navigator.clipboard.writeText(String(data.result?.url ?? data.url)).catch(() => undefined); }}>Copiar</button>
        </div>
        <dl className="my-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[10px] text-[var(--text-muted)]"><dt>Status</dt><dd>{String(data.result?.status ?? data.status ?? "—")}</dd><dt>SHA-256</dt><dd className="break-all font-mono">{String(data.result?.content_hash ?? "—")}</dd><dt>Evidência</dt><dd>{data.evidence_id ?? "não vinculada"}</dd><dt>Isolamento</dt><dd>JS, downloads e service workers bloqueados</dd></dl>
        <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words border-t border-[var(--border-subtle)] pt-2 text-[11px] leading-relaxed text-[var(--text-secondary)]">{String(data.result?.content ?? data.result?.error ?? "Nenhum conteúdo textual retornado")}</pre>
      </section>}
      <section aria-labelledby="browser-history-title" className="rounded border border-[var(--border-subtle)] p-3">
        <h4 id="browser-history-title" className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Histórico preservado</h4>
        {history.length === 0 ? <p className="mt-2 text-[11px] text-[var(--text-muted)]">Nenhuma captura vinculada encontrada.</p> : <ul className="mt-2 space-y-2">{history.map((item) => <li key={item.id}><button type="button" onClick={() => { setUrl(item.url); setInvestigationId(item.investigation_id); }} className="w-full rounded bg-[var(--surface-2)] p-2 text-left hover:bg-[var(--surface-3)]"><span className="block truncate font-mono text-[11px] text-[var(--text-primary)]">{item.url}</span><span className="block truncate text-[10px] text-[var(--text-muted)]">{item.investigation_title} · {new Date(item.created_at).toLocaleString("pt-BR")} · {item.content_hash?.slice(0, 12) ?? "sem hash"}</span></button></li>)}</ul>}
      </section>
    </div>
  );
}

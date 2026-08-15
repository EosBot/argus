"use client";

/* ============================================================
   ARGUS 2.0 — Tool Configuration
   Enable/disable tools and configure parameters by category.
   ============================================================ */

import { useCallback, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useInvestigations } from "../../hooks/useInvestigations";

/* ============================ Types ============================ */

export type ToolCategory =
  | "recon"
  | "analysis"
  | "exploitation"
  | "collection"
  | "reporting";

export interface Tool {
  id: string;
  name: string;
  category: ToolCategory;
  enabled: boolean;
  description: string;
  version?: string;
  requiresApiKey: boolean;
  configured: boolean;
  parameters?: Record<string, unknown>;
  availability?: "available" | "needs_connection" | "not_installed" | "not_implemented";
  implementation?:
    | "agent"
    | "native"
    | "system"
    | "public_api"
    | "connector"
    | "connector+agent"
    | "binary+agent";
  binary?: string;
}

export interface ToolConfigProps {
  tools: Tool[];
  onToggle?: (id: string, enabled: boolean) => Promise<void>;
  onConfigure?: (id: string, params: Record<string, unknown>) => Promise<void>;
  onExecute?: (id: string, target: string, investigationId: string, authorized: boolean) => Promise<string>;
}

/* ============================ Metadata ============================ */

const CATEGORY_META: Record<
  ToolCategory,
  { label: string; icon: string; description: string }
> = {
  recon: {
    label: "Reconnaissance",
    icon: "🔍",
    description: "OSINT gathering, port scanning, service enumeration",
  },
  analysis: {
    label: "Analysis",
    icon: "📊",
    description: "Threat analysis, malware detection, pattern matching",
  },
  exploitation: {
    label: "Exploitation",
    icon: "⚡",
    description: "Vulnerability scanning, payload generation",
  },
  collection: {
    label: "Collection",
    icon: "📦",
    description: "Data harvesting, evidence gathering, IOC extraction",
  },
  reporting: {
    label: "Reporting",
    icon: "📄",
    description: "Report generation, export formats, documentation",
  },
};

const CATEGORY_COLORS: Record<ToolCategory, string> = {
  recon: "border-emerald-500/40 bg-emerald-500/10",
  analysis: "border-blue-500/40 bg-blue-500/10",
  exploitation: "border-red-500/40 bg-red-500/10",
  collection: "border-amber-500/40 bg-amber-500/10",
  reporting: "border-purple-500/40 bg-purple-500/10",
};

/* ============================ Component ============================ */

export default function ToolConfig({
  tools,
  onToggle,
  onConfigure,
  onExecute,
}: ToolConfigProps) {
  const { investigations, isLoading: investigationsLoading } = useInvestigations();
  const [expandedCategory, setExpandedCategory] = useState<ToolCategory | null>("recon");
  const [expandedTool, setExpandedTool] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const toolsByCategory = (category: ToolCategory) =>
    tools.filter((tool) => {
      if (tool.category !== category) return false;
      const term = search.trim().toLowerCase();
      return !term || `${tool.name} ${tool.description} ${tool.binary ?? ""}`.toLowerCase().includes(term);
    });
  const executableCount = tools.filter((tool) => tool.availability === "available").length;
  const pendingCount = tools.length - executableCount;

  const toggleCategory = useCallback((cat: ToolCategory) => {
    setExpandedCategory((prev) => (prev === cat ? null : cat));
  }, []);

  const toggleToolExpand = useCallback((id: string) => {
    setExpandedTool((prev) => (prev === id ? null : id));
  }, []);

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">
          Tool Configuration
        </h3>
        <p className="mt-1 text-xs text-[var(--text-muted)]">
          {executableCount} executáveis agora · {pendingCount} dependem de pacote, conexão ou executor
        </p>
      </div>

      <label className="block">
        <span className="sr-only">Buscar ferramentas</span>
        <input
          type="search"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Buscar por nome, função ou pacote…"
          className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-2 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--accent-primary)]"
        />
      </label>

      <div className="space-y-2">
        {(Object.keys(CATEGORY_META) as ToolCategory[]).map((cat) => {
          const meta = CATEGORY_META[cat];
          const catTools = toolsByCategory(cat);
          const enabledCount = catTools.filter((t) => t.enabled).length;
          // Search results must be immediately discoverable. Keeping a matching
          // category collapsed made the search appear empty until the operator
          // guessed which accordion contained the tool.
          const isExpanded = search.trim().length > 0 ? catTools.length > 0 : expandedCategory === cat;

          return (
            <div key={cat} className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)]">
              <button
                type="button"
                aria-expanded={isExpanded}
                className="flex w-full items-center gap-3 p-3 text-left hover:bg-[var(--surface-3)] focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-[var(--accent-primary)]"
                onClick={() => toggleCategory(cat)}
              >
                <span className="text-lg">{meta.icon}</span>
                <div className="flex-1">
                  <div className="text-sm font-medium text-[var(--text-primary)]">{meta.label}</div>
                  <div className="text-[10px] text-[var(--text-muted)]">{meta.description}</div>
                </div>
                <span className="text-[10px] text-[var(--text-muted)]">
                  {enabledCount}/{catTools.length} active
                </span>
                <svg
                  viewBox="0 0 16 16"
                  className={`h-4 w-4 text-[var(--text-muted)] transition-transform ${isExpanded ? "rotate-180" : ""}`}
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.5"
                >
                  <path d="M4 6l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </button>

              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden border-t border-[var(--border-subtle)]"
                  >
                    <div className="space-y-1 p-2">
                      {catTools.length === 0 && (
                        <div className="p-3 text-center text-[10px] text-[var(--text-muted)]">
                          No tools in this category
                        </div>
                      )}
                      {catTools.map((tool) => (
                        <ToolRow
                          key={tool.id}
                          tool={tool}
                          expanded={expandedTool === tool.id}
                          onToggle={() => onToggle?.(tool.id, !tool.enabled)}
                          onExpand={() => toggleToolExpand(tool.id)}
                          onConfigure={(params) => onConfigure?.(tool.id, params)}
                          onExecute={onExecute ? (target, investigationId, authorized) => onExecute(tool.id, target, investigationId, authorized) : undefined}
                          investigations={investigations}
                          investigationsLoading={investigationsLoading}
                        />
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ============================ Tool Row ============================ */

function ToolRow({
  tool,
  expanded,
  onToggle,
  onExpand,
  onConfigure,
  onExecute,
  investigations,
  investigationsLoading,
}: {
  tool: Tool;
  expanded: boolean;
  onToggle: () => Promise<void> | undefined;
  onExpand: () => void;
  onConfigure: (params: Record<string, unknown>) => Promise<void> | undefined;
  onExecute?: (target: string, investigationId: string, authorized: boolean) => Promise<string>;
  investigations: Array<{ id: string; title: string }>;
  investigationsLoading: boolean;
}) {
  const [editParams, setEditParams] = useState<Record<string, string>>({});
  const [target, setTarget] = useState("");
  const [investigationId, setInvestigationId] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [executionStatus, setExecutionStatus] = useState("");
  const [saving, setSaving] = useState(false);
  const [settingsStatus, setSettingsStatus] = useState("");

  const toggle = async () => {
    setSaving(true);
    setSettingsStatus("");
    try {
      await onToggle();
    } catch (cause) {
      setSettingsStatus(cause instanceof Error ? cause.message : "Falha ao alterar ferramenta");
    } finally {
      setSaving(false);
    }
  };

  const configure = async () => {
    setSaving(true);
    setSettingsStatus("");
    try {
      await onConfigure(editParams);
      setSettingsStatus("Configuração confirmada pelo backend.");
    } catch (cause) {
      setSettingsStatus(cause instanceof Error ? cause.message : "Falha ao salvar configuração");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="rounded-md bg-[var(--surface-1)]">
      <div className="flex items-center gap-2 p-2">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            void toggle();
          }}
          disabled={saving || tool.availability !== "available"}
          role="switch"
          aria-checked={tool.enabled}
          aria-label={`${tool.enabled ? "Desativar" : "Ativar"} ${tool.name}`}
          className={`relative h-5 w-9 rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
            tool.enabled ? "bg-[var(--accent-primary)]" : "bg-[var(--surface-3)]"
          }`}
        >
          <span
            className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${
              tool.enabled ? "left-[18px]" : "left-0.5"
            }`}
          />
        </button>

        <div className="flex-1 min-w-0 cursor-pointer" onClick={onExpand}>
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-[var(--text-primary)]">{tool.name}</span>
            {tool.version && (
              <span className="text-[10px] text-[var(--text-muted)]">v{tool.version}</span>
            )}
            {tool.requiresApiKey && !tool.configured && (
              <span className="rounded-full bg-amber-500/20 px-1.5 py-0.5 text-[9px] text-amber-300">
                Needs API key
              </span>
            )}
            {tool.availability && tool.availability !== "available" && (
              <span className="rounded-full bg-zinc-500/20 px-1.5 py-0.5 text-[9px] text-zinc-300">
                {tool.availability === "not_installed" ? `Instale ${tool.binary ?? "o pacote"}` : tool.availability === "needs_connection" ? "Configure a conexão" : "Sem executor"}
              </span>
            )}
          </div>
          <div className="text-[10px] text-[var(--text-muted)]">{tool.description}</div>
        </div>

        <svg
          viewBox="0 0 16 16"
          className={`h-3 w-3 shrink-0 text-[var(--text-muted)] transition-transform ${expanded ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <path d="M4 6l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>

      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-[var(--border-subtle)]"
          >
            <div className="space-y-2 p-2">
              <div className="text-[10px] text-[var(--text-muted)]">Implementação: {tool.implementation ?? "não informada"}</div>
              {tool.parameters &&
                Object.entries(tool.parameters).map(([key, value]) => (
                  <div key={key}>
                    <label className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                      {key}
                    </label>
                    <input
                      type="text"
                      defaultValue={String(value)}
                      onChange={(e) =>
                        setEditParams((prev) => ({ ...prev, [key]: e.target.value }))
                      }
                      className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
                    />
                  </div>
                ))}
              <button
                type="button"
                onClick={() => void configure()}
                disabled={saving}
                className="rounded-md bg-[var(--accent-primary)]/10 px-3 py-1 text-[10px] font-medium text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/20"
              >
                {saving ? "Salvando…" : "Save Configuration"}
              </button>
              {settingsStatus && <p role="status" className="text-[10px] text-[var(--text-muted)]">{settingsStatus}</p>}
              {onExecute && tool.availability === "available" && (
                <div className="space-y-2 border-t border-[var(--border-subtle)] pt-2">
                  <label className="block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Objetivo, indicador ou alvo</label>
                  <textarea value={target} onChange={(event) => setTarget(event.target.value)} rows={2} className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] text-[var(--text-primary)]" />
                  <select value={investigationId} onChange={(event) => setInvestigationId(event.target.value)} disabled={investigationsLoading} aria-label="Investigação vinculada" className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-2)] px-2 py-1 font-mono text-[11px] text-[var(--text-primary)]">
                    <option value="">{investigationsLoading ? "Carregando casos…" : "Selecione um caso (obrigatório)"}</option>
                    {investigations.map((investigation) => <option key={investigation.id} value={investigation.id}>{investigation.title}</option>)}
                  </select>
                  {tool.category === "exploitation" && <label className="flex items-center gap-2 text-[10px] text-amber-300"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />Confirmo autorização explícita para este alvo</label>}
                  <button type="button" disabled={!target.trim() || !investigationId || (tool.category === "exploitation" && !authorized)} onClick={async () => { try { setExecutionStatus("Enviando…"); setExecutionStatus(await onExecute(target, investigationId, authorized)); } catch (cause) { setExecutionStatus(cause instanceof Error ? cause.message : "Falha ao executar"); } }} className="rounded-md bg-[var(--accent-primary)] px-3 py-1 text-[10px] font-medium text-white disabled:opacity-40">Executar ferramenta</button>
                  {executionStatus && <pre role="status" className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded border border-[var(--border-subtle)] bg-black/20 p-2 font-mono text-[10px] text-[var(--text-muted)]">{executionStatus}</pre>}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

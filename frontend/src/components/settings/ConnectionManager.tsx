"use client";

/* ============================================================
   ARGUS 2.0 — Connection Manager
   CRUD operations for tool backend connections.
   ============================================================ */

import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";

/* ============================ Types ============================ */

export type ConnectionStatus = "connected" | "disconnected" | "error" | "testing";

export interface ToolConnection {
  id: string;
  name: string;
  type: "shodan" | "censys" | "virustotal" | "abuseipdb" | "otx" | "threatfox" | "urlhaus" | "custom";
  endpoint?: string;
  apiKey?: string;
  status: ConnectionStatus;
  lastSync?: Date;
  capabilities: string[];
}

export interface ConnectionManagerProps {
  connections: ToolConnection[];
  onAdd?: (connection: Omit<ToolConnection, "id" | "status" | "capabilities">) => Promise<void>;
  onUpdate?: (id: string, updates: Partial<ToolConnection>) => Promise<void>;
  onDelete?: (id: string) => Promise<void>;
  onTest?: (id: string) => Promise<boolean>;
  onSync?: (id: string) => Promise<void>;
}

/* ============================ Metadata ============================ */

const TOOL_TYPES: Record<
  ToolConnection["type"],
  { label: string; icon: string; defaultEndpoint: string; capabilities: string[] }
> = {
  shodan: {
    label: "Shodan",
    icon: "🔍",
    defaultEndpoint: "https://api.shodan.io",
    capabilities: ["host-lookup", "port-scan", "vuln-search"],
  },
  censys: {
    label: "Censys",
    icon: "🌐",
    defaultEndpoint: "https://api.platform.censys.io/v3/global",
    capabilities: ["public-host-lookup"],
  },
  virustotal: {
    label: "VirusTotal",
    icon: "🦠",
    defaultEndpoint: "https://www.virustotal.com/api/v3",
    capabilities: ["url-scan", "file-scan", "domain-report"],
  },
  abuseipdb: {
    label: "AbuseIPDB",
    icon: "⚠️",
    defaultEndpoint: "https://api.abuseipdb.com/api/v2",
    capabilities: ["ip-check", "bulk-check"],
  },
  otx: {
    label: "OTX AlienVault",
    icon: "👽",
    defaultEndpoint: "https://otx.alienvault.com/api/v1",
    capabilities: ["pulse-search", "ioc-lookup", "domain-report"],
  },
  threatfox: {
    label: "ThreatFox",
    icon: "🦊",
    defaultEndpoint: "https://threatfox-api.abuse.ch/api/v1/",
    capabilities: ["ioc-search", "malware-intelligence"],
  },
  urlhaus: {
    label: "URLhaus",
    icon: "🔗",
    defaultEndpoint: "https://urlhaus-api.abuse.ch/v1/",
    capabilities: ["malicious-url-lookup"],
  },
  custom: {
    label: "Custom API",
    icon: "⚙️",
    defaultEndpoint: "",
    capabilities: [],
  },
};

const STATUS_META: Record<ConnectionStatus, { label: string; dot: string; text: string }> = {
  connected: { label: "Connected", dot: "bg-emerald-400", text: "text-emerald-400" },
  disconnected: { label: "Disconnected", dot: "bg-zinc-500", text: "text-zinc-400" },
  error: { label: "Error", dot: "bg-red-400", text: "text-red-400" },
  testing: { label: "Testing...", dot: "bg-amber-400 animate-pulse", text: "text-amber-400" },
};

/* ============================ Component ============================ */

export default function ConnectionManager({
  connections,
  onAdd,
  onUpdate,
  onDelete,
  onTest,
  onSync,
}: ConnectionManagerProps) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);

  const toggleExpand = useCallback((id: string) => {
    setExpanded((prev) => (prev === id ? null : id));
  }, []);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">
            Tool Connections
          </h3>
          <p className="mt-1 text-xs text-[var(--text-muted)]">
            Manage connections to OSINT tool backends
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-1.5 rounded-md bg-[var(--accent-primary)]/10 px-3 py-1.5 text-xs font-medium text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/20"
        >
          <span>+</span>
          Add Connection
        </button>
      </div>

      {/* Add Form */}
      <AnimatePresence>
        {showAdd && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <AddConnectionForm
              onSubmit={async (c) => {
                await onAdd?.(c);
                setShowAdd(false);
              }}
              onCancel={() => setShowAdd(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Connection List */}
      <div className="space-y-2">
        {connections.length === 0 && (
          <div className="rounded-lg border border-dashed border-[var(--border-subtle)] p-6 text-center">
            <p className="text-xs text-[var(--text-muted)]">
              No connections configured. Add one to enable tool access.
            </p>
          </div>
        )}
        {connections.map((conn) => (
          <ConnectionCard
            key={conn.id}
            connection={conn}
            expanded={expanded === conn.id}
            onToggle={() => toggleExpand(conn.id)}
            onUpdate={(updates) => onUpdate?.(conn.id, updates)}
            onDelete={() => onDelete?.(conn.id)}
            onTest={onTest ? () => onTest(conn.id) : async () => false}
            onSync={onSync ? () => onSync(conn.id) : async () => undefined}
          />
        ))}
      </div>
    </div>
  );
}

/* ============================ Connection Card ============================ */

function ConnectionCard({
  connection,
  expanded,
  onToggle,
  onUpdate,
  onDelete,
  onTest,
  onSync,
}: {
  connection: ToolConnection;
  expanded: boolean;
  onToggle: () => void;
  onUpdate: (updates: Partial<ToolConnection>) => Promise<void> | undefined;
  onDelete: () => Promise<void> | undefined;
  onTest: () => Promise<boolean>;
  onSync: () => Promise<void>;
}) {
  const meta = TOOL_TYPES[connection.type];
  const status = STATUS_META[connection.status];
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [endpoint, setEndpoint] = useState(connection.endpoint || "");
  const [apiKey, setApiKey] = useState(connection.apiKey || "");

  useEffect(() => {
    setEndpoint(connection.endpoint || "");
    setApiKey(connection.apiKey || "");
  }, [connection.endpoint, connection.apiKey]);

  const handleTest = async () => {
    setTesting(true);
    setActionError(null);
    try {
      if (!await onTest()) setActionError("A conexão não respondeu com credenciais válidas.");
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Falha ao testar a conexão.");
    } finally {
      setTesting(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    setActionError(null);
    try {
      await onSync();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Falha ao sincronizar a conexão.");
    } finally {
      setSyncing(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setActionError(null);
    try {
      await onUpdate({ endpoint, apiKey });
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Não foi possível salvar a conexão.");
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    setSaving(true);
    setActionError(null);
    try {
      await onDelete();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Não foi possível excluir a conexão.");
      setSaving(false);
    }
  };

  return (
    <motion.div
      layout
      className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)]"
    >
      {/* Summary Row */}
      <div
        className="flex cursor-pointer items-center gap-3 p-3 hover:bg-[var(--surface-3)]"
        onClick={onToggle}
      >
        <span className="text-lg">{meta.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--text-primary)]">
              {connection.name}
            </span>
            <span className="text-xs text-[var(--text-muted)]">({meta.label})</span>
          </div>
          {connection.endpoint && (
            <span className="truncate font-mono text-[10px] text-[var(--text-muted)]">
              {connection.endpoint}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="flex items-center gap-1">
            <span className={`h-2 w-2 rounded-full ${status.dot}`} />
            <span className={`text-[10px] ${status.text}`}>{status.label}</span>
          </span>
          <svg
            viewBox="0 0 16 16"
            className={`h-4 w-4 text-[var(--text-muted)] transition-transform ${expanded ? "rotate-180" : ""}`}
            fill="none"
            stroke="currentColor"
            strokeWidth="1.5"
          >
            <path d="M4 6l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
      </div>

      {/* Expanded Details */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-[var(--border-subtle)]"
          >
            <div className="space-y-3 p-3">
              {/* Endpoint */}
              <div>
                <label htmlFor={`connection-endpoint-${connection.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Endpoint
                </label>
                <input
                  id={`connection-endpoint-${connection.id}`}
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
                  placeholder={meta.defaultEndpoint}
                />
              </div>

              {/* API Key */}
              <div>
                <label htmlFor={`connection-key-${connection.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  API Key
                </label>
                <input
                  id={`connection-key-${connection.id}`}
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
                  placeholder="Enter API key"
                />
              </div>

              {/* Capabilities */}
              <div>
                <label className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Capabilities
                </label>
                <div className="flex flex-wrap gap-1">
                  {connection.capabilities.map((cap) => (
                    <span
                      key={cap}
                      className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-3)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                    >
                      {cap}
                    </span>
                  ))}
                  {connection.capabilities.length === 0 && (
                    <span className="text-[10px] italic text-[var(--text-muted)]">
                      No capabilities detected
                    </span>
                  )}
                </div>
              </div>

              {/* Last Sync */}
              {connection.lastSync && (
                <div className="text-[10px] text-[var(--text-muted)]">
                  Last sync: {connection.lastSync.toLocaleString()}
                </div>
              )}

              {/* Actions */}
              {actionError && <p role="alert" className="text-[10px] text-red-300">{actionError}</p>}
              <div className="flex items-center justify-between pt-2">
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={handleTest}
                    disabled={testing || saving}
                    className="flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-3)] disabled:opacity-50"
                  >
                    {testing ? (
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent-primary)] border-t-transparent" />
                    ) : (
                      <span>🔄</span>
                    )}
                    {testing ? "Testing..." : "Test"}
                  </button>
                  <button
                    type="button"
                    onClick={handleSync}
                    disabled={syncing || saving}
                    className="flex items-center gap-1.5 rounded-md border border-[var(--border-subtle)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:bg-[var(--surface-3)] disabled:opacity-50"
                  >
                    {syncing ? (
                      <span className="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent-primary)] border-t-transparent" />
                    ) : (
                      <span>🔃</span>
                    )}
                    {syncing ? "Syncing..." : "Sync"}
                  </button>
                  <button type="button" onClick={() => void handleSave()} disabled={saving} className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">{saving ? "Salvando…" : "Salvar alterações"}</button>
                </div>
                <button
                  type="button"
                  onClick={() => void handleDelete()}
                  disabled={saving}
                  className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs text-red-400 hover:bg-red-400/10"
                >
                  <span>🗑️</span>
                  Delete
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

/* ============================ Add Connection Form ============================ */

function AddConnectionForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (connection: Omit<ToolConnection, "id" | "status" | "capabilities">) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState<ToolConnection["type"]>("shodan");
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setSaving(true);
    setError(null);
    try {
      await onSubmit({ name: name.trim(), type, endpoint: endpoint || TOOL_TYPES[type].defaultEndpoint, apiKey });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível adicionar a conexão.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-lg border border-[var(--accent-primary)]/30 bg-[var(--surface-2)] p-4"
    >
      <h4 className="mb-3 text-xs font-semibold text-[var(--text-primary)]">
        Add New Connection
      </h4>
      <div className="grid grid-cols-2 gap-3">
        {/* Name */}
        <div>
          <label htmlFor="new-connection-name" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Name
          </label>
          <input
            id="new-connection-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder="My Shodan API"
            autoFocus
          />
        </div>

        {/* Type */}
        <div>
          <label htmlFor="new-connection-type" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Tool Type
          </label>
          <select
            id="new-connection-type"
            value={type}
            onChange={(e) => setType(e.target.value as ToolConnection["type"])}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
          >
            {Object.entries(TOOL_TYPES).map(([key, meta]) => (
              <option key={key} value={key}>
                {meta.icon} {meta.label}
              </option>
            ))}
          </select>
        </div>

        {/* Endpoint */}
        <div className="col-span-2">
          <label htmlFor="new-connection-endpoint" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Endpoint
          </label>
          <input
            id="new-connection-endpoint"
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder={TOOL_TYPES[type].defaultEndpoint}
          />
        </div>

        {/* API Key */}
        <div className="col-span-2">
          <label htmlFor="new-connection-key" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            API Key
          </label>
          <input
            id="new-connection-key"
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder="Enter API key"
          />
        </div>
      </div>

      {/* Actions */}
      {error && <p role="alert" className="mt-3 text-[10px] text-red-300">{error}</p>}
      <div className="mt-4 flex justify-end gap-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md px-3 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)]"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={saving || !name.trim()}
          className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-[var(--text-on-accent)] hover:bg-[var(--accent-primary-dim)] disabled:opacity-50"
        >
          {saving ? "Adicionando…" : "Add Connection"}
        </button>
      </div>
    </form>
  );
}

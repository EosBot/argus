"use client";

/* ============================================================
   ARGUS 2.0 — Provider Configuration
   CRUD for LLM providers with API key management,
   health checks, and model discovery.
   ============================================================ */

import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";

/* ============================ Types ============================ */

export type ProviderStatus = "active" | "inactive" | "error";

export interface Provider {
  id: string;
  name: string;
  type: "openai" | "anthropic" | "ollama" | "azure" | "custom";
  endpoint?: string;
  apiKey?: string;
  status: ProviderStatus;
  models: string[];
  lastChecked?: Date;
}

export interface ProviderConfigProps {
  providers: Provider[];
  onAdd?: (provider: Omit<Provider, "id" | "status" | "models">) => Promise<void>;
  onUpdate?: (id: string, updates: Partial<Provider>) => Promise<void>;
  onDelete?: (id: string) => Promise<void>;
  onTest?: (id: string) => Promise<boolean>;
}

/* ============================ Metadata ============================ */

const PROVIDER_TYPES: Record<
  Provider["type"],
  { label: string; icon: string; defaultEndpoint: string }
> = {
  openai: { label: "OpenAI", icon: "🟢", defaultEndpoint: "https://api.openai.com/v1" },
  anthropic: { label: "Anthropic", icon: "🟠", defaultEndpoint: "https://api.anthropic.com" },
  ollama: { label: "Ollama", icon: "🦙", defaultEndpoint: "http://localhost:11434" },
  azure: { label: "Azure OpenAI", icon: "🔵", defaultEndpoint: "" },
  custom: { label: "Custom", icon: "⚙️", defaultEndpoint: "" },
};

const STATUS_META: Record<ProviderStatus, { label: string; dot: string; text: string }> = {
  active: { label: "Connected", dot: "bg-emerald-400", text: "text-emerald-400" },
  inactive: { label: "Inactive", dot: "bg-zinc-500", text: "text-zinc-400" },
  error: { label: "Error", dot: "bg-red-400", text: "text-red-400" },
};

/* ============================ Component ============================ */

export default function ProviderConfig({
  providers,
  onAdd,
  onUpdate,
  onDelete,
  onTest,
}: ProviderConfigProps) {
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
            LLM Providers
          </h3>
          <p className="mt-1 text-xs text-[var(--text-muted)]">
            Configure language model backends for ARGUS analysis
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowAdd(!showAdd)}
          className="flex items-center gap-1.5 rounded-md bg-[var(--accent-primary)]/10 px-3 py-1.5 text-xs font-medium text-[var(--accent-primary)] hover:bg-[var(--accent-primary)]/20"
        >
          <span>+</span>
          Add Provider
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
            <AddProviderForm
              onSubmit={async (p) => {
                await onAdd?.(p);
                setShowAdd(false);
              }}
              onCancel={() => setShowAdd(false)}
            />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Provider List */}
      <div className="space-y-2">
        {providers.length === 0 && (
          <div className="rounded-lg border border-dashed border-[var(--border-subtle)] p-6 text-center">
            <p className="text-xs text-[var(--text-muted)]">
              No providers configured. Add one to get started.
            </p>
          </div>
        )}
        {providers.map((provider) => (
          <ProviderCard
            key={provider.id}
            provider={provider}
            expanded={expanded === provider.id}
            onToggle={() => toggleExpand(provider.id)}
            onUpdate={(updates) => onUpdate?.(provider.id, updates)}
            onDelete={() => onDelete?.(provider.id)}
            onTest={onTest ? () => onTest(provider.id) : async () => false}
          />
        ))}
      </div>
    </div>
  );
}

/* ============================ Provider Card ============================ */

function ProviderCard({
  provider,
  expanded,
  onToggle,
  onUpdate,
  onDelete,
  onTest,
}: {
  provider: Provider;
  expanded: boolean;
  onToggle: () => void;
  onUpdate: (updates: Partial<Provider>) => Promise<void> | undefined;
  onDelete: () => Promise<void> | undefined;
  onTest: () => Promise<boolean>;
}) {
  const meta = PROVIDER_TYPES[provider.type];
  const status = STATUS_META[provider.status];
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [endpoint, setEndpoint] = useState(provider.endpoint || "");
  const [apiKey, setApiKey] = useState(provider.apiKey || "");

  useEffect(() => {
    setEndpoint(provider.endpoint || "");
    setApiKey(provider.apiKey || "");
  }, [provider.endpoint, provider.apiKey]);

  const handleTest = async () => {
    setTesting(true);
    try {
      await onTest();
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    setActionError(null);
    try {
      await onUpdate({ endpoint, apiKey });
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : "Não foi possível salvar o provider.");
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
      setActionError(cause instanceof Error ? cause.message : "Não foi possível excluir o provider.");
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
              {provider.name}
            </span>
            <span className="text-xs text-[var(--text-muted)]">({meta.label})</span>
          </div>
          {provider.endpoint && (
            <span className="truncate font-mono text-[10px] text-[var(--text-muted)]">
              {provider.endpoint}
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
                <label htmlFor={`provider-endpoint-${provider.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Endpoint
                </label>
                <input
                  id={`provider-endpoint-${provider.id}`}
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
                  placeholder={meta.defaultEndpoint}
                />
              </div>

              {/* API Key */}
              <div>
                <label htmlFor={`provider-key-${provider.id}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  API Key
                </label>
                <input
                  id={`provider-key-${provider.id}`}
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
                  placeholder="sk-..."
                />
              </div>

              {/* Models */}
              <div>
                <label className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
                  Available Models
                </label>
                <div className="flex flex-wrap gap-1">
                  {provider.models.map((model) => (
                    <span
                      key={model}
                      className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-3)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]"
                    >
                      {model}
                    </span>
                  ))}
                  {provider.models.length === 0 && (
                    <span className="text-[10px] italic text-[var(--text-muted)]">
                      No models discovered
                    </span>
                  )}
                </div>
              </div>

              {/* Actions */}
              {actionError && <p role="alert" className="text-[10px] text-red-300">{actionError}</p>}
              <div className="flex items-center justify-between pt-2">
                <div className="flex gap-2"><button
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
                  {testing ? "Testing..." : "Test Connection"}
                </button><button type="button" onClick={() => void handleSave()} disabled={saving} className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">{saving ? "Salvando…" : "Salvar alterações"}</button></div>
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

/* ============================ Add Provider Form ============================ */

function AddProviderForm({
  onSubmit,
  onCancel,
}: {
  onSubmit: (provider: Omit<Provider, "id" | "status" | "models">) => Promise<void>;
  onCancel: () => void;
}) {
  const [name, setName] = useState("");
  const [type, setType] = useState<Provider["type"]>("openai");
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
      await onSubmit({ name: name.trim(), type, endpoint: endpoint || PROVIDER_TYPES[type].defaultEndpoint, apiKey });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível adicionar o provider.");
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
        Add New Provider
      </h4>
      <div className="grid grid-cols-2 gap-3">
        {/* Name */}
        <div>
          <label htmlFor="new-provider-name" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Name
          </label>
          <input
            id="new-provider-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder="My OpenAI"
            autoFocus
          />
        </div>

        {/* Type */}
        <div>
          <label htmlFor="new-provider-type" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Type
          </label>
          <select
            id="new-provider-type"
            value={type}
            onChange={(e) => setType(e.target.value as Provider["type"])}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
          >
            {Object.entries(PROVIDER_TYPES).map(([key, meta]) => (
              <option key={key} value={key}>
                {meta.icon} {meta.label}
              </option>
            ))}
          </select>
        </div>

        {/* Endpoint */}
        <div className="col-span-2">
          <label htmlFor="new-provider-endpoint" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Endpoint
          </label>
          <input
            id="new-provider-endpoint"
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder={PROVIDER_TYPES[type].defaultEndpoint}
          />
        </div>

        {/* API Key */}
        <div className="col-span-2">
          <label htmlFor="new-provider-key" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            API Key
          </label>
          <input
            id="new-provider-key"
            type="password"
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:border-[var(--accent-primary)] focus:outline-none"
            placeholder="sk-..."
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
          {saving ? "Adicionando…" : "Add Provider"}
        </button>
      </div>
    </form>
  );
}

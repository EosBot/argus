"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import ProviderConfig from "./ProviderConfig";
import type { Provider } from "./ProviderConfig";
import ConnectionManager from "./ConnectionManager";
import type { ToolConnection } from "./ConnectionManager";
import ModelSelector from "./ModelSelector";
import type { Model } from "./ModelSelector";
import ToolConfig from "./ToolConfig";
import type { Tool } from "./ToolConfig";
import OpsecConfig from "./OpsecConfig";
import UserManager from "./UserManager";
import type { User } from "./UserManager";
import { apiFetch } from "../../lib/api";

/* ============================================================
   Types
   ============================================================ */

export type SettingsTab =
  | "providers"
  | "connections"
  | "models"
  | "tools"
  | "opsec"
  | "users"
  | "help";

export interface SettingsPanelProps {
  initialTab?: SettingsTab;
  onClose?: () => void;
  /** Callback disparado quando o modelo ativo muda (usado pelo terminal). */
  onActiveModelChange?: (model: string) => void;
}

const TABS: { key: SettingsTab; label: string; icon: string }[] = [
  { key: "providers", label: "Providers", icon: "⚡" },
  { key: "connections", label: "Connections", icon: "🔌" },
  { key: "models", label: "Models", icon: "🤖" },
  { key: "tools", label: "Tools", icon: "🛠️" },
  { key: "opsec", label: "OPSEC", icon: "🔒" },
  { key: "users", label: "Users", icon: "👥" },
  { key: "help", label: "Como Funciona", icon: "?" },
];

/* ============================================================
   API helpers
   ============================================================ */

interface ActiveConfig {
  providerId: string | null;
  model: string | null;
}

async function fetchJson<T>(path: string, init?: RequestInit, ms = 8000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await apiFetch<T>(path, {
      ...init,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...init?.headers },
    });
  } finally {
    clearTimeout(timer);
  }
}

/* ============================================================
   Component
   ============================================================ */

export default function SettingsPanel({
  initialTab = "providers",
  onClose,
  onActiveModelChange,
}: SettingsPanelProps) {
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [activeConfig, setActiveConfig] = useState<ActiveConfig>({
    providerId: null,
    model: null,
  });
  const [mode, setMode] = useState<"basic" | "advanced">("basic");
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState<string | null>(null);
  const [connections, setConnections] = useState<ToolConnection[]>([]);
  const [selectedModels, setSelectedModels] = useState<Record<string, string>>(
    {},
  );
  const [tools, setTools] = useState<Tool[]>([]);
  const [opsecSettings, setOpsecSettings] = useState({
    torProxy: "socks5://127.0.0.1:9050",
    socksPort: 9050,
    httpPort: 8118,
    rateLimitPerMinute: 30,
    userAgentRotation: true,
    requestDelay: 1500,
    maxConcurrentRequests: 5,
    enableDnsLeakProtection: true,
    enableWebRtcLeakProtection: true,
    clearCookiesOnExit: true,
  });
  const [users, setUsers] = useState<User[]>([]);
  const [currentUserId, setCurrentUserId] = useState("");
  const [currentRole, setCurrentRole] = useState<string | null>(null);

  // Ref para evitar re-fetch quando onActiveModelChange muda
  const onActiveModelChangeRef = useRef(onActiveModelChange);
  onActiveModelChangeRef.current = onActiveModelChange;

  /* ---------- Fetch com timeout (reutilizado pelos handlers) ---------- */

  /* ---------- Carregamento inicial ---------- */

  useEffect(() => {
    let cancelled = false;
    void fetchJson<{ id: string; role: string }>("/api/auth/me")
      .then((me) => {
        if (!cancelled) {
          setCurrentUserId(me.id);
          setCurrentRole(me.role);
          if (me.role !== "admin" && !["tools", "help"].includes(activeTab)) setActiveTab("tools");
        }
      })
      .catch(() => { if (!cancelled) setCurrentRole("unknown"); });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const data = await fetchJson<{
          providers: Provider[];
          active: ActiveConfig;
        }>("/api/providers");
        if (cancelled) return;
        // Normaliza lastChecked (API retorna string ISO)
        const normalized: Provider[] = data.providers.map((p) => ({
          ...p,
          lastChecked: p.lastChecked
            ? new Date(p.lastChecked as unknown as string)
            : undefined,
        }));
        setProviders(normalized);
        setActiveConfig(data.active);
        if (data.active.model) {
          onActiveModelChangeRef.current?.(data.active.model);
        }
      } catch {
        if (cancelled) return;
        setProviders([]);
        setApiError("Backend indisponível — nenhum provider foi carregado");
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const loadOperations = async () => {
      try {
        const [settings, catalog] = await Promise.all([
          fetchJson<{ mode?: "basic" | "advanced"; task_models?: Record<string, string>; opsec?: typeof opsecSettings; connections?: ToolConnection[] }>("/api/operations/settings"),
          fetchJson<{ items: Array<Tool & { category: string }> }>("/api/operations/tools"),
        ]);
        if (cancelled) return;
        if (settings.mode) setMode(settings.mode);
        setSelectedModels(settings.task_models ?? {});
        if (settings.opsec) setOpsecSettings((prev) => ({ ...prev, ...settings.opsec }));
        setConnections((settings.connections ?? []).map((connection) => ({ ...connection, lastSync: connection.lastSync ? new Date(connection.lastSync as unknown as string) : undefined })));
        const categoryMap: Record<string, Tool["category"]> = {
          dark_web: "collection", osint: "collection", people: "collection",
          infra: "exploitation", forensic: "analysis", crypto: "analysis",
          threat_intel: "analysis", report: "reporting",
        };
        setTools(catalog.items.map((tool) => ({ ...tool, category: categoryMap[tool.category] ?? "analysis" })));
      } catch (cause) {
        if (!cancelled) setApiError(cause instanceof Error ? `${cause.message}. Configurações operacionais não foram carregadas.` : "Configurações operacionais indisponíveis");
      }
    };
    void loadOperations();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const loadUsers = async () => {
      try {
        const [response, me] = await Promise.all([
          fetchJson<{ items: Array<{ id: string; username: string; email: string; role: User["role"]; is_active: boolean }> }>("/api/users"),
          fetchJson<{ id: string }>("/api/auth/me"),
        ]);
        if (cancelled) return;
        setCurrentUserId(me.id);
        setUsers(response.items.map((user) => ({ id: user.id, name: user.username, email: user.email, role: user.role, status: user.is_active ? "active" : "inactive" })));
      } catch {
        if (!cancelled) setUsers([]);
      }
    };
    void loadUsers();
    return () => { cancelled = true; };
  }, []);

  const persistOperations = useCallback(async (updates: Record<string, unknown>) => {
    if (currentRole !== "admin") {
      setApiError("Somente administradores podem alterar configurações globais.");
      return false;
    }
    try {
      await fetchJson("/api/operations/settings", { method: "PUT", body: JSON.stringify(updates) });
      setApiError(null);
      return true;
    } catch (cause) {
      setApiError(cause instanceof Error ? `${cause.message}. A alteração não foi persistida.` : "Falha ao salvar configuração");
      return false;
    }
  }, [currentRole]);

  /* ---------- Handlers de providers ---------- */

  const handleProviderAdd = useCallback(
    async (provider: Omit<Provider, "id" | "status" | "models">) => {
      try {
        const created = await fetchJson<Provider>("/api/providers", {
          method: "POST",
          body: JSON.stringify(provider),
        });
        setProviders((prev) => [...prev, created]);
        setApiError(null);
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error("Erro ao salvar provider no backend");
        setApiError(error.message);
        throw error;
      }
    },
    [],
  );

  const handleProviderUpdate = useCallback(
    async (id: string, updates: Partial<Provider>) => {
      try {
        const updated = await fetchJson<Provider>(`/api/providers/${id}`, {
          method: "PUT",
          body: JSON.stringify(updates),
        });
        setProviders((prev) => prev.map((p) => (p.id === id ? { ...p, ...updated } : p)));
        setApiError(null);
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error("Erro ao atualizar provider no backend");
        setApiError(error.message);
        throw error;
      }
    },
    [],
  );

  const handleProviderDelete = useCallback(
    async (id: string) => {
      try {
        await fetchJson(`/api/providers/${id}`, { method: "DELETE" });
        setProviders((prev) => prev.filter((p) => p.id !== id));
        if (activeConfig.providerId === id) {
          setActiveConfig({ providerId: null, model: null });
          onActiveModelChangeRef.current?.("auto");
        }
        setApiError(null);
      } catch (cause) {
        const error = cause instanceof Error ? cause : new Error("Erro ao excluir provider no backend");
        setApiError(error.message);
        throw error;
      }
    },
    [activeConfig.providerId],
  );

  const handleProviderTest = useCallback(
    async (id: string): Promise<boolean> => {
      const provider = providers.find((p) => p.id === id);
      if (!provider?.endpoint) {
        setProviders((prev) =>
          prev.map((p) => (p.id === id ? { ...p, status: "error" } : p)),
        );
        return false;
      }
      // Tenta via API do backend
      try {
        const result = await fetchJson<{ ok: boolean; provider: Provider }>(
          `/api/providers/${id}/test`,
          { method: "POST" },
        );
        setProviders((prev) =>
          prev.map((p) => (p.id === id ? { ...p, ...result.provider } : p)),
        );
        return result.ok;
      } catch {
        setProviders((prev) => prev.map((p) => p.id === id ? { ...p, status: "error", lastChecked: new Date() } : p));
        setApiError("O backend não conseguiu testar o provider; a chave não foi enviada pelo navegador ao endpoint externo.");
        return false;
      }
    },
    [providers],
  );

  const handleSetActiveProvider = useCallback(
    async (providerId: string | null, model: string | null) => {
      try {
        const result = await fetchJson<{ active: ActiveConfig }>(
          "/api/providers/active",
          {
            method: "PUT",
            body: JSON.stringify({ providerId, model }),
          },
        );
        setActiveConfig(result.active);
        onActiveModelChangeRef.current?.(result.active.model || "auto");
      } catch {
        setApiError("Erro ao definir provider ativo no backend");
        throw new Error("Erro ao definir provider ativo no backend");
      }
    },
    [],
  );

  /* ---------- Handlers de connections ---------- */

  const handleConnectionAdd = useCallback(async (
    connection: Omit<ToolConnection, "id" | "status" | "capabilities">,
  ) => {
    const next = [...connections, {
      ...connection,
      id: `c-${crypto.randomUUID()}`,
      status: "disconnected" as const,
      capabilities: [],
    }];
    if (!await persistOperations({ connections: next })) throw new Error("A conexão não foi salva");
    setConnections(next);
  }, [connections, persistOperations]);

  const handleConnectionUpdate = useCallback(async (id: string, updates: Partial<ToolConnection>) => {
    const next = connections.map((connection) => connection.id === id ? { ...connection, ...updates } : connection);
    if (!await persistOperations({ connections: next })) throw new Error("A conexão não foi atualizada");
    setConnections(next);
  }, [connections, persistOperations]);

  const handleConnectionDelete = useCallback(async (id: string) => {
    const next = connections.filter((connection) => connection.id !== id);
    if (!await persistOperations({ connections: next })) throw new Error("A conexão não foi excluída");
    setConnections(next);
  }, [connections, persistOperations]);

  const handleConnectionTest = useCallback(
    async (id: string): Promise<boolean> => {
      const conn = connections.find((c) => c.id === id);
      if (!conn?.endpoint) {
        setConnections((prev) =>
          prev.map((c) => (c.id === id ? { ...c, status: "error" } : c)),
        );
        return false;
      }
      try {
        const result = await fetchJson<{ ok: boolean }>("/api/operations/connections/test", { method: "POST", body: JSON.stringify({ id: conn.id, type: conn.type, endpoint: conn.endpoint, apiKey: conn.apiKey }) });
        const ok = result.ok;
        setConnections((prev) =>
          prev.map((c) =>
            c.id === id ? { ...c, status: ok ? "connected" : "error" } : c,
          ),
        );
        return ok;
      } catch {
        setConnections((prev) =>
          prev.map((c) => (c.id === id ? { ...c, status: "error" } : c)),
        );
        return false;
      }
    },
    [connections],
  );

  const handleConnectionSync = useCallback(
    async (id: string): Promise<void> => {
      const conn = connections.find((c) => c.id === id);
      if (!conn?.endpoint) return;
      try {
        const result = await fetchJson<{ ok: boolean }>("/api/operations/connections/test", { method: "POST", body: JSON.stringify({ id: conn.id, type: conn.type, endpoint: conn.endpoint, apiKey: conn.apiKey }) });
        const ok = result.ok;
        const caps =
          conn.type === "shodan"
            ? ["host-lookup", "port-scan", "vuln-search"]
            : conn.type === "virustotal"
              ? ["url-scan", "file-scan", "domain-report"]
              : conn.type === "censys"
                ? ["host-search", "cert-search"]
                : conn.type === "abuseipdb"
                  ? ["ip-check"]
                  : conn.type === "otx"
                    ? ["pulse-search", "ioc-lookup"]
                    : conn.capabilities;
        const next = connections.map((c) => c.id === id ? {
          ...c,
          status: ok ? ("connected" as const) : ("error" as const),
          lastSync: new Date(),
          capabilities: ok ? caps : c.capabilities,
        } : c);
        if (!await persistOperations({ connections: next })) throw new Error("A sincronização não foi persistida");
        setConnections(next);
      } catch (cause) {
        setConnections((prev) =>
          prev.map((c) => (c.id === id ? { ...c, status: "error" } : c)),
        );
        throw cause;
      }
    },
    [connections, persistOperations],
  );

  /* ---------- Handlers de tools / models / opsec / users ---------- */

  const handleToolToggle = async (id: string, enabled: boolean) => {
    if (!await persistOperations({ tools: { [id]: { enabled } } })) throw new Error("A alteração da ferramenta não foi persistida");
    setTools((prev) => prev.map((t) => (t.id === id ? { ...t, enabled } : t)));
  };

  const handleModelSelect = async (taskType: string, modelId: string) => {
    const next = { ...selectedModels, [taskType]: modelId };
    if (!await persistOperations({ task_models: next })) throw new Error("A seleção de modelo não foi persistida");
    setSelectedModels(next);
  };

  /* ---------- Render ---------- */

  return (
    <div className="flex h-full flex-col bg-[var(--surface-1)]">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-4 py-3">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[var(--accent-primary)]/10 text-[var(--accent-primary)]">
            ⚙️
          </div>
          <div>
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Settings
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              Configure providers, tools, and system preferences
            </p>
          </div>
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="Fechar configurações"
            className="rounded-md p-1.5 text-[var(--text-muted)] hover:bg-[var(--surface-2)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent-primary)]"
          >
            <svg
              viewBox="0 0 16 16"
              className="h-4 w-4"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
            </svg>
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[var(--border-subtle)] px-4 overflow-x-auto">
        {TABS.filter((tab) => currentRole === null || currentRole === "admin" || tab.key === "tools" || tab.key === "help").map((tab) => (
          <button
            key={tab.key}
            type="button"
            onClick={() => setActiveTab(tab.key)}
            className={`relative flex items-center gap-2 px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors ${
              activeTab === tab.key
                ? "text-[var(--accent-primary)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
            }`}
          >
            <span className="text-sm">{tab.icon}</span>
            {tab.label}
            {activeTab === tab.key && (
              <motion.div
                layoutId="settings-tab-indicator"
                className="absolute bottom-0 left-0 right-0 h-0.5 bg-[var(--accent-primary)]"
                transition={{ duration: 0.2 }}
              />
            )}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3 border-b border-[var(--border-subtle)] px-4 py-2">
        <span className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">Detalhamento</span>
        <div className="flex rounded-lg bg-[var(--surface-2)] p-0.5" role="group" aria-label="Nível de detalhamento das configurações">
          {(["basic", "advanced"] as const).map((value) => (
            <button key={value} type="button" aria-pressed={mode === value} disabled={currentRole !== "admin"} title={currentRole === "admin" ? undefined : "Aguardando permissão administrativa"} onClick={() => { void persistOperations({ mode: value }).then((saved) => { if (saved) setMode(value); }); }} className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${mode === value ? "bg-[var(--accent-primary)] text-white" : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"}`}>
              {value === "basic" ? "Básico" : "Avançado"}
            </button>
          ))}
        </div>
        {apiError && <span role="status" className="text-[10px] text-amber-400">{apiError}</span>}
        {loading && <span className="text-[10px] text-[var(--text-muted)]">Carregando…</span>}
      </div>

      {currentRole && currentRole !== "admin" && (
        <div className="border-b border-[var(--border-subtle)] bg-amber-500/5 px-4 py-2 text-[11px] text-amber-300">
          Perfil investigador: execução autorizada de ferramentas disponível; configurações globais são administradas por um administrador.
        </div>
      )}

      {/* Content */}
      <div className="min-h-0 flex-1 overflow-y-auto p-4">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeTab}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.15 }}
          >
            {activeTab === "providers" && (
              <div className="space-y-4">
                {/* Seletor de Provider Ativo + Modelo */}
                <ActiveProviderSelector
                  providers={providers}
                  activeConfig={activeConfig}
                  onSetActive={handleSetActiveProvider}
                />

                {/* Modo avançado: lista completa de providers */}
                {mode === "advanced" && (
                  <ProviderConfig
                    providers={providers}
                    onAdd={handleProviderAdd}
                    onUpdate={handleProviderUpdate}
                    onDelete={handleProviderDelete}
                    onTest={handleProviderTest}
                  />
                )}
              </div>
            )}

            {activeTab === "connections" && (
              <ConnectionManager
                connections={connections}
                onAdd={handleConnectionAdd}
                onUpdate={handleConnectionUpdate}
                onDelete={handleConnectionDelete}
                onTest={handleConnectionTest}
                onSync={handleConnectionSync}
              />
            )}

            {activeTab === "models" && (
              <ModelSelector
                models={providers.flatMap((provider) => provider.models.map((name, index) => ({ id: `${provider.id}-${index}`, name, provider: provider.name, capabilities: ["general"] as Model["capabilities"], contextWindow: 0, costPer1kTokens: 0 })))}
                selectedModels={selectedModels}
                onSelect={handleModelSelect}
              />
            )}

            {activeTab === "tools" && (
              <ToolConfig
                tools={tools}
                onToggle={handleToolToggle}
                onConfigure={async (id, params) => {
                  const enabled = tools.find((tool) => tool.id === id)?.enabled ?? false;
                  if (!await persistOperations({ tools: { [id]: { enabled, parameters: params } } })) {
                    throw new Error("A configuração da ferramenta não foi persistida");
                  }
                  setTools((prev) => prev.map((tool) => tool.id === id ? { ...tool, parameters: { ...tool.parameters, ...params } } : tool));
                }}
                onExecute={async (id, target, investigationId, authorized) => {
                  const response = await fetchJson<{ task_id: string; status: string; implementation?: string; result?: Record<string, unknown> }>(`/api/operations/tools/${id}/execute`, { method: "POST", body: JSON.stringify({ target, investigation_id: investigationId || null, authorized }) });
                  const summary = `Task ${response.task_id} · ${response.status}${response.implementation ? ` · ${response.implementation}` : ""}`;
                  return response.result ? `${summary}\n${JSON.stringify(response.result, null, 2)}` : summary;
                }}
              />
            )}

            {activeTab === "opsec" && (
              <OpsecConfig
                settings={opsecSettings}
                onSave={async (next) => {
                  const saved = await persistOperations({ opsec: next });
                  if (saved) setOpsecSettings(next);
                  return saved;
                }}
              />
            )}

            {activeTab === "users" && (
              <UserManager
                users={users}
                currentUserId={currentUserId}
                onAdd={async (user) => {
                  const created = await fetchJson<{ id: string; username: string; email: string; role: User["role"]; is_active: boolean; temporary_password: string }>("/api/users", { method: "POST", body: JSON.stringify({ username: user.name, email: user.email, role: user.role }) });
                  setUsers((prev) => [...prev, { id: created.id, name: created.username, email: created.email, role: created.role, status: "active" }]);
                  return created.temporary_password;
                }}
                onUpdate={async (id, updates) => {
                  const payload = { email: updates.email, role: updates.role, is_active: updates.status ? updates.status === "active" : undefined };
                  await fetchJson(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify(payload) });
                  setUsers((prev) => prev.map((user) => user.id === id ? { ...user, ...updates } : user));
                }}
                onDelete={async (id) => { await fetchJson(`/api/users/${id}`, { method: "DELETE" }); setUsers((prev) => prev.filter((user) => user.id !== id)); }}
              />
            )}

            {activeTab === "help" && (
              <section className="space-y-4" aria-labelledby="help-title">
                <div><h3 id="help-title" className="text-sm font-semibold text-[var(--text-primary)]">Do objetivo à evidência</h3><p className="mt-1 text-xs text-[var(--text-muted)]">O ARGUS separa coleta passiva de ações ativas para preservar contexto, autorização e rastreabilidade.</p></div>
                {[
                  ["1", "Crie uma investigação", "Use Investigations para abrir o caso que receberá achados e evidências."],
                  ["2", "Inicie a coleta", "Descreva o objetivo em Collection. Os agentes consultam fontes e devolvem resultados ao caso."],
                  ["3", "Revise as fontes", "Confirme origem, conteúdo e confiança antes de promover um resultado a achado."],
                  ["4", "Autorize ações ativas", "Exploitation exige selecionar uma investigação e confirmar explicitamente o escopo."],
                  ["5", "Exporte a evidência", "Preserve hashes, timestamps, fontes e histórico antes de compartilhar."],
                ].map(([step, title, body]) => <article key={step} className="grid grid-cols-[2rem_1fr] gap-3 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3"><span className="font-mono text-xs text-[var(--accent-primary)]">{step}</span><div><h4 className="text-xs font-medium text-[var(--text-primary)]">{title}</h4><p className="mt-1 text-[11px] leading-relaxed text-[var(--text-muted)]">{body}</p></div></article>)}
              </section>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

/* ============================================================
   Active Provider Selector
   ============================================================ */

function ActiveProviderSelector({
  providers,
  activeConfig,
  onSetActive,
}: {
  providers: Provider[];
  activeConfig: ActiveConfig;
  onSetActive: (providerId: string | null, model: string | null) => Promise<void>;
}) {
  const selectedProvider = providers.find(
    (p) => p.id === activeConfig.providerId,
  );
  const availableModels = selectedProvider?.models ?? [];
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const saveActive = (providerId: string | null, model: string | null) => {
    setSaving(true);
    setError(null);
    void onSetActive(providerId, model)
      .catch((cause) => setError(cause instanceof Error ? cause.message : "Falha ao definir provider"))
      .finally(() => setSaving(false));
  };

  return (
    <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-4">
      <div className="mb-3 flex items-center gap-2">
        <span className="text-sm">⚡</span>
        <h4 className="text-xs font-semibold text-[var(--text-primary)]">
          Provider Ativo + Modelo
        </h4>
        <span className="text-[10px] text-[var(--text-muted)]">
          (usado pelo terminal)
        </span>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {/* Provider */}
        <div>
          <label htmlFor="active-provider" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Provider
          </label>
          <select
            id="active-provider"
            value={activeConfig.providerId ?? ""}
            onChange={(e) => {
              const providerId = e.target.value || null;
              const provider = providers.find((p) => p.id === providerId);
              const model = provider?.models[0] ?? null;
              saveActive(providerId, model);
            }}
            disabled={saving}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
          >
            <option value="">— Nenhum —</option>
            {providers.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} ({p.type})
              </option>
            ))}
          </select>
        </div>

        {/* Modelo */}
        <div>
          <label htmlFor="active-model" className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
            Modelo
          </label>
          <select
            id="active-model"
            value={activeConfig.model ?? ""}
            onChange={(e) => {
              const model = e.target.value || null;
              saveActive(activeConfig.providerId, model);
            }}
            disabled={saving || !activeConfig.providerId}
            className="w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none disabled:opacity-50"
          >
            <option value="">— auto —</option>
            {availableModels.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
      </div>
      {error && <p role="alert" className="mt-2 text-[10px] text-red-300">{error}</p>}

      {/* Status do provider ativo */}
      {selectedProvider ? (
        <div className="mt-3 flex items-center gap-2 border-t border-[var(--border-subtle)] pt-3">
          <span
            className={`h-2 w-2 rounded-full ${
              selectedProvider.status === "active"
                ? "bg-emerald-400"
                : selectedProvider.status === "error"
                  ? "bg-red-400"
                  : "bg-zinc-500"
            }`}
          />
          <span className="truncate font-mono text-[10px] text-[var(--text-muted)]">
            {selectedProvider.endpoint}
          </span>
          <span className="text-[10px] text-[var(--text-muted)]">·</span>
          <span className="text-[10px] text-[var(--text-secondary)]">
            {activeConfig.model ?? "auto"}
          </span>
        </div>
      ) : (
        <div className="mt-3 border-t border-[var(--border-subtle)] pt-3">
          <span className="text-[10px] text-[var(--text-muted)]">
            Nenhum provider ativo — terminal usará &quot;auto&quot;
          </span>
        </div>
      )}
    </div>
  );
}

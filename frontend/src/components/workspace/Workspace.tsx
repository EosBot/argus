"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { useTheme } from "../ThemeProvider";
import { useKeyboardShortcuts } from "../../hooks/useKeyboardShortcuts";
import { createShortcuts } from "../../config/shortcuts";
import InvestigationTree from "../sidebar/InvestigationTree";
import ScanCard from "../cards/ScanCard";
import CommandPalette from "../notifications/CommandPalette";
import ToastContainer from "../notifications/ToastContainer";
import SettingsPanel from "../settings/SettingsPanel";
import { useInvestigations } from "../../hooks/useInvestigations";
import { useAuth } from "../../hooks/useAuth";
import { apiFetch } from "../../lib/api";
import { getAccessToken } from "../../lib/auth";
import CollectionPanel from "./CollectionPanel";
import ExploitationPanel from "./ExploitationPanel";
import SafeBrowserPanel from "./SafeBrowserPanel";
import NewInvestigationDialog from "./NewInvestigationDialog";
import WorkspaceGuide from "./WorkspaceGuide";
import styles from "./Workspace.module.css";

const TerminalPane = dynamic(() => import("../terminal/TerminalPane"), {
  ssr: false,
  loading: () => <div className={styles.terminalLoading}>Loading terminal...</div>,
});

/* ============================================================
   Types + constants
   ============================================================ */

export type PanelType = "sidebar" | "terminal" | "agent-status" | "inspector" | "collection" | "exploitation" | "browser";

export interface PanelConfig {
  id: string;
  type: PanelType;
  title: string;
  /** Width as a percentage of the workspace row (0–100). */
  width: number;
  visible: boolean;
}

export interface WorkspaceLayout {
  panels: PanelConfig[];
}

const STORAGE_KEY = "argus.workspace.layout.v1";
const MIN_PANELS = 2;
const MAX_PANELS = 6;
const MIN_WIDTH = 12;

const DEFAULT_LAYOUT: WorkspaceLayout = {
  panels: [
    { id: "sidebar", type: "sidebar", title: "Investigations", width: 20, visible: true },
    { id: "terminal", type: "terminal", title: "Terminal", width: 50, visible: true },
    { id: "agent-status", type: "agent-status", title: "Agent Status", width: 20, visible: true },
    { id: "inspector", type: "inspector", title: "Inspector", width: 10, visible: false },
    { id: "collection", type: "collection", title: "Collection", width: 20, visible: false },
    { id: "exploitation", type: "exploitation", title: "Exploitation", width: 20, visible: false },
    { id: "browser", type: "browser", title: "Safe Browser", width: 30, visible: false },
  ],
};

const PANEL_TYPES: ReadonlyArray<{ type: PanelType; title: string }> = [
  { type: "sidebar", title: "Investigations" },
  { type: "terminal", title: "Terminal" },
  { type: "agent-status", title: "Agent Status" },
  { type: "inspector", title: "Inspector" },
  { type: "collection", title: "Collection" },
  { type: "exploitation", title: "Exploitation" },
  { type: "browser", title: "Safe Browser" },
];

/* ============================================================
   Helpers
   ============================================================ */

function loadLayout(): WorkspaceLayout {
  if (typeof window === "undefined") return DEFAULT_LAYOUT;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_LAYOUT;
    const parsed = JSON.parse(raw) as Partial<WorkspaceLayout>;
    if (!Array.isArray(parsed.panels) || parsed.panels.length < MIN_PANELS) {
      return DEFAULT_LAYOUT;
    }
    const panels = parsed.panels
      .filter(
        (p): p is PanelConfig =>
          p != null &&
          typeof p.id === "string" &&
          typeof p.type === "string" &&
          typeof p.width === "number" &&
          Number.isFinite(p.width),
      )
      .map((p) => ({
        ...p,
        title: typeof p.title === "string" ? p.title : p.type,
        width: Math.min(Math.max(p.width, MIN_WIDTH), 100),
        visible: p.visible !== false,
      }));
    if (panels.length < MIN_PANELS) return DEFAULT_LAYOUT;

    // Ensure all PANEL_TYPES exist in the layout (add missing ones)
    const existingTypes = new Set(panels.map((p) => p.type));
    const missingPanels = DEFAULT_LAYOUT.panels.filter(
      (p) => !existingTypes.has(p.type),
    );
    if (missingPanels.length > 0) {
      panels.push(...missingPanels.map((p) => ({ ...p })));
    }

    return { panels };
  } catch {
    return DEFAULT_LAYOUT;
  }
}

function cloneLayout(layout: WorkspaceLayout): WorkspaceLayout {
  return { panels: layout.panels.map((p) => ({ ...p })) };
}

interface ResizeState {
  index: number;
  startX: number;
  startWidths: number[];
}

/* ============================================================
   Panel content renderers
   ============================================================ */

function SidebarPanel({ investigations, onNewInvestigation, onSelect }: { investigations?: Parameters<typeof InvestigationTree>[0]["investigations"]; onNewInvestigation?: () => void; onSelect?: Parameters<typeof InvestigationTree>[0]["onSelect"] }) {
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <div style={{ padding: "8px", borderBottom: "1px solid var(--border-subtle)" }}>
        <button
          onClick={onNewInvestigation}
          style={{
            width: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "6px",
            padding: "8px 12px",
            borderRadius: "6px",
            border: "1px dashed var(--border-subtle)",
            background: "transparent",
            color: "var(--text-muted)",
            fontSize: "12px",
            cursor: "pointer",
            transition: "all 0.15s",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = "var(--surface-2)";
            e.currentTarget.style.color = "var(--text-primary)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = "transparent";
            e.currentTarget.style.color = "var(--text-muted)";
          }}
        >
          <span>+</span>
          New Investigation
        </button>
      </div>
      <div style={{ flex: 1, overflow: "auto" }}>
        <InvestigationTree investigations={investigations} onSelect={onSelect} />
      </div>
    </div>
  );
}

function TerminalPanel() {
  const token = getAccessToken();
  const { investigations, isLoading } = useInvestigations();
  const [investigationId, setInvestigationId] = useState(() => {
    if (typeof window === "undefined") return "";
    return window.localStorage.getItem("argus:terminal-investigation") || "";
  });
  useEffect(() => {
    if (investigationId) window.localStorage.setItem("argus:terminal-investigation", investigationId);
    else window.localStorage.removeItem("argus:terminal-investigation");
  }, [investigationId]);
  const protocol = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss" : "ws";
  return (
    <div style={{ height: "100%", display: "flex", flexDirection: "column" }}>
      <label style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", borderBottom: "1px solid var(--border-subtle)", fontSize: 11, color: "var(--text-muted)" }}>
        Caso para evidências
        <select value={investigationId} onChange={(event) => setInvestigationId(event.target.value)} disabled={isLoading} aria-label="Investigação do terminal" style={{ flex: 1, minWidth: 0, background: "var(--surface-2)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)", borderRadius: 4, padding: "4px 6px", fontFamily: "var(--font-mono)" }}>
          <option value="">{isLoading ? "Carregando casos…" : "Selecione antes de pesquisar"}</option>
          {investigations.map((investigation) => <option key={investigation.id} value={investigation.id}>{investigation.title}</option>)}
        </select>
      </label>
      <TerminalPane
        wsUrl={`${protocol}://${process.env.NEXT_PUBLIC_WS_URL?.replace(/^wss?:\/\//, "") || "localhost:8000"}/ws/v1/terminal?token=${encodeURIComponent(token ?? "")}`}
        title="argus-terminal"
        height="100%"
        investigationId={investigationId}
      />
    </div>
  );
}

function AgentStatusPanel() {
  const [agents, setAgents] = useState<Array<{ name: string; description: string; status: string; task_id?: string; error?: string }>>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const data = await apiFetch<{ items: typeof agents }>("/api/operations/agents/status");
        if (active) { setAgents(data.items); setError(null); }
      } catch (cause) {
        if (active) setError(cause instanceof Error ? cause.message : "Falha ao consultar agentes");
      }
    };
    void load();
    const timer = window.setInterval(load, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 12,
        padding: 12,
        overflow: "auto",
        height: "100%",
      }}
    >
      {error && <div role="status" className="rounded-lg border border-red-500/30 p-3 text-xs text-red-300">{error}. Verifique o backend.</div>}
      {!error && agents.length === 0 && <div className="p-3 text-xs text-[var(--text-muted)]">Nenhum agente registrado.</div>}
      {agents.map((agent) => (
        <ScanCard
          key={agent.name}
          title={agent.name.replaceAll("_", " ")}
          status={agent.status === "running" ? "running" : agent.status === "completed" || agent.status === "done" ? "done" : "queue"}
          progress={agent.status === "completed" || agent.status === "done" ? 100 : agent.status === "running" ? 50 : 0}
          model={{ name: agent.task_id || "ready", type: "agent" }}
          output={agent.error || agent.description}
        />
      ))}
    </div>
  );
}

export interface ResearchEvent {
  query: string;
  results: number;
  status: string;
  ts?: number;
}

function InspectorPanel({ lastResearch }: { lastResearch?: ResearchEvent }) {
  useEffect(() => {
    if (document.getElementById("argus-inspector-kf")) return;
    const s = document.createElement("style");
    s.id = "argus-inspector-kf";
    s.textContent =
      "@keyframes argus-pulse{0%,100%{opacity:1}50%{opacity:0.3}}";
    document.head.appendChild(s);
  }, []);

  if (!lastResearch) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          height: "100%",
          padding: 12,
          background: "var(--surface-1)",
          borderLeft: "2px solid var(--accent-cyan)",
          color: "var(--text-muted)",
          fontFamily: "var(--font-mono)",
          fontSize: 12,
          letterSpacing: "0.05em",
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: "var(--status-neutral, #64748b)",
            flex: "none",
          }}
        />
        <span>AGUARDANDO PESQUISA</span>
      </div>
    );
  }

  const isSearching = lastResearch.status === "searching";
  const query =
    lastResearch.query.length > 60
      ? lastResearch.query.slice(0, 57) + "..."
      : lastResearch.query;
  const time = lastResearch.ts
    ? new Date(lastResearch.ts).toLocaleTimeString("pt-BR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "--:--:--";

  const ledColor = isSearching ? "var(--accent-amber)" : "var(--accent-green)";
  const statusLabel = isSearching ? "SEARCHING" : "DONE";

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 8,
        height: "100%",
        padding: 12,
        background: "var(--surface-1)",
        borderLeft: "2px solid var(--accent-cyan)",
        fontFamily: "var(--font-mono)",
        fontSize: 12,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: ledColor,
            boxShadow: `0 0 6px ${ledColor}`,
            flex: "none",
            animation: isSearching ? "argus-pulse 1s ease-in-out infinite" : "none",
          }}
        />
        <span
          style={{
            color: ledColor,
            letterSpacing: "0.05em",
            fontWeight: 600,
          }}
        >
          {statusLabel}
        </span>
      </div>

      <div
        style={{
          color: "var(--text-primary)",
          wordBreak: "break-all",
          lineHeight: 1.4,
        }}
      >
        {query}
      </div>

      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          color: "var(--text-muted)",
          fontSize: 11,
        }}
      >
        <span>{lastResearch.results} resultados</span>
        <span>{time}</span>
      </div>
    </div>
  );
}



function renderPanelContent(
  type: PanelType,
  investigations?: Parameters<typeof InvestigationTree>[0]["investigations"],
  onNewInvestigation?: () => void,
  lastResearch?: ResearchEvent,
  browserUrl?: string,
  onSelect?: Parameters<typeof InvestigationTree>[0]["onSelect"],
) {
  switch (type) {
    case "sidebar":
      return <SidebarPanel investigations={investigations} onNewInvestigation={onNewInvestigation} onSelect={onSelect} />;
    case "terminal":
      return <TerminalPanel />;
    case "agent-status":
      return <AgentStatusPanel />;
    case "inspector":
      return <InspectorPanel lastResearch={lastResearch} />;
    case "collection":
      return <CollectionPanel />;
    case "exploitation":
      return <ExploitationPanel />;
    case "browser":
      return <SafeBrowserPanel initialUrl={browserUrl} />;
    default:
      return null;
  }
}

/* ============================================================
   Workspace shell
   ============================================================ */

function WorkspaceShell() {
  const { user, logout } = useAuth();
  const [layout, setLayout] = useState<WorkspaceLayout>(DEFAULT_LAYOUT);
  const [mounted, setMounted] = useState(false);
  const [draggingId, setDraggingId] = useState<string | null>(null);
  const [dropTargetId, setDropTargetId] = useState<string | null>(null);
  const [resizeActive, setResizeActive] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [browserUrl, setBrowserUrl] = useState("");
  const [lastResearch, setLastResearch] = useState<ResearchEvent>();
  const [backendConnected, setBackendConnected] = useState(false);
  const [newInvestigationOpen, setNewInvestigationOpen] = useState(false);
  const [guideOpen, setGuideOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const resizeRef = useRef<ResizeState | null>(null);

  const handleTreeSelect = useCallback((node: import("../sidebar/InvestigationTree").TreeNode) => {
    if (node.type === "evidence") {
      window.dispatchEvent(new CustomEvent("argus:open-safe-browser", { detail: { url: node.title } }));
    }
  }, []);

  useEffect(() => {
    setLayout(loadLayout());
    setMounted(true);
  }, []);

  useEffect(() => {
    const openSafeBrowser = (event: Event) => {
      const url = (event as CustomEvent<{ url?: string }>).detail?.url;
      if (!url) return;
      setBrowserUrl(url);
      setLayout((prev) => ({ panels: prev.panels.map((panel) => panel.type === "browser" ? { ...panel, visible: true } : panel) }));
    };
    window.addEventListener("argus:open-safe-browser", openSafeBrowser);
    return () => window.removeEventListener("argus:open-safe-browser", openSafeBrowser);
  }, []);

  useEffect(() => {
    const updateResearch = (event: Event) => {
      const detail = (event as CustomEvent<ResearchEvent>).detail;
      if (detail?.query) setLastResearch(detail);
    };
    window.addEventListener("argus:research", updateResearch);
    return () => window.removeEventListener("argus:research", updateResearch);
  }, []);

  useEffect(() => {
    let active = true;
    const checkBackend = async () => {
      try {
        await apiFetch("/api/monitoring/health");
        if (active) setBackendConnected(true);
      } catch {
        if (active) setBackendConnected(false);
      }
    };
    void checkBackend();
    const timer = window.setInterval(checkBackend, 10_000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  /* ---------- Data hooks ---------- */
  const { investigations, createInvestigation } = useInvestigations();

  const exportWorkspace = useCallback(() => {
    const snapshot = { exportedAt: new Date().toISOString(), layout, investigations };
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `argus-workspace-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }, [investigations, layout]);

  /* ---------- Keyboard shortcuts ---------- */
  const { theme, setTheme, themes } = useTheme();
  const shortcuts = useMemo(
    () =>
      createShortcuts({
        focusSearch: () => {
          setCommandPaletteOpen(true);
        },
        newInvestigation: () => {
          setNewInvestigationOpen(true);
        },
        closeModal: () => {
          setCommandPaletteOpen(false);
          setSettingsOpen(false);
          setNewInvestigationOpen(false);
        },
        toggleSettings: () => {
          setSettingsOpen((prev) => !prev);
        },
        exportView: () => {
          exportWorkspace();
        },
        setTheme,
      }),
    [exportWorkspace, setTheme],
  );
  useKeyboardShortcuts(shortcuts);

  /* ---------- Persistence ---------- */
  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(layout));
    } catch {
      /* storage full / unavailable — layout stays in-memory */
    }
  }, [layout]);

  const visiblePanels = useMemo(() => layout.panels.filter((p) => p.visible), [layout.panels]);
  const visibleCount = visiblePanels.length;

  /* ---------- Panel visibility (2–4 panels) ---------- */
  const togglePanel = useCallback((type: PanelType) => {
    setLayout((prev) => {
      const count = prev.panels.filter((p) => p.visible).length;
      const target = prev.panels.find((p) => p.type === type);
      if (!target) return prev;
      const willShow = !target.visible;
      if (willShow && count >= MAX_PANELS) return prev;
      if (!willShow && count <= MIN_PANELS) return prev;
      return {
        panels: prev.panels.map((p) =>
          p.type === type ? { ...p, visible: willShow } : p,
        ),
      };
    });
  }, []);

  const resetLayout = useCallback(() => {
    setLayout(cloneLayout(DEFAULT_LAYOUT));
  }, []);

  /* ---------- Resize (pointer capture on handle) ---------- */
  const startResize = useCallback(
    (index: number) => (e: React.PointerEvent<HTMLDivElement>) => {
      e.preventDefault();
      resizeRef.current = {
        index,
        startX: e.clientX,
        startWidths: visiblePanels.map((p) => p.width),
      };
      setResizeActive(true);
      e.currentTarget.setPointerCapture(e.pointerId);
    },
    [visiblePanels],
  );

  const onResizeMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    const r = resizeRef.current;
    const container = containerRef.current;
    if (!r || !container) return;
    const rect = container.getBoundingClientRect();
    if (rect.width === 0) return;

    const deltaPct = ((e.clientX - r.startX) / rect.width) * 100;
    const left = r.startWidths[r.index];
    const right = r.startWidths[r.index + 1];
    if (left === undefined || right === undefined) return;

    let newLeft = Math.min(Math.max(left + deltaPct, MIN_WIDTH), 100 - MIN_WIDTH);
    let newRight = right - (newLeft - left);
    if (newRight < MIN_WIDTH) {
      newRight = MIN_WIDTH;
      newLeft = left + right - MIN_WIDTH;
    }

    setLayout((prev) => {
      const visible = prev.panels.filter((p) => p.visible);
      const updated = visible.map((p, i) => {
        if (i === r.index) return { ...p, width: newLeft };
        if (i === r.index + 1) return { ...p, width: newRight };
        return p;
      });
      let vi = 0;
      return { panels: prev.panels.map((p) => (p.visible ? updated[vi++] : p)) };
    });
  }, []);

  const endResize = useCallback(() => {
    resizeRef.current = null;
    setResizeActive(false);
  }, []);

  /* ---------- Drag-and-drop reordering ---------- */
  const onDragStart = useCallback(
    (id: string) => (e: React.DragEvent<HTMLDivElement>) => {
      setDraggingId(id);
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", id);
    },
    [],
  );

  const onDragOver = useCallback(
    (id: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      if (dropTargetId !== id) setDropTargetId(id);
    },
    [dropTargetId],
  );

  const onDrop = useCallback(
    (targetId: string) => (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      const sourceId = draggingId ?? e.dataTransfer.getData("text/plain");
      setDropTargetId(null);
      setDraggingId(null);
      if (!sourceId || sourceId === targetId) return;
      setLayout((prev) => {
        const panels = [...prev.panels];
        const si = panels.findIndex((p) => p.id === sourceId);
        const ti = panels.findIndex((p) => p.id === targetId);
        if (si < 0 || ti < 0) return prev;
        const [moved] = panels.splice(si, 1);
        panels.splice(ti, 0, moved);
        return { panels };
      });
    },
    [draggingId],
  );

  const onDragEnd = useCallback(() => {
    setDropTargetId(null);
    setDraggingId(null);
  }, []);

  /* ---------- Render ---------- */
  return (
    <div className={styles.workspace}>
      {/* Toolbar */}
      <div className={styles.toolbar}>
        <span className={styles.toolbarTitle}>ARGUS</span>
        {PANEL_TYPES.map(({ type, title }) => {
          const active = layout.panels.some((p) => p.type === type && p.visible);
          const disabled =
            (active && visibleCount <= MIN_PANELS) ||
            (!active && visibleCount >= MAX_PANELS);
          return (
            <button
              key={type}
              type="button"
              className={active ? `${styles.toggle} ${styles.toggleActive}` : styles.toggle}
              disabled={disabled}
              onClick={() => togglePanel(type)}
              aria-pressed={active}
            >
              {title}
            </button>
          );
        })}
        <span className={styles.spacer} />
        <button
          type="button"
          className={styles.toggle}
          onClick={() => setGuideOpen(true)}
          title="Como funciona"
          aria-label="Abrir guia rápido"
        >
          ?
        </button>
        <button
          type="button"
          className={styles.toggle}
          onClick={() => setSettingsOpen((prev) => !prev)}
          title="Settings (Ctrl+,)"
        >
          ⚙
        </button>
        <button
          type="button"
          className={styles.toggle}
          onClick={() => setCommandPaletteOpen(true)}
          title="Command Palette (Ctrl+K)"
        >
          ⌘K
        </button>
        <button type="button" className={styles.reset} onClick={resetLayout}>
          Reset
        </button>
        <button
          type="button"
          className={styles.reset}
          onClick={logout}
          title="Logout"
        >
          ⏻ Logout
        </button>
      </div>

      {/* Panel row */}
      <div ref={containerRef} className={styles.row}>
        {visiblePanels.map((panel, index) => {
          const isLast = index === visiblePanels.length - 1;
          return (
            <div key={panel.id} className={styles.panelSlot} data-panel-type={panel.type} style={{ width: `${panel.width}%` }}>
              <div
                className={[
                  styles.panel,
                  draggingId === panel.id ? styles.panelDragging : "",
                  dropTargetId === panel.id ? styles.panelDropTarget : "",
                ]
                  .filter(Boolean)
                  .join(" ")}
                draggable
                onDragStart={onDragStart(panel.id)}
                onDragOver={onDragOver(panel.id)}
                onDrop={onDrop(panel.id)}
                onDragEnd={onDragEnd}
              >
                <div className={styles.header}>
                  <span className={styles.title}>{panel.title}</span>
                  <button
                    type="button"
                    className={styles.close}
                    onClick={() => togglePanel(panel.type)}
                    disabled={visibleCount <= MIN_PANELS}
                    aria-label={`Close ${panel.title}`}
                    title="Close panel"
                  >
                    ×
                  </button>
                </div>
                <div className={styles.body}>{renderPanelContent(panel.type, investigations, () => setNewInvestigationOpen(true), lastResearch, browserUrl, handleTreeSelect)}</div>
              </div>
              {!isLast && (
                <div
                  className={
                    resizeActive
                      ? `${styles.resizeHandle} ${styles.resizeHandleActive}`
                      : styles.resizeHandle
                  }
                  role="separator"
                  aria-orientation="vertical"
                  onPointerDown={startResize(index)}
                  onPointerMove={onResizeMove}
                  onPointerUp={endResize}
                  onPointerCancel={endResize}
                />
              )}
            </div>
          );
        })}
      </div>

      {/* Status bar */}
      <div className={styles.statusBar}>
        <span className={`${styles.statusDot} ${backendConnected ? styles.statusDotConnected : ""}`} />
        <span>{backendConnected ? "Backend online" : "Backend offline"}</span>
        <span>·</span>
        <span suppressHydrationWarning>{theme}</span>
        <span className={styles.statusSpacer} />
        {user && (
          <>
            <span className={styles.statusUser} title={user.email}>
              {user.username} · {user.role}
            </span>
            <span>·</span>
          </>
        )}
        <span>{themes.length} themes</span>
        <span>·</span>
        <span>{visibleCount} panels</span>
      </div>

      {/* Command palette */}
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        onNewInvestigation={() => setNewInvestigationOpen(true)}
        onExport={exportWorkspace}
      />

      {newInvestigationOpen && <NewInvestigationDialog onClose={() => setNewInvestigationOpen(false)} onCreate={async (data) => {
        const investigation = await createInvestigation({ title: data.title, description: data.description });
        if (!investigation) return { created: false, started: false };
        if (!data.autoStart) return { created: true, started: false };
        try {
          const goal = data.description?.trim() || data.title;
          await apiFetch(`/api/investigations/${investigation.id}/run?${new URLSearchParams({ goal }).toString()}`, { method: "POST" });
          return { created: true, started: true };
        } catch {
          return { created: true, started: false };
        }
      }} />}
      <WorkspaceGuide open={guideOpen} onClose={() => setGuideOpen(false)} />

      {/* Settings overlay */}
      {settingsOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={() => setSettingsOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Settings"
        >
          <div
            className="relative h-[80vh] w-[90vw] max-w-4xl overflow-hidden rounded-xl border border-[var(--border-subtle)] bg-[var(--surface-1)] shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <SettingsPanel onClose={() => setSettingsOpen(false)} />
          </div>
        </div>
      )}

      {/* Toast notifications */}
      <ToastContainer />
    </div>
  );
}

export default function Workspace() {
  return <WorkspaceShell />;
}

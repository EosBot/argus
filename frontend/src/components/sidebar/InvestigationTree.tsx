"use client";

/* ============================================================
   ARGUS 2.0 — InvestigationTree
   Sidebar tree navigation: Investigations → Targets → Findings
   → IOCs → Evidence
   - Expand / collapse per node
   - Right-click context menu (new investigation, add target,
     export)
   - Status badges per node
   - Drag-and-drop of IOC nodes onto target/finding containers
   ============================================================ */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { apiDownload } from "../../lib/api";

/* ============================ Types ============================ */

export type NodeStatus = "active" | "pending" | "complete" | "error";

export interface IOC {
  type: "ioc";
  id: string;
  value: string;
  kind: "domain" | "ip" | "hash" | "url" | "email";
  risk: "low" | "medium" | "high";
}

export interface Evidence {
  type: "evidence";
  id: string;
  title: string;
  kind: string;
  status: NodeStatus;
}

export interface Finding {
  type: "finding";
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: NodeStatus;
  iocs: IOC[];
  evidence: Evidence[];
}

export interface Target {
  type: "target";
  id: string;
  name: string;
  status: NodeStatus;
  findings: Finding[];
}

export interface Investigation {
  type: "investigation";
  id: string;
  title: string;
  status: NodeStatus;
  targets: Target[];
}

export type TreeNode = Investigation | Target | Finding | IOC | Evidence;

export type MenuAction = "new" | "add-target" | "export";
type ExportFormat = "json" | "csv" | "stix" | "misp" | "sigma" | "yara" | "pdf" | "timeline" | "ioc-package";

const EXPORT_FORMATS: Array<{ value: ExportFormat; label: string }> = [
  { value: "json", label: "JSON" },
  { value: "csv", label: "IOC CSV" },
  { value: "stix", label: "STIX 2.1" },
  { value: "misp", label: "MISP" },
  { value: "sigma", label: "Sigma" },
  { value: "yara", label: "YARA" },
  { value: "pdf", label: "PDF" },
  { value: "timeline", label: "Timeline" },
  { value: "ioc-package", label: "IOC package" },
];

/* ======================== Status metadata ======================= */

const STATUS_META: Record<NodeStatus, { label: string; dot: string }> = {
  active: { label: "Active", dot: "bg-emerald-400" },
  pending: { label: "Pending", dot: "bg-amber-400" },
  complete: { label: "Complete", dot: "bg-sky-400" },
  error: { label: "Error", dot: "bg-red-400" },
};

const RISK_META: Record<IOC["risk"], { label: string; cls: string }> = {
  low: { label: "low", cls: "text-zinc-400 border-zinc-700" },
  medium: { label: "med", cls: "text-amber-300 border-amber-500/40" },
  high: { label: "high", cls: "text-red-300 border-red-500/40" },
};

const SEVERITY_META: Record<Finding["severity"], { label: string; cls: string }> = {
  info: { label: "info", cls: "text-zinc-400 border-zinc-700" },
  low: { label: "low", cls: "text-zinc-300 border-zinc-600" },
  medium: { label: "med", cls: "text-amber-300 border-amber-500/40" },
  high: { label: "high", cls: "text-orange-300 border-orange-500/40" },
  critical: { label: "crit", cls: "text-red-300 border-red-500/50" },
};

const KIND_GLYPH: Record<IOC["kind"], string> = {
  domain: "d",
  ip: "i",
  hash: "h",
  url: "u",
  email: "@",
};

/* ======================= Context menu state ======================= */

interface MenuState {
  x: number;
  y: number;
  nodeId: string;
  nodeType: string;
}

/* ============================ Component ============================ */

export interface InvestigationTreeProps {
  investigations?: Investigation[];
  onSelect?: (node: TreeNode) => void;
  onAction?: (action: MenuAction, node: TreeNode) => void;
}

export default function InvestigationTree({
  investigations = [],
  onSelect,
  onAction,
}: InvestigationTreeProps) {
  const [data, setData] = useState<Investigation[]>(investigations);
  const [expanded, setExpanded] = useState<Set<string>>(() => {
    const init = new Set<string>();
    investigations.forEach((inv) => init.add(inv.id));
    investigations.forEach((inv) =>
      inv.targets.forEach((t) => init.add(t.id)),
    );
    return init;
  });
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [draggingIoc, setDraggingIoc] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<ExportFormat>("json");
  const [exportStatus, setExportStatus] = useState<string>("");
  const menuRef = useRef<HTMLDivElement>(null);

  /* Sync when the parent swaps in new data. */
  useEffect(() => {
    setData(investigations);
  }, [investigations]);

  const toggle = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const isExpanded = useCallback((id: string) => expanded.has(id), [expanded]);

  /* ---------- Context menu ---------- */
  const openMenu = useCallback(
    (e: React.MouseEvent, node: TreeNode) => {
      e.preventDefault();
      e.stopPropagation();
      setMenu({
        x: Math.min(e.clientX, window.innerWidth - 200),
        y: Math.min(e.clientY, window.innerHeight - 140),
        nodeId: node.id,
        nodeType: node.type,
      });
    },
    [],
  );

  useEffect(() => {
    if (!menu) return;
    const close = () => setMenu(null);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMenu(null);
    };
    window.addEventListener("click", close);
    window.addEventListener("contextmenu", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("contextmenu", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [menu]);

  const exportNode = useCallback(
    async (node: TreeNode) => {
      if (node.type === "investigation") {
        try {
          setExportStatus(`Gerando ${exportFormat.toUpperCase()}…`);
          const filename = await apiDownload(
            `/api/investigations/${encodeURIComponent(node.id)}/export/${exportFormat}`,
            `${node.id}.${exportFormat}`,
          );
          setExportStatus(`Exportado: ${filename}`);
        } catch (error) {
          setExportStatus(`Falha: ${error instanceof Error ? error.message : "erro desconhecido"}`);
        }
        return;
      }
      const blob = new Blob([JSON.stringify(node, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${node.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    },
    [exportFormat],
  );

  const dispatch = useCallback(
    (action: MenuAction) => {
      if (!menu) return;
      const node = findNode(data, menu.nodeId);
      setMenu(null);
      if (!node) return;

      if (onAction) {
        onAction(action, node);
        return;
      }

      if (action === "export") {
        void exportNode(node);
      } else if (action === "new") {
        setData((prev) => [
          {
            type: "investigation",
            id: `inv-${Date.now()}`,
            title: `Investigation ${prev.length + 1}`,
            status: "pending",
            targets: [],
          },
          ...prev,
        ]);
      } else if (action === "add-target" && node.type === "investigation") {
        const name = window.prompt("Target name");
        if (!name?.trim()) return;
        setData((prev) =>
          prev.map((inv) =>
            inv.id === node.id
              ? {
                  ...inv,
                  targets: [
                    ...inv.targets,
                    {
                      type: "target",
                      id: `tgt-${Date.now()}`,
                      name: name.trim(),
                      status: "pending",
                      findings: [],
                    },
                  ],
                }
              : inv,
          ),
        );
      }
    },
    [menu, data, onAction, exportNode],
  );

  const handleAction = useCallback(
    (action: MenuAction, node: TreeNode) => {
      if (action === "export") void exportNode(node);
      else onAction?.(action, node);
    },
    [exportNode, onAction],
  );

  /* ---------- IOC drag & drop ---------- */
  const onIocDragStart = useCallback((e: React.DragEvent, ioc: IOC) => {
    setDraggingIoc(ioc.id);
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("application/x-argus-ioc", ioc.id);
    e.dataTransfer.setData("text/plain", ioc.value);
  }, []);

  const onIocDragEnd = useCallback(() => {
    setDraggingIoc(null);
    setDropTarget(null);
  }, []);

  const onDropZone = useCallback(
    (node: Target | Finding) => (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setDropTarget(null);
      const iocId = e.dataTransfer.getData("application/x-argus-ioc") || draggingIoc;
      if (!iocId) return;
      setData((prev) => attachIoc(prev, iocId, node.id));
    },
    [draggingIoc],
  );

  const onDropOver = useCallback(
    (id: string) => (e: React.DragEvent) => {
      e.preventDefault();
      e.stopPropagation();
      e.dataTransfer.dropEffect = "move";
      if (dropTarget !== id) setDropTarget(id);
    },
    [dropTarget],
  );

  const onDropLeave = useCallback(() => setDropTarget(null), []);

  /* ---------- Render helpers ---------- */
  const statusBadge = (status: NodeStatus) => {
    const meta = STATUS_META[status];
    return (
      <span
        className="inline-flex items-center gap-1 rounded-full border border-zinc-700/60 bg-zinc-800/70 px-1.5 py-px text-[10px] leading-4 text-zinc-300"
        title={meta.label}
      >
        <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
        {meta.label}
      </span>
    );
  };

  const chevron = (open: boolean) => (
    <svg
      viewBox="0 0 16 16"
      className={`h-3 w-3 shrink-0 text-zinc-500 transition-transform ${open ? "rotate-90" : ""}`}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      aria-hidden
    >
      <path d="M6 4l4 4-4 4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );

  const glyph = (label: string, cls: string) => (
    <span
      className={`flex h-4 w-4 shrink-0 items-center justify-center rounded text-[10px] font-bold leading-none ${cls}`}
    >
      {label}
    </span>
  );

  const rowCls = (nodeType: string) => {
    const base =
      "group/row flex w-full items-center gap-1.5 rounded-md px-1.5 py-1 text-left text-xs transition-colors cursor-pointer";
    return `${base} ${
      dropTarget === nodeType ? "outline outline-1 outline-dashed outline-emerald-400/70 bg-emerald-400/5" : "hover:bg-zinc-800/70"
    }`;
  };

  const sectionCls = (id: string) =>
    `rounded-md border transition-colors ${
      dropTarget === id
        ? "border-emerald-400/50 bg-emerald-400/5"
        : "border-zinc-800/80"
    }`;

  /* ---------- Recursive node renderers ---------- */
  const renderInvestigation = (inv: Investigation, depth: number) => {
    const open = isExpanded(inv.id);
    return (
      <li key={inv.id}>
        <div
          className={rowCls(inv.id)}
          style={{ paddingLeft: `${depth * 12 + 4}px` }}
          onClick={() => {
            toggle(inv.id);
            onSelect?.(inv);
          }}
          onContextMenu={(e) => openMenu(e, { ...inv, type: "investigation" })}
          role="treeitem"
          aria-expanded={open}
        >
          {chevron(open)}
          {glyph("I", "bg-emerald-500/20 text-emerald-300")}
          <span className="truncate font-medium text-zinc-100">{inv.title}</span>
          <span className="ml-auto flex shrink-0 items-center gap-1">
            {statusBadge(inv.status)}
            <span className="text-[10px] text-zinc-600">{inv.targets.length}</span>
          </span>
        </div>
        <AnimatePresence initial={false}>
          {open && (
            <motion.ul
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.18, ease: "easeInOut" }}
              className="overflow-hidden"
              role="group"
            >
              {inv.targets.length === 0 && (
                <li className="px-5 py-1 text-[11px] italic text-zinc-600">No targets</li>
              )}
              {inv.targets.map((t) => renderTarget(t, depth + 1))}
            </motion.ul>
          )}
        </AnimatePresence>
      </li>
    );
  };

  const renderTarget = (target: Target, depth: number) => {
    const open = isExpanded(target.id);
    return (
      <li key={target.id}>
        <div
          className={rowCls(target.id)}
          style={{ paddingLeft: `${depth * 12 + 4}px` }}
          onClick={() => {
            toggle(target.id);
            onSelect?.(target);
          }}
          onContextMenu={(e) => openMenu(e, { ...target, type: "target" })}
          role="treeitem"
          aria-expanded={open}
        >
          {chevron(open)}
          {glyph("T", "bg-sky-500/20 text-sky-300")}
          <span className="truncate font-mono text-[11px] text-zinc-200">{target.name}</span>
          <span className="ml-auto shrink-0">{statusBadge(target.status)}</span>
        </div>
        <AnimatePresence initial={false}>
          {open && (
            <motion.ul
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.18, ease: "easeInOut" }}
              className="overflow-hidden"
              role="group"
            >
              {target.findings.length === 0 && (
                <li
                  className={`m-1.5 rounded-md border border-dashed border-zinc-800 px-3 py-2 text-[11px] italic text-zinc-600 ${dropTarget === target.id ? "border-emerald-400/60 text-emerald-300" : ""}`}
                  onDragOver={onDropOver(target.id)}
                  onDrop={onDropZone(target)}
                  onDragLeave={onDropLeave}
                >
                  Drop IOC here to attach
                </li>
              )}
              {target.findings.map((f) => renderFinding(f, depth + 1))}
            </motion.ul>
          )}
        </AnimatePresence>
      </li>
    );
  };

  const renderFinding = (finding: Finding, depth: number) => {
    const open = isExpanded(finding.id);
    const sev = SEVERITY_META[finding.severity];
    return (
      <li key={finding.id}>
        <div
          className={rowCls(finding.id)}
          style={{ paddingLeft: `${depth * 12 + 4}px` }}
          onClick={() => {
            toggle(finding.id);
            onSelect?.(finding);
          }}
          onContextMenu={(e) => openMenu(e, { ...finding, type: "finding" })}
          role="treeitem"
          aria-expanded={open}
        >
          {chevron(open)}
          {glyph("F", "bg-amber-500/20 text-amber-300")}
          <span className="truncate text-zinc-200">{finding.title}</span>
          <span
            className={`ml-auto shrink-0 rounded border px-1 text-[9px] uppercase leading-4 ${sev.cls}`}
            title={finding.severity}
          >
            {sev.label}
          </span>
        </div>
        <AnimatePresence initial={false}>
          {open && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.18, ease: "easeInOut" }}
              className="overflow-hidden"
              role="group"
            >
              {/* IOCs */}
              <div
                className={`m-1.5 ${sectionCls(finding.id)} p-1 ${dropTarget === finding.id ? "outline outline-1 outline-dashed outline-emerald-400/70" : ""}`}
                onDragOver={onDropOver(finding.id)}
                onDrop={onDropZone(finding)}
                onDragLeave={onDropLeave}
              >
                <div className="px-1.5 pb-0.5 pt-0.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  IOCs ({finding.iocs.length})
                </div>
                {finding.iocs.length === 0 && (
                  <div className="px-1.5 py-0.5 text-[11px] italic text-zinc-600">
                    Drop IOC here to attach
                  </div>
                )}
                {finding.iocs.map((ioc) => {
                  const risk = RISK_META[ioc.risk];
                  const ghost = draggingIoc === ioc.id;
                  return (
                    <div
                      key={ioc.id}
                      draggable
                      onDragStart={(e) => onIocDragStart(e, ioc)}
                      onDragEnd={onIocDragEnd}
                      onClick={() => onSelect?.(ioc)}
                      onContextMenu={(e) => openMenu(e, { ...ioc, type: "ioc" })}
                      className={`flex items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] transition-colors ${ghost ? "opacity-40" : "hover:bg-zinc-800/80"} cursor-grab active:cursor-grabbing`}
                      title={`${ioc.value} · ${ioc.kind}`}
                    >
                      <span className="w-3 text-center font-mono text-[9px] text-zinc-500">
                        {KIND_GLYPH[ioc.kind]}
                      </span>
                      <span className="truncate font-mono text-zinc-300">{ioc.value}</span>
                      <span
                        className={`ml-auto shrink-0 rounded border px-1 text-[9px] uppercase leading-4 ${risk.cls}`}
                      >
                        {risk.label}
                      </span>
                    </div>
                  );
                })}
              </div>

              {/* Evidence */}
              <div className="m-1.5 rounded-md border border-zinc-800/80 p-1">
                <div className="px-1.5 pb-0.5 pt-0.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  Evidence ({finding.evidence.length})
                </div>
                {finding.evidence.length === 0 && (
                  <div className="px-1.5 py-0.5 text-[11px] italic text-zinc-600">
                    No evidence recorded
                  </div>
                )}
                {finding.evidence.map((ev) => (
                  <div
                    key={ev.id}
                    onClick={() => onSelect?.(ev)}
                    onContextMenu={(e) => openMenu(e, { ...ev, type: "evidence" })}
                    className="flex cursor-pointer items-center gap-1.5 rounded px-1.5 py-0.5 text-[11px] hover:bg-zinc-800/70"
                  >
                    <span className="text-[10px] text-zinc-500">◆</span>
                    <span className="truncate text-zinc-300">{ev.title}</span>
                    <span className="ml-auto text-[10px] text-zinc-600">{ev.kind}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </li>
    );
  };

  const totalIocs = useMemo(
    () =>
      data.reduce(
        (acc, inv) =>
          acc +
          inv.targets.reduce(
            (a, t) => a + t.findings.reduce((b, f) => b + f.iocs.length, 0),
            0,
          ),
        0,
      ),
    [data],
  );

  return (
    <div className="flex h-full flex-col bg-zinc-950/60 text-zinc-100">
      {/* Header */}
      <div className="flex items-center justify-between gap-2 border-b border-zinc-800 px-3 py-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
          Investigations
        </span>
        <div className="flex items-center gap-1.5">
          <label htmlFor="investigation-export-format" className="sr-only">Formato de exportação do caso</label>
          <select
            id="investigation-export-format"
            value={exportFormat}
            onChange={(event) => setExportFormat(event.target.value as ExportFormat)}
            className="max-w-24 rounded border border-zinc-800 bg-zinc-900 px-1 py-0.5 text-[10px] text-zinc-300"
            title="Formato usado por Export no menu de contexto da investigação"
          >
            {EXPORT_FORMATS.map((format) => <option key={format.value} value={format.value}>{format.label}</option>)}
          </select>
          <span className="rounded-full border border-zinc-800 bg-zinc-900 px-1.5 py-px font-mono text-[10px] text-zinc-500">
            {totalIocs} IOC
          </span>
        </div>
      </div>

      {exportStatus && (
        <div className="border-b border-zinc-800 px-3 py-1 text-[10px] text-zinc-400" role="status">
          {exportStatus}
        </div>
      )}

      {/* Tree */}
      <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
        {data.length === 0 && (
          <div className="p-3 text-[11px] italic text-zinc-600">No investigations</div>
        )}
        <ul role="tree" className="space-y-0.5">
          {data.map((inv) => renderInvestigation(inv, 0))}
        </ul>
      </div>

      {/* Context menu */}
      <AnimatePresence>
        {menu && (
          <motion.div
            ref={menuRef}
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.96 }}
            transition={{ duration: 0.1 }}
            className="fixed z-50 w-48 overflow-hidden rounded-lg border border-zinc-700 bg-zinc-900 py-1 shadow-xl shadow-black/50"
            style={{ left: menu.x, top: menu.y }}
            onClick={(e) => e.stopPropagation()}
            role="menu"
          >
            <div className="border-b border-zinc-800 px-2.5 py-1 text-[10px] uppercase tracking-wider text-zinc-500">
              {menu.nodeType}
            </div>
            <button
              type="button"
              role="menuitem"
              onClick={() => dispatch("new")}
              className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs text-zinc-200 hover:bg-zinc-800"
            >
              <span className="text-emerald-400">＋</span> New investigation
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={() => dispatch("add-target")}
              className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs text-zinc-200 hover:bg-zinc-800"
            >
              <span className="text-sky-400">⊕</span> Add target
            </button>
            <div className="my-1 border-t border-zinc-800" />
            <button
              type="button"
              role="menuitem"
              onClick={() => dispatch("export")}
              className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs text-zinc-200 hover:bg-zinc-800"
            >
              <span className="text-zinc-400">⇩</span> Export {menu.nodeType === "investigation" ? exportFormat.toUpperCase() : "node JSON"}
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ============================ Helpers ============================ */

function findNode(
  data: Investigation[],
  id: string,
): (TreeNode & { type: string }) | null {
  for (const inv of data) {
    if (inv.id === id) return { ...inv, type: "investigation" };
    for (const t of inv.targets) {
      if (t.id === id) return { ...t, type: "target" };
      for (const f of t.findings) {
        if (f.id === id) return { ...f, type: "finding" };
        const ioc = f.iocs.find((i) => i.id === id);
        if (ioc) return { ...ioc, type: "ioc" };
        const ev = f.evidence.find((e) => e.id === id);
        if (ev) return { ...ev, type: "evidence" };
      }
    }
  }
  return null;
}

/** Move an IOC from its current finding onto a target or finding node. */
function attachIoc(data: Investigation[], iocId: string, targetId: string): Investigation[] {
  return data.map((inv) => ({
    ...inv,
    targets: inv.targets.map((t) => {
      // Strip the IOC from wherever it currently lives.
      const stripped: Target = {
        ...t,
        findings: t.findings.map((f) =>
          f.iocs.some((i) => i.id === iocId)
            ? { ...f, iocs: f.iocs.filter((i) => i.id !== iocId) }
            : f,
        ),
      };

      if (t.id === targetId) {
        // Dropped onto a target: move IOC into its first finding, or an
        // orphan bucket when the target has no findings.
        const first = stripped.findings[0];
        if (first) {
          const ioc = t.findings.flatMap((f) => f.iocs).find((i) => i.id === iocId);
          return ioc
            ? {
                ...stripped,
                findings: stripped.findings.map((f, idx) =>
                  idx === 0 ? { ...f, iocs: [...f.iocs, ioc] } : f,
                ),
              }
            : stripped;
        }
        return stripped;
      }

      const hit = t.findings.find((f) => f.id === targetId);
      if (hit) {
        const ioc = t.findings.flatMap((f) => f.iocs).find((i) => i.id === iocId);
        return ioc
          ? {
              ...stripped,
              findings: stripped.findings.map((f) =>
                f.id === targetId ? { ...f, iocs: [...f.iocs, ioc] } : f,
              ),
            }
          : stripped;
      }
      return stripped;
    }),
  }));
}

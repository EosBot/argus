"use client";

import { AnimatePresence, motion } from "motion/react";
import { useInvestigationProgress } from "../../hooks/useInvestigationProgress";

export type ScanStatus = "queue" | "running" | "done";

export interface ScanModel {
  /** Model/tool identifier, e.g. "gpt-5.2" or "tor" */
  name: string;
  /** Optional tool category, e.g. "model" | "agent" | "tool" */
  type?: "model" | "agent" | "tool";
}

export interface ScanCardProps {
  /** Investigation name */
  title: string;
  /** Current status */
  status: ScanStatus;
  /** Progress 0–100 (only meaningful while running) */
  progress?: number;
  /** Elapsed time, ISO duration string or plain text, e.g. "2m 14s" */
  elapsed?: string;
  /** Model/tool badge */
  model?: ScanModel;
  /** Output preview text, expanded when provided */
  output?: string;
  /** Whether the output preview starts expanded */
  defaultExpanded?: boolean;
  /** Investigation ID — when provided, live progress streams over WebSocket */
  investigationId?: string;
}

const STATUS_META: Record<
  ScanStatus,
  { label: string; dot: string; pulse: boolean; bar: string }
> = {
  running: { label: "Running", dot: "bg-emerald-400", pulse: true, bar: "bg-emerald-400" },
  done: { label: "Done", dot: "bg-sky-400", pulse: false, bar: "bg-sky-400" },
  queue: { label: "Queued", dot: "bg-amber-400", pulse: false, bar: "bg-amber-400" },
};

function clampProgress(value: number): number {
  return Math.max(0, Math.min(100, value));
}

export default function ScanCard({
  title,
  status,
  progress = 0,
  elapsed,
  model,
  output,
  defaultExpanded = false,
  investigationId,
}: ScanCardProps) {
  const live = useInvestigationProgress(investigationId ?? "");
  const effectiveStatus = investigationId ? live.status : status;
  const effectiveProgress = investigationId ? live.progress : progress;
  const meta = STATUS_META[effectiveStatus];
  const clamped = clampProgress(effectiveProgress);
  const showBar = effectiveStatus !== "queue";
  const canExpand = Boolean(output && output.trim().length > 0);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.96 }}
      transition={{ type: "spring", stiffness: 300, damping: 28 }}
      className="group rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm backdrop-blur"
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="truncate text-sm font-semibold text-zinc-100">{title}</h3>
          <div className="mt-1.5 flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${meta.dot} ${
                meta.pulse ? "animate-pulse" : ""
              }`}
            />
            <span className="text-xs text-zinc-400">{meta.label}</span>
            {elapsed ? (
              <>
                <span className="text-zinc-600">·</span>
                <span className="font-mono text-xs text-zinc-500">{elapsed}</span>
              </>
            ) : null}
          </div>
        </div>
        {model ? (
          <span className="shrink-0 rounded-md border border-zinc-700 bg-zinc-800 px-2 py-0.5 font-mono text-[11px] text-zinc-300">
            {model.name}
          </span>
        ) : null}
      </div>

      {/* Progress */}
      {showBar ? (
        <div className="mt-3 flex items-center gap-2">
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
            <motion.div
              className={`h-full rounded-full ${meta.bar}`}
              initial={{ width: 0 }}
              animate={{ width: `${clamped}%` }}
              transition={{ type: "spring", stiffness: 120, damping: 20 }}
            />
          </div>
          <span className="w-9 text-right font-mono text-xs tabular-nums text-zinc-400">
            {Math.round(clamped)}%
          </span>
        </div>
      ) : null}

      {/* Output preview */}
      <AnimatePresence initial={false}>
        {canExpand && defaultExpanded ? (
          <motion.pre
            key="output"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeInOut" }}
            className="mt-3 max-h-40 overflow-auto whitespace-pre-wrap rounded-md border border-zinc-800 bg-black/40 p-3 font-mono text-xs leading-relaxed text-zinc-400"
          >
            {output}
          </motion.pre>
        ) : null}
      </AnimatePresence>
    </motion.div>
  );
}

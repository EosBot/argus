"use client";

import { AnimatePresence, motion } from "motion/react";
import { useEffect } from "react";

export type NotificationSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface ToastProps {
  /** Notification title */
  title: string;
  /** Optional body text */
  body?: string | null;
  /** Severity level — controls color/accent */
  severity: NotificationSeverity;
  /** Dismiss callback */
  onClose: () => void;
  /** Auto-dismiss duration in ms (default 5000, 0 = no auto-dismiss) */
  duration?: number;
}

const SEVERITY_META: Record<
  NotificationSeverity,
  { accent: string; icon: string; bar: string }
> = {
  info: { accent: "border-sky-500/50", icon: "ℹ️", bar: "bg-sky-500" },
  low: { accent: "border-emerald-500/50", icon: "✅", bar: "bg-emerald-500" },
  medium: { accent: "border-amber-500/50", icon: "⚠️", bar: "bg-amber-500" },
  high: { accent: "border-orange-500/50", icon: "🔶", bar: "bg-orange-500" },
  critical: { accent: "border-red-500/50", icon: "🚨", bar: "bg-red-500" },
};

export function Toast({ title, body, severity, onClose, duration = 5000 }: ToastProps) {
  const meta = SEVERITY_META[severity] ?? SEVERITY_META.info;

  useEffect(() => {
    if (duration <= 0) return;
    const timer = setTimeout(onClose, duration);
    return () => clearTimeout(timer);
  }, [duration, onClose]);

  return (
    <AnimatePresence>
      <motion.div
        layout
        initial={{ opacity: 0, x: 80, scale: 0.95 }}
        animate={{ opacity: 1, x: 0, scale: 1 }}
        exit={{ opacity: 0, x: 80, scale: 0.95 }}
        transition={{ type: "spring", stiffness: 400, damping: 30 }}
        className={`pointer-events-auto w-80 overflow-hidden rounded-lg border ${meta.accent} bg-zinc-900/95 shadow-lg shadow-black/40 backdrop-blur`}
        role="alert"
      >
        {/* Severity accent bar */}
        <div className={`h-0.5 ${meta.bar}`} />

        <div className="flex items-start gap-3 p-3">
          <span className="mt-0.5 text-base leading-none">{meta.icon}</span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-zinc-100">{title}</p>
            {body ? (
              <p className="mt-1 line-clamp-2 text-xs text-zinc-400">{body}</p>
            ) : null}
          </div>
          <button
            onClick={onClose}
            className="shrink-0 rounded p-0.5 text-zinc-500 transition-colors hover:text-zinc-300"
            aria-label="Dismiss"
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path
                d="M10.5 3.5L3.5 10.5M3.5 3.5L10.5 10.5"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
              />
            </svg>
          </button>
        </div>
      </motion.div>
    </AnimatePresence>
  );
}

export default Toast;

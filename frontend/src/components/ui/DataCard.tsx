"use client";

import type { ReactNode } from "react";
import { motion } from "motion/react";

/* ============================================================
   ConfidenceIndicator — corroborated / single-source / unverified
   ============================================================ */

export type ConfidenceLevel = "corroborated" | "single-source" | "unverified";

const CONFIDENCE_META: Record<
  ConfidenceLevel,
  { label: string; badge: string; dot: string; bar: string; width: string }
> = {
  corroborated: {
    label: "Corroborated",
    badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    dot: "bg-emerald-400",
    bar: "bg-emerald-400",
    width: "w-full",
  },
  "single-source": {
    label: "Single Source",
    badge: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    dot: "bg-amber-400",
    bar: "bg-amber-400",
    width: "w-2/3",
  },
  unverified: {
    label: "Unverified",
    badge: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
    dot: "bg-zinc-500",
    bar: "bg-zinc-500",
    width: "w-1/3",
  },
};

export interface ConfidenceIndicatorProps {
  level: ConfidenceLevel;
  /** Optional numeric confidence 0–100, rendered as a slim bar when provided */
  score?: number;
  className?: string;
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(100, value));
}

export function ConfidenceIndicator({
  level,
  score,
  className = "",
}: ConfidenceIndicatorProps) {
  const meta = CONFIDENCE_META[level];

  return (
    <div className={`flex items-center gap-2 ${className}`} title={`Confidence: ${meta.label}`}>
      <span
        className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-medium ${meta.badge}`}
      >
        <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
        {meta.label}
      </span>
      {typeof score === "number" ? (
        <div className="h-1 w-14 overflow-hidden rounded-full bg-zinc-800">
          <motion.div
            className={`h-full rounded-full ${meta.bar}`}
            initial={{ width: 0 }}
            animate={{ width: `${clampScore(score)}%` }}
            transition={{ duration: 0.4, ease: "easeOut" }}
          />
        </div>
      ) : null}
    </div>
  );
}

/* ============================================================
   SourceBadge — fonte da inteligência
   ============================================================ */

export type SourceKind = "osint" | "ti-feed" | "crawler" | "agent" | "manual";

const SOURCE_KIND_META: Record<SourceKind, { label: string; badge: string }> = {
  osint: { label: "OSINT", badge: "bg-sky-500/10 text-sky-400 border-sky-500/30" },
  "ti-feed": { label: "TI Feed", badge: "bg-violet-500/10 text-violet-400 border-violet-500/30" },
  crawler: { label: "Crawler", badge: "bg-teal-500/10 text-teal-400 border-teal-500/30" },
  agent: { label: "Agent", badge: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  manual: { label: "Manual", badge: "bg-zinc-500/10 text-zinc-300 border-zinc-500/30" },
};

export interface SourceBadgeProps {
  name: string;
  kind?: SourceKind;
  /** Optional ISO timestamp or relative text, e.g. "2026-08-13T03:00:00Z" */
  timestamp?: string;
  className?: string;
}

export function SourceBadge({ name, kind, timestamp, className = "" }: SourceBadgeProps) {
  const kindMeta = kind ? SOURCE_KIND_META[kind] : null;

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono text-[11px] ${className}`}
      title={timestamp ? `${name} · ${timestamp}` : name}
    >
      {kindMeta ? (
        <span
          className={`inline-flex items-center rounded border px-1.5 py-0.5 ${kindMeta.badge}`}
        >
          {kindMeta.label}
        </span>
      ) : null}
      <span className="truncate text-zinc-400">{name}</span>
      {timestamp ? (
        <time className="shrink-0 text-zinc-600" dateTime={timestamp}>
          {timestamp}
        </time>
      ) : null}
    </span>
  );
}

/* ============================================================
   StatBadge — número + label + trend
   ============================================================ */

export type TrendDirection = "up" | "down" | "flat";

const TREND_ARROW: Record<TrendDirection, string> = {
  up: "▲",
  down: "▼",
  flat: "▬",
};

const TREND_COLOR: Record<TrendDirection, string> = {
  up: "text-emerald-400",
  down: "text-rose-400",
  flat: "text-zinc-500",
};

export interface StatBadgeProps {
  value: string | number;
  label: string;
  trend?: TrendDirection;
  /** Optional trend delta text, e.g. "+12%" */
  trendText?: string;
  className?: string;
}

export function StatBadge({ value, label, trend, trendText, className = "" }: StatBadgeProps) {
  return (
    <div
      className={`flex min-w-[5.5rem] flex-col gap-0.5 rounded-lg border border-zinc-800 bg-zinc-900/60 px-3 py-2 ${className}`}
    >
      <div className="flex items-baseline gap-1.5">
        <span className="font-mono text-base font-semibold tabular-nums text-zinc-100">
          {value}
        </span>
        {trend ? (
          <span
            className={`font-mono text-[11px] ${TREND_COLOR[trend]}`}
            title={trendText ?? trend}
          >
            {TREND_ARROW[trend]}
            {trendText ? ` ${trendText}` : ""}
          </span>
        ) : null}
      </div>
      <span className="truncate text-[11px] text-zinc-500">{label}</span>
    </div>
  );
}

/* ============================================================
   IOCBadge — tipo + valor + ações
   ============================================================ */

export type IOCType = "ip" | "domain" | "url" | "hash" | "email" | "cve";

const IOC_TYPE_META: Record<IOCType, { label: string; badge: string }> = {
  ip: { label: "IP", badge: "bg-sky-500/10 text-sky-400 border-sky-500/30" },
  domain: { label: "Domain", badge: "bg-teal-500/10 text-teal-400 border-teal-500/30" },
  url: { label: "URL", badge: "bg-violet-500/10 text-violet-400 border-violet-500/30" },
  hash: { label: "Hash", badge: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
  email: { label: "Email", badge: "bg-rose-500/10 text-rose-400 border-rose-500/30" },
  cve: { label: "CVE", badge: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" },
};

export interface IOCAction {
  label: string;
  onAction: () => void;
  /** Destructive actions get danger styling */
  danger?: boolean;
}

export interface IOCBadgeProps {
  type: IOCType;
  value: string;
  actions?: IOCAction[];
  className?: string;
}

export function IOCBadge({ type, value, actions, className = "" }: IOCBadgeProps) {
  const meta = IOC_TYPE_META[type];

  return (
    <span
      className={`inline-flex max-w-full items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900/80 py-1 pl-2 pr-1 ${className}`}
    >
      <span
        className={`shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase ${meta.badge}`}
      >
        {meta.label}
      </span>
      <code className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-200" title={value}>
        {value}
      </code>
      {actions && actions.length > 0 ? (
        <span className="flex shrink-0 items-center gap-0.5">
          {actions.map((action) => (
            <button
              key={action.label}
              type="button"
              onClick={action.onAction}
              className={`rounded px-1.5 py-0.5 text-[11px] transition-colors ${
                action.danger
                  ? "text-rose-400 hover:bg-rose-500/10"
                  : "text-zinc-400 hover:bg-zinc-700/60 hover:text-zinc-200"
              }`}
            >
              {action.label}
            </button>
          ))}
        </span>
      ) : null}
    </span>
  );
}

/* ============================================================
   TimelineEvent — evento na timeline
   ============================================================ */

export interface TimelineEventProps {
  timestamp: string;
  title: string;
  description?: string;
  /** Icon node rendered inside the marker dot */
  icon?: ReactNode;
  kind?: ConfidenceLevel;
  isLast?: boolean;
  className?: string;
}

export function TimelineEvent({
  timestamp,
  title,
  description,
  icon,
  kind = "unverified",
  isLast = false,
  className = "",
}: TimelineEventProps) {
  const meta = CONFIDENCE_META[kind];

  return (
    <li className={`relative flex gap-3 pl-1 ${className}`}>
      {/* Rail + marker */}
      <div className="flex flex-col items-center">
        <span
          className={`z-10 flex h-5 w-5 shrink-0 items-center justify-center rounded-full border border-zinc-700 bg-zinc-900 text-[10px] ${meta.dot}`}
        >
          {icon ?? null}
        </span>
        {!isLast ? <span className="mt-1 w-px flex-1 bg-zinc-800" /> : null}
      </div>

      {/* Content */}
      <div className="min-w-0 flex-1 pb-4">
        <div className="flex items-baseline justify-between gap-2">
          <h4 className="truncate text-sm font-medium text-zinc-100">{title}</h4>
          <time className="shrink-0 font-mono text-[11px] tabular-nums text-zinc-500" dateTime={timestamp}>
            {timestamp}
          </time>
        </div>
        {description ? (
          <p className="mt-0.5 text-xs leading-relaxed text-zinc-400">{description}</p>
        ) : null}
      </div>
    </li>
  );
}

/* ============================================================
   DataCard — finding/IOC com confidence badge + source attribution
   ============================================================ */

export interface DataCardProps {
  /** Finding title */
  title: string;
  /** Short summary of the finding */
  summary: string;
  /** Full detail body rendered under the summary */
  children?: ReactNode;
  confidence: ConfidenceLevel;
  /** Numeric confidence 0–100 for the indicator bar */
  confidenceScore?: number;
  source: SourceBadgeProps;
  /** Optional IOC chips attached to the card */
  iocs?: Array<{ type: IOCType; value: string; actions?: IOCAction[] }>;
  /** Optional stats rendered in a row under the summary */
  stats?: Array<{ value: string | number; label: string; trend?: TrendDirection; trendText?: string }>;
  className?: string;
}

export default function DataCard({
  title,
  summary,
  children,
  confidence,
  confidenceScore,
  source,
  iocs,
  stats,
  className = "",
}: DataCardProps) {
  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ type: "spring", stiffness: 300, damping: 28 }}
      className={`rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm backdrop-blur ${className}`}
    >
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h3 className="min-w-0 text-sm font-semibold text-zinc-100">{title}</h3>
        <ConfidenceIndicator level={confidence} score={confidenceScore} />
      </div>

      <p className="mt-2 text-xs leading-relaxed text-zinc-400">{summary}</p>

      {/* Stats row */}
      {stats && stats.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {stats.map((stat) => (
            <StatBadge key={`${stat.label}-${stat.value}`} {...stat} />
          ))}
        </div>
      ) : null}

      {/* IOC chips */}
      {iocs && iocs.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {iocs.map((ioc) => (
            <IOCBadge key={`${ioc.type}-${ioc.value}`} {...ioc} />
          ))}
        </div>
      ) : null}

      {/* Detail body */}
      {children ? <div className="mt-3">{children}</div> : null}

      {/* Footer — source attribution */}
      <footer className="mt-3 flex items-center justify-between gap-2 border-t border-zinc-800/80 pt-2.5">
        <SourceBadge {...source} />
        <span className="text-[10px] uppercase tracking-wider text-zinc-600">Intelligence</span>
      </footer>
    </motion.article>
  );
}

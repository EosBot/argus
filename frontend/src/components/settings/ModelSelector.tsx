"use client";

/* ============================================================
   ARGUS 2.0 — Model Selector
   Model selection with capability chips for different task types.
   ============================================================ */

import { useCallback, useMemo, useState } from "react";
import { AnimatePresence, motion } from "motion/react";

/* ============================ Types ============================ */

export type TaskType = "reasoning" | "coding" | "analysis" | "general" | "fast";

export interface Model {
  id: string;
  name: string;
  provider: string;
  capabilities: TaskType[];
  contextWindow: number;
  costPer1kTokens?: number;
  maxOutputTokens?: number;
}

export interface ModelSelectorProps {
  models: Model[];
  selectedModels: Partial<Record<TaskType, string>>;
  onSelect: (taskType: TaskType, modelId: string) => Promise<void>;
}

/* ============================ Metadata ============================ */

const TASK_META: Record<TaskType, { label: string; icon: string; description: string }> = {
  reasoning: {
    label: "Reasoning",
    icon: "🧠",
    description: "Complex logical analysis and multi-step problem solving",
  },
  coding: {
    label: "Coding",
    icon: "💻",
    description: "Code generation, review, and debugging",
  },
  analysis: {
    label: "Analysis",
    icon: "📊",
    description: "Data analysis, pattern recognition, summarization",
  },
  general: {
    label: "General",
    icon: "🤖",
    description: "General-purpose tasks and conversation",
  },
  fast: {
    label: "Fast",
    icon: "⚡",
    description: "Quick responses for simple queries",
  },
};

const CAPABILITY_COLORS: Record<TaskType, string> = {
  reasoning: "border-purple-500/40 text-purple-300 bg-purple-500/10",
  coding: "border-blue-500/40 text-blue-300 bg-blue-500/10",
  analysis: "border-amber-500/40 text-amber-300 bg-amber-500/10",
  general: "border-zinc-500/40 text-zinc-300 bg-zinc-500/10",
  fast: "border-emerald-500/40 text-emerald-300 bg-emerald-500/10",
};

/* ============================ Component ============================ */

export default function ModelSelector({
  models,
  selectedModels,
  onSelect,
}: ModelSelectorProps) {
  const [filter, setFilter] = useState<TaskType | "all">("all");

  const filteredModels = useMemo(() => {
    if (filter === "all") return models;
    return models.filter((m) => m.capabilities.includes(filter));
  }, [models, filter]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">
          Model Selection
        </h3>
        <p className="mt-1 text-xs text-[var(--text-muted)]">
          Choose the best model for each task type
        </p>
      </div>

      {/* Task Type Selection */}
      <div className="space-y-2">
        <label className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Task Type
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => setFilter("all")}
            className={`rounded-full border px-3 py-1 text-xs transition-colors ${
              filter === "all"
                ? "border-[var(--accent-primary)] bg-[var(--accent-primary)]/10 text-[var(--accent-primary)]"
                : "border-[var(--border-subtle)] text-[var(--text-muted)] hover:border-[var(--border-strong)]"
            }`}
          >
            All
          </button>
          {(Object.entries(TASK_META) as [TaskType, (typeof TASK_META)[TaskType]][]).map(
            ([key, meta]) => (
              <button
                key={key}
                type="button"
                onClick={() => setFilter(key)}
                className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs transition-colors ${
                  filter === key
                    ? "border-[var(--accent-primary)] bg-[var(--accent-primary)]/10 text-[var(--accent-primary)]"
                    : "border-[var(--border-subtle)] text-[var(--text-muted)] hover:border-[var(--border-strong)]"
                }`}
              >
                <span>{meta.icon}</span>
                {meta.label}
              </button>
            )
          )}
        </div>
      </div>

      {/* Current Selections */}
      <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3">
        <div className="mb-2 text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Current Selections
        </div>
        <div className="space-y-2">
          {(Object.entries(TASK_META) as [TaskType, (typeof TASK_META)[TaskType]][]).map(
            ([key, meta]) => {
              const selectedId = selectedModels[key];
              const selectedModel = models.find((m) => m.id === selectedId);
              return (
                <div key={key} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span>{meta.icon}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{meta.label}</span>
                  </div>
                  <span
                    aria-label={`Selected model for ${meta.label}`}
                    className="text-xs text-[var(--text-primary)]"
                  >
                    {selectedModel ? selectedModel.name : "Not selected"}
                  </span>
                </div>
              );
            }
          )}
        </div>
      </div>

      {/* Model List */}
      <div className="space-y-2">
        <div className="text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Available Models ({filteredModels.length})
        </div>
        {filteredModels.length === 0 && (
          <div className="rounded-lg border border-dashed border-[var(--border-subtle)] p-6 text-center">
            <p className="text-xs text-[var(--text-muted)]">
              No models match the selected filter
            </p>
          </div>
        )}
        <AnimatePresence>
          {filteredModels.map((model) => (
            <ModelCard
              key={model.id}
              model={model}
              selectedFor={Object.entries(selectedModels)
                .filter(([_, id]) => id === model.id)
                .map(([type]) => type as TaskType)}
              onSelect={onSelect}
            />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

/* ============================ Model Card ============================ */

function ModelCard({
  model,
  selectedFor,
  onSelect,
}: {
  model: Model;
  selectedFor: TaskType[];
  onSelect: (taskType: TaskType, modelId: string) => Promise<void>;
}) {
  const [showAssign, setShowAssign] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3"
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-[var(--text-primary)]">
              {model.name}
            </span>
            <span className="text-[10px] text-[var(--text-muted)]">
              ({model.provider})
            </span>
          </div>
          <div className="mt-1 flex items-center gap-3 text-[10px] text-[var(--text-muted)]">
            <span>Context: {(model.contextWindow / 1000).toFixed(0)}K</span>
            {model.costPer1kTokens !== undefined && (
              <span>${model.costPer1kTokens.toFixed(4)}/1K tokens</span>
            )}
            {model.maxOutputTokens !== undefined && (
              <span>Max output: {(model.maxOutputTokens / 1000).toFixed(0)}K</span>
            )}
          </div>
        </div>
        <button
          type="button"
          aria-label={`Assign ${model.name}`}
          onClick={() => setShowAssign(!showAssign)}
          className="rounded-md border border-[var(--border-subtle)] px-2 py-1 text-[10px] text-[var(--text-muted)] hover:bg-[var(--surface-3)]"
        >
          Assign
        </button>
      </div>

      {/* Capability Chips */}
      <div className="mt-2 flex flex-wrap gap-1">
        {model.capabilities.map((cap) => (
          <span
            key={cap}
            className={`rounded-full border px-2 py-0.5 text-[10px] ${CAPABILITY_COLORS[cap]}`}
          >
            {TASK_META[cap].icon} {TASK_META[cap].label}
          </span>
        ))}
      </div>

      {/* Currently assigned */}
      {selectedFor.length > 0 && (
        <div className="mt-2 flex items-center gap-1.5 text-[10px] text-[var(--accent-primary)]">
          <span>✓</span>
          Selected for: {selectedFor.map((t) => TASK_META[t].label).join(", ")}
        </div>
      )}

      {/* Assignment Dropdown */}
      <AnimatePresence>
        {showAssign && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="mt-2 overflow-hidden border-t border-[var(--border-subtle)] pt-2"
          >
            <div className="text-[10px] font-medium text-[var(--text-muted)] mb-1">
              Assign to task type:
            </div>
            <div className="flex flex-wrap gap-1">
              {(Object.entries(TASK_META) as [TaskType, (typeof TASK_META)[TaskType]][]).map(
                ([key, meta]) => {
                  const isAssigned = selectedFor.includes(key);
                  return (
                    <button
                      key={key}
                      type="button"
                      onClick={() => {
                        setSaving(true);
                        setError(null);
                        void onSelect(key, isAssigned ? "" : model.id)
                          .then(() => setShowAssign(false))
                          .catch((cause) => setError(cause instanceof Error ? cause.message : "Falha ao atribuir modelo"))
                          .finally(() => setSaving(false));
                      }}
                      disabled={saving}
                      className={`flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] transition-colors ${
                        isAssigned
                          ? "border-[var(--accent-primary)] bg-[var(--accent-primary)]/10 text-[var(--accent-primary)]"
                          : "border-[var(--border-subtle)] text-[var(--text-muted)] hover:border-[var(--border-strong)]"
                      }`}
                    >
                      <span>{meta.icon}</span>
                      {isAssigned ? `Remove ${meta.label}` : meta.label}
                      {isAssigned && <span aria-hidden="true">×</span>}
                    </button>
                  );
                }
              )}
            </div>
            {error && <p role="alert" className="mt-2 text-[10px] text-red-300">{error}</p>}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

"use client";

import { FormEvent, useState } from "react";

type CreateResult = { created: boolean; started: boolean };

export default function NewInvestigationDialog({ onClose, onCreate }: { onClose: () => void; onCreate: (data: { title: string; description?: string; autoStart: boolean }) => Promise<CreateResult> }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [autoStart, setAutoStart] = useState(true);
  const [created, setCreated] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    if (created) { onClose(); return; }
    const result = await onCreate({ title: title.trim(), description: description.trim() || undefined, autoStart });
    setSaving(false);
    if (!result.created) {
      setError("Não foi possível criar a investigação. Verifique o backend e suas permissões.");
    } else if (autoStart && !result.started) {
      setCreated(true);
      setError("O caso foi criado, mas o pipeline autônomo não iniciou. Feche esta janela e consulte Agent Status antes de tentar novamente.");
    } else {
      onClose();
    }
  }

  return <div className="fixed inset-0 z-[1200] flex items-center justify-center bg-black/70 p-4" role="presentation" onMouseDown={onClose}>
    <form role="dialog" aria-modal="true" aria-labelledby="new-investigation-title" onSubmit={submit} onMouseDown={(event) => event.stopPropagation()} className="w-full max-w-lg space-y-4 rounded-xl border border-[var(--border-accent)] bg-[var(--surface-1)] p-5 shadow-2xl">
      <div><h2 id="new-investigation-title" className="text-sm font-semibold text-[var(--text-primary)]">Nova investigação</h2><p className="mt-1 text-xs text-[var(--text-muted)]">Crie o caso que receberá planos, achados, IOCs e evidências.</p></div>
      <div><label htmlFor="investigation-title" className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Título</label><input id="investigation-title" autoFocus required maxLength={256} value={title} onChange={(event) => setTitle(event.target.value)} className="w-full rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-2 text-sm text-[var(--text-primary)]" /></div>
      <div><label htmlFor="investigation-description" className="mb-1 block text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Objetivo e escopo</label><textarea id="investigation-description" rows={4} maxLength={8192} value={description} onChange={(event) => setDescription(event.target.value)} className="w-full rounded border border-[var(--border-subtle)] bg-[var(--surface-2)] px-3 py-2 text-sm text-[var(--text-primary)]" /></div>
      <label className="flex items-start gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3 text-xs text-[var(--text-secondary)]">
        <input type="checkbox" checked={autoStart} onChange={(event) => setAutoStart(event.target.checked)} className="mt-0.5" />
        <span><strong className="block text-[var(--text-primary)]">Iniciar pipeline autônomo</strong>Planeja e executa os subagentes de pesquisa, coleta, análise e relatório usando este objetivo.</span>
      </label>
      {error && <div role="alert" className="text-xs text-red-300">{error}</div>}
      <div className="flex justify-end gap-2"><button type="button" onClick={onClose} className="rounded px-3 py-2 text-xs text-[var(--text-muted)]">{created ? "Fechar" : "Cancelar"}</button>{!created && <button type="submit" disabled={saving || !title.trim()} className="rounded bg-[var(--accent-primary)] px-3 py-2 text-xs font-medium text-white disabled:opacity-40">{saving ? "Criando…" : autoStart ? "Criar e investigar" : "Criar caso"}</button>}</div>
    </form>
  </div>;
}

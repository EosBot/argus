"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "argus.workspace.guide.v1";

const STEPS = [
  {
    eyebrow: "Caso",
    title: "Comece pela investigação",
    body: "Crie ou selecione um caso. Coletas, evidências e ações autorizadas ficam vinculadas a ele automaticamente.",
  },
  {
    eyebrow: "Objetivo",
    title: "Descreva o que precisa descobrir",
    body: "Em Collection, deixe Pesquisa autônoma ativa. O Prometheus planeja e distribui o trabalho entre os agentes sem exigir IDs ou comandos.",
  },
  {
    eyebrow: "Fontes",
    title: "Acompanhe a pesquisa",
    body: "O Terminal mostra as fontes consultadas; o Inspector resume a consulta atual. Links .onion abrem somente no Safe Browser isolado.",
  },
  {
    eyebrow: "Escopo",
    title: "Separe coleta de ação ativa",
    body: "Exploitation só executa após selecionar um caso e confirmar autorização explícita. Use-a apenas em ativos sob seu controle.",
  },
  {
    eyebrow: "Prova",
    title: "Revise e exporte",
    body: "Resultados são persistidos como evidência com hashes. Exporte o workspace ou gere os formatos forenses a partir da investigação.",
  },
] as const;

interface WorkspaceGuideProps {
  open: boolean;
  onClose: () => void;
}

export default function WorkspaceGuide({ open, onClose }: WorkspaceGuideProps) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    if (open) setStep(0);
  }, [open]);

  if (!open) return null;
  const current = STEPS[step];
  const finish = () => {
    window.localStorage.setItem(STORAGE_KEY, "completed");
    onClose();
  };
  const dismiss = () => {
    window.localStorage.setItem(STORAGE_KEY, `dismissed:${step + 1}`);
    onClose();
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="workspace-guide-title"
      className="fixed inset-0 z-[120] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onKeyDown={(event) => { if (event.key === "Escape") dismiss(); }}
    >
      <div className="w-full max-w-lg overflow-hidden rounded-lg border border-cyan-400/30 bg-[#071019] shadow-[0_0_50px_rgba(34,211,238,0.12)]">
        <div className="h-1 bg-slate-800" aria-hidden="true">
          <div className="h-full bg-cyan-400 transition-[width] motion-reduce:transition-none" style={{ width: `${((step + 1) / STEPS.length) * 100}%` }} />
        </div>
        <div className="p-6">
          <div className="mb-5 flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-300">
            <span>{current.eyebrow}</span>
            <span>{step + 1} / {STEPS.length}</span>
          </div>
          <h2 id="workspace-guide-title" className="text-xl font-semibold text-slate-100">{current.title}</h2>
          <p className="mt-3 min-h-20 text-sm leading-6 text-slate-300">{current.body}</p>
          <div className="mt-7 flex items-center gap-2">
            <button type="button" onClick={dismiss} className="mr-auto rounded px-2 py-2 text-xs text-slate-400 hover:text-slate-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-300">Pular</button>
            {step > 0 && <button type="button" onClick={() => setStep((value) => value - 1)} className="rounded border border-slate-700 px-3 py-2 text-xs text-slate-200 hover:bg-slate-800">Voltar</button>}
            <button type="button" autoFocus onClick={() => step === STEPS.length - 1 ? finish() : setStep((value) => value + 1)} className="rounded bg-cyan-300 px-4 py-2 text-xs font-semibold text-slate-950 hover:bg-cyan-200">
              {step === STEPS.length - 1 ? "Concluir" : "Próximo"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

"use client";

import { useEffect, useState } from "react";

export interface OpsecSettings {
  torProxy: string;
  socksPort: number;
  httpPort: number;
  rateLimitPerMinute: number;
  userAgentRotation: boolean;
  requestDelay: number;
  maxConcurrentRequests: number;
  enableDnsLeakProtection: boolean;
  enableWebRtcLeakProtection: boolean;
  clearCookiesOnExit: boolean;
}

export interface OpsecConfigProps {
  settings: OpsecSettings;
  onSave: (settings: OpsecSettings) => Promise<boolean>;
}

const DEFAULT_SETTINGS: OpsecSettings = {
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
};

export default function OpsecConfig({ settings, onSave }: OpsecConfigProps) {
  const [local, setLocal] = useState(settings);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => setLocal(settings), [settings]);

  const update = (key: keyof OpsecSettings, value: unknown) => {
    const next = { ...local, [key]: value };
    setLocal(next);
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      if (!await onSave(local)) setError("As alterações de OPSEC não foram persistidas.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Não foi possível salvar OPSEC.");
    } finally {
      setSaving(false);
    }
  };

  const Toggle = ({
    label,
    description,
    checked,
    onChange: onToggle,
  }: {
    label: string;
    description: string;
    checked: boolean;
    onChange: (v: boolean) => void;
  }) => (
    <div className="flex items-center justify-between rounded-md bg-[var(--surface-1)] p-3">
      <div>
        <div className="text-xs font-medium text-[var(--text-primary)]">{label}</div>
        <div className="text-[10px] text-[var(--text-muted)]">{description}</div>
      </div>
      <button
        type="button"
        onClick={() => onToggle(!checked)}
        role="switch"
        aria-checked={checked}
        aria-label={label}
        className={`relative h-5 w-9 rounded-full transition-colors ${
          checked ? "bg-[var(--accent-primary)]" : "bg-[var(--surface-3)]"
        }`}
      >
        <span
          className={`absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform ${
            checked ? "left-[18px]" : "left-0.5"
          }`}
        />
      </button>
    </div>
  );

  const Input = ({
    label,
    value,
    onChange: onInput,
    type = "text",
    suffix,
  }: {
    label: string;
    value: string | number;
    onChange: (v: string) => void;
    type?: string;
    suffix?: string;
  }) => (
    <div>
      <label htmlFor={`opsec-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`} className="mb-1 block text-[10px] font-medium uppercase tracking-wider text-[var(--text-muted)]">
        {label}
      </label>
      <div className="flex items-center gap-2">
        <input
          id={`opsec-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}
          type={type}
          value={value}
          onChange={(e) => onInput(e.target.value)}
          className="flex-1 rounded-md border border-[var(--border-subtle)] bg-[var(--surface-1)] px-2.5 py-1.5 font-mono text-xs text-[var(--text-primary)] focus:border-[var(--accent-primary)] focus:outline-none"
        />
        {suffix && (
          <span className="text-[10px] text-[var(--text-muted)]">{suffix}</span>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">
          Operational Security
        </h3>
        <p className="mt-1 text-xs text-[var(--text-muted)]">
          Configure proxy, rate limiting, and stealth settings
        </p>
      </div>

      <div className="space-y-3">
        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3">
          <div className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Tor Proxy
          </div>
          <div className="space-y-2">
            <Input
              label="SOCKS Proxy"
              value={local.torProxy}
              onChange={(v) => update("torProxy", v)}
            />
            <div className="grid grid-cols-2 gap-2">
              <Input
                label="SOCKS Port"
                value={local.socksPort}
                onChange={(v) => update("socksPort", parseInt(v) || 9050)}
                type="number"
              />
              <Input
                label="HTTP Port"
                value={local.httpPort}
                onChange={(v) => update("httpPort", parseInt(v) || 8118)}
                type="number"
              />
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3">
          <div className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Rate Limiting
          </div>
          <div className="space-y-2">
            <Input
              label="Max requests per minute"
              value={local.rateLimitPerMinute}
              onChange={(v) => update("rateLimitPerMinute", parseInt(v) || 30)}
              type="number"
            />
            <Input
              label="Delay between requests"
              value={local.requestDelay}
              onChange={(v) => update("requestDelay", parseInt(v) || 1500)}
              type="number"
              suffix="ms"
            />
            <Input
              label="Max concurrent requests"
              value={local.maxConcurrentRequests}
              onChange={(v) => update("maxConcurrentRequests", parseInt(v) || 5)}
              type="number"
            />
          </div>
        </div>

        <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-2)] p-3">
          <div className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">
            Stealth Settings
          </div>
          <div className="space-y-2">
            <Toggle
              label="User-Agent Rotation"
              description="Rotate browser fingerprints per request"
              checked={local.userAgentRotation}
              onChange={(v) => update("userAgentRotation", v)}
            />
            <Toggle
              label="DNS Leak Protection"
              description="Route all DNS through Tor"
              checked={local.enableDnsLeakProtection}
              onChange={(v) => update("enableDnsLeakProtection", v)}
            />
            <Toggle
              label="WebRTC Leak Protection"
              description="Disable WebRTC to prevent IP leaks"
              checked={local.enableWebRtcLeakProtection}
              onChange={(v) => update("enableWebRtcLeakProtection", v)}
            />
            <Toggle
              label="Clear Cookies on Exit"
              description="Automatically clear session data"
              checked={local.clearCookiesOnExit}
              onChange={(v) => update("clearCookiesOnExit", v)}
            />
          </div>
        </div>
      </div>
      <div className="sticky bottom-0 flex items-center justify-between border-t border-[var(--border-subtle)] bg-[var(--surface-1)]/95 py-3 backdrop-blur">
        <span className="text-[10px] text-[var(--text-muted)]">Alterações só entram em vigor após confirmação do backend.</span>
        <button type="button" onClick={() => void save()} disabled={saving} className="rounded-md bg-[var(--accent-primary)] px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50">{saving ? "Salvando…" : "Salvar OPSEC"}</button>
      </div>
      {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    </div>
  );
}

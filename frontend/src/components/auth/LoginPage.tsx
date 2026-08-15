"use client";

/* ============================================================
   ARGUS 2.0 — LoginPage
   Terminal-styled authentication screen. On success the
   AUTH_CHANGED_EVENT fires and AuthGate swaps to <Workspace/>.
   ============================================================ */

import { useState, type FormEvent } from "react";
import { useAuth } from "../../hooks/useAuth";
import styles from "./Auth.module.css";

export default function LoginPage() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (submitting) return;

    setError(null);
    setSubmitting(true);
    try {
      await login(username.trim(), password);
      // Success → AuthGate re-renders into <Workspace/> automatically.
    } catch (err) {
      setError(err instanceof Error ? err.message : "Falha na autenticação");
      setSubmitting(false);
    }
  };

  return (
    <div className={styles.auth}>
      <div className={styles.card}>
        <div className={styles.brand}>
          <h1 className={styles.title}>ARGUS</h1>
          <span className={styles.badge}>v2.0</span>
        </div>

        <p className={styles.subtitle}>
          Investigação autônoma de Dark Web e OSINT — acesso restrito.
        </p>

        <form className={styles.form} onSubmit={handleSubmit}>
          <div className={styles.field}>
            <label className={styles.label} htmlFor="auth-username">
              Usuário
            </label>
            <input
              id="auth-username"
              className={styles.input}
              type="text"
              autoComplete="username"
              placeholder="admin"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              required
            />
          </div>

          <div className={styles.field}>
            <label className={styles.label} htmlFor="auth-password">
              Senha
            </label>
            <input
              id="auth-password"
              className={styles.input}
              type="password"
              autoComplete="current-password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {error && (
            <div className={styles.error} role="alert">
              {error}
            </div>
          )}

          <button type="submit" className={styles.submit} disabled={submitting}>
            {submitting ? "Autenticando…" : "Acessar"}
          </button>
        </form>

        <div className={styles.hint}>
          As credenciais iniciais são geradas localmente durante a instalação e
          ficam apenas nos arquivos protegidos do host (<code>.env</code> / credenciais de setup).
        </div>
      </div>
    </div>
  );
}

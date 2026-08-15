"use client";

/* ============================================================
   ARGUS 2.0 — AuthGate
   Renders <LoginPage/> when unauthenticated, otherwise renders
   children (<Workspace/>). Shows a brief loading state while the
   stored token is validated against /api/auth/me.
   ============================================================ */

import type { ReactNode } from "react";
import { useAuth } from "../../hooks/useAuth";
import LoginPage from "./LoginPage";
import styles from "./Auth.module.css";

export default function AuthGate({ children }: { children: ReactNode }) {
  const { status } = useAuth();

  if (status === "loading") {
    return <div className={styles.loading}>Inicializando ARGUS…</div>;
  }

  if (status === "unauthenticated") {
    return <LoginPage />;
  }

  return <>{children}</>;
}

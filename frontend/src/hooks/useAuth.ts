"use client";

/* ============================================================
   ARGUS 2.0 — useAuth hook
   Authentication state: loading / authenticated / unauthenticated.
   Subscribes to AUTH_CHANGED_EVENT so login/logout/refresh syncs
   across the whole app automatically.
   ============================================================ */

import { useCallback, useEffect, useState } from "react";
import {
  AUTH_CHANGED_EVENT,
  fetchCurrentUser,
  getAccessToken,
  login as authLogin,
  logout as authLogout,
  type UserInfo,
} from "../lib/auth";

export type AuthStatus = "loading" | "authenticated" | "unauthenticated";

export interface UseAuthResult {
  status: AuthStatus;
  user: UserInfo | null;
  login: (username: string, password: string) => Promise<UserInfo>;
  logout: () => void;
}

export function useAuth(): UseAuthResult {
  const [status, setStatus] = useState<AuthStatus>("loading");
  const [user, setUser] = useState<UserInfo | null>(null);

  const sync = useCallback(async () => {
    if (!getAccessToken()) {
      setStatus("unauthenticated");
      setUser(null);
      return;
    }
    try {
      const me = await fetchCurrentUser();
      setUser(me);
      setStatus("authenticated");
    } catch {
      // Token invalid/expired and refresh failed — force login.
      setUser(null);
      setStatus("unauthenticated");
    }
  }, []);

  useEffect(() => {
    sync();
    window.addEventListener(AUTH_CHANGED_EVENT, sync);
    return () => window.removeEventListener(AUTH_CHANGED_EVENT, sync);
  }, [sync]);

  const login = useCallback(async (username: string, password: string) => {
    const me = await authLogin(username, password);
    setUser(me);
    setStatus("authenticated");
    return me;
  }, []);

  const logout = useCallback(() => {
    authLogout();
    setUser(null);
    setStatus("unauthenticated");
  }, []);

  return { status, user, login, logout };
}

"use client";

/* ============================================================
   ARGUS 2.0 — Authentication client
   JWT token storage (localStorage) + login/logout/refresh.

   Backend contract:
     POST /api/auth/login    {username, password} -> TokenResponse
     POST /api/auth/refresh  {refresh_token}      -> TokenResponse
     GET  /api/auth/me       (Bearer)             -> UserInfoResponse
   ============================================================ */

import { API_BASE } from "./config";

export const AUTH_CHANGED_EVENT = "argus:auth-changed";

const ACCESS_KEY = "argus.access_token.v1";
const REFRESH_KEY = "argus.refresh_token.v1";

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserInfo {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
}

/* ---------- Token storage ---------- */

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string): void {
  window.localStorage.setItem(ACCESS_KEY, access);
  window.localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens(): void {
  window.localStorage.removeItem(ACCESS_KEY);
  window.localStorage.removeItem(REFRESH_KEY);
}

/** Broadcast auth changes so all consumers (useAuth, apiFetch) re-sync. */
export function notifyAuthChanged(): void {
  if (typeof window !== "undefined") {
    window.dispatchEvent(new Event(AUTH_CHANGED_EVENT));
  }
}

/* ---------- Auth API calls ---------- */

export async function login(username: string, password: string): Promise<UserInfo> {
  const response = await fetch(`${API_BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    let detail = `Login falhou (${response.status})`;
    try {
      const body = await response.json();
      if (body?.detail) detail = String(body.detail);
    } catch {
      /* keep default message */
    }
    throw new Error(detail);
  }

  const tokens = (await response.json()) as TokenResponse;
  setTokens(tokens.access_token, tokens.refresh_token);
  notifyAuthChanged();

  return fetchCurrentUser();
}

/** Exchange the refresh token for a new access token. Returns null on failure. */
export async function refreshAccessToken(): Promise<string | null> {
  const refresh = getRefreshToken();
  if (!refresh) return null;

  try {
    const response = await fetch(`${API_BASE}/api/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    });
    if (!response.ok) return null;

    const tokens = (await response.json()) as TokenResponse;
    setTokens(tokens.access_token, tokens.refresh_token);
    return tokens.access_token;
  } catch {
    return null;
  }
}

export async function fetchCurrentUser(): Promise<UserInfo> {
  const token = getAccessToken();
  if (!token) throw new Error("Não autenticado");

  const response = await fetch(`${API_BASE}/api/auth/me`, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
  });
  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

export function logout(): void {
  clearTokens();
  notifyAuthChanged();
}

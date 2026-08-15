/* ============================================================
   ARGUS — shared API client helper
   Attaches JWT bearer token; on 401 tries a single refresh and
   retries the request once. If refresh fails, clears session.
   ============================================================ */

import { clearTokens, getAccessToken, getRefreshToken, notifyAuthChanged, refreshAccessToken } from "./auth";
import { API_BASE } from "./config";

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;

  const doFetch = async (token: string | null): Promise<Response> => {
    return fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(options?.headers ?? {}),
      },
    });
  };

  let response = await doFetch(getAccessToken());

  // 401 → try refresh once, then retry the original request
  if (response.status === 401 && getRefreshToken()) {
    const newAccess = await refreshAccessToken();
    if (newAccess) {
      response = await doFetch(newAccess);
    } else {
      clearTokens();
      notifyAuthChanged();
    }
  }

  if (!response.ok) {
    throw new Error(`API error: ${response.status} ${response.statusText}`);
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}

/** Download an authenticated, server-generated artifact without parsing it as JSON. */
export async function apiDownload(path: string, fallbackFilename: string): Promise<string> {
  const url = `${API_BASE}${path}`;
  const doFetch = (token: string | null) =>
    fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });

  let response = await doFetch(getAccessToken());
  if (response.status === 401 && getRefreshToken()) {
    const newAccess = await refreshAccessToken();
    if (newAccess) response = await doFetch(newAccess);
    else {
      clearTokens();
      notifyAuthChanged();
    }
  }
  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    throw new Error(detail || `API error: ${response.status} ${response.statusText}`);
  }

  const disposition = response.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match?.[1] || fallbackFilename;
  const objectUrl = URL.createObjectURL(await response.blob());
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
  return filename;
}

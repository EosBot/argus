/* ============================================================
   ARGUS 2.0 — Shared config
   Single source of truth for the API base URL (avoids circular
   imports between lib/auth.ts and lib/api.ts).
   ============================================================ */

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

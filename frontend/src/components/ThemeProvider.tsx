"use client";

import * as React from "react";
import type { ReactNode } from "react";

/* ============================================================
   ARGUS 2.0 — ThemeProvider
   CSS-variable theming · dark "matrix" default · 6 palettes
   Persists selection in localStorage · animated theme switch
   · honours prefers-reduced-motion
   ============================================================ */

export type ThemeId =
  | "matrix"
  | "dracula"
  | "nord"
  | "gruvbox"
  | "tokyo-night"
  | "terminal";

export interface Theme {
  id: ThemeId;
  label: string;
  description: string;
  variables: Record<string, string>;
}

const STORAGE_KEY = "argus-theme";
export const DEFAULT_THEME: ThemeId = "matrix";

/* ------------------------------------------------------------------
   Palettes — each theme overrides the color tokens declared in
   tokens.css. Keys must match the design-system token names.
   ------------------------------------------------------------------ */

const SURFACE_TOKENS = (s0: string, s1: string, s2: string, s3: string) => ({
  "--surface-0": s0,
  "--surface-1": s1,
  "--surface-2": s2,
  "--surface-3": s3,
});

export const THEMES: Theme[] = [
  {
    id: "matrix",
    label: "Matrix",
    description: "Terminal green on deep slate — the ARGUS default",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#030712", "#0b1120", "#111a2e", "#1a2438"),
      "--accent-primary": "#00FF41",
      "--accent-primary-dim": "#00cc34",
      "--accent-secondary": "#00F0FF",
      "--accent-secondary-dim": "#00b8c4",
      "--status-success": "#00FF41",
      "--status-warning": "#FFB020",
      "--status-danger": "#FF3B30",
      "--status-info": "#00F0FF",
      "--status-neutral": "#64748b",
      "--text-primary": "#f8fafc",
      "--text-secondary": "#94a3b8",
      "--text-muted": "#64748b",
      "--text-on-accent": "#030712",
      "--border-subtle": "rgba(148, 163, 184, 0.16)",
      "--border-strong": "rgba(148, 163, 184, 0.32)",
      "--border-accent": "rgba(0, 255, 65, 0.5)",
      "--glow-primary": "0 0 8px rgba(0, 255, 65, 0.55), 0 0 24px rgba(0, 255, 65, 0.25)",
      "--glow-secondary": "0 0 8px rgba(0, 240, 255, 0.55), 0 0 24px rgba(0, 240, 255, 0.25)",
      "--glow-danger": "0 0 8px rgba(255, 59, 48, 0.55), 0 0 24px rgba(255, 59, 48, 0.25)",
    },
  },
  {
    id: "dracula",
    label: "Dracula",
    description: "Dark purple base with neon accents",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#282a36", "#21222c", "#191a21", "#44475a"),
      "--accent-primary": "#bd93f9",
      "--accent-primary-dim": "#9d6cf0",
      "--accent-secondary": "#8be9fd",
      "--accent-secondary-dim": "#62d6f5",
      "--status-success": "#50fa7b",
      "--status-warning": "#f1fa8c",
      "--status-danger": "#ff5555",
      "--status-info": "#8be9fd",
      "--status-neutral": "#6272a4",
      "--text-primary": "#f8f8f2",
      "--text-secondary": "#b3b3c0",
      "--text-muted": "#6272a4",
      "--text-on-accent": "#282a36",
      "--border-subtle": "rgba(189, 147, 249, 0.18)",
      "--border-strong": "rgba(189, 147, 249, 0.34)",
      "--border-accent": "rgba(189, 147, 249, 0.5)",
      "--glow-primary": "0 0 8px rgba(189, 147, 249, 0.55), 0 0 24px rgba(189, 147, 249, 0.25)",
      "--glow-secondary": "0 0 8px rgba(139, 233, 253, 0.55), 0 0 24px rgba(139, 233, 253, 0.25)",
      "--glow-danger": "0 0 8px rgba(255, 85, 85, 0.55), 0 0 24px rgba(255, 85, 85, 0.25)",
    },
  },
  {
    id: "nord",
    label: "Nord",
    description: "Frosty polar blues, calm and muted",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#2e3440", "#3b4252", "#434c5e", "#4c566a"),
      "--accent-primary": "#88c0d0",
      "--accent-primary-dim": "#5e81ac",
      "--accent-secondary": "#81a1c1",
      "--accent-secondary-dim": "#6d8cab",
      "--status-success": "#a3be8c",
      "--status-warning": "#ebcb8b",
      "--status-danger": "#bf616a",
      "--status-info": "#88c0d0",
      "--status-neutral": "#4c566a",
      "--text-primary": "#eceff4",
      "--text-secondary": "#d8dee9",
      "--text-muted": "#828fa3",
      "--text-on-accent": "#2e3440",
      "--border-subtle": "rgba(136, 192, 208, 0.16)",
      "--border-strong": "rgba(136, 192, 208, 0.34)",
      "--border-accent": "rgba(136, 192, 208, 0.5)",
      "--glow-primary": "0 0 8px rgba(136, 192, 208, 0.55), 0 0 24px rgba(136, 192, 208, 0.25)",
      "--glow-secondary": "0 0 8px rgba(129, 161, 193, 0.55), 0 0 24px rgba(129, 161, 193, 0.25)",
      "--glow-danger": "0 0 8px rgba(191, 97, 106, 0.55), 0 0 24px rgba(191, 97, 106, 0.25)",
    },
  },
  {
    id: "gruvbox",
    label: "Gruvbox",
    description: "Warm earthy retro palette",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#282828", "#32302f", "#3c3836", "#504945"),
      "--accent-primary": "#fe8019",
      "--accent-primary-dim": "#d65d0e",
      "--accent-secondary": "#b8bb26",
      "--accent-secondary-dim": "#98971a",
      "--status-success": "#b8bb26",
      "--status-warning": "#fabd2f",
      "--status-danger": "#fb4934",
      "--status-info": "#83a598",
      "--status-neutral": "#928374",
      "--text-primary": "#ebdbb2",
      "--text-secondary": "#d5c4a1",
      "--text-muted": "#928374",
      "--text-on-accent": "#282828",
      "--border-subtle": "rgba(235, 219, 178, 0.14)",
      "--border-strong": "rgba(235, 219, 178, 0.3)",
      "--border-accent": "rgba(254, 128, 25, 0.5)",
      "--glow-primary": "0 0 8px rgba(254, 128, 25, 0.55), 0 0 24px rgba(254, 128, 25, 0.25)",
      "--glow-secondary": "0 0 8px rgba(184, 187, 38, 0.55), 0 0 24px rgba(184, 187, 38, 0.25)",
      "--glow-danger": "0 0 8px rgba(251, 73, 52, 0.55), 0 0 24px rgba(251, 73, 52, 0.25)",
    },
  },
  {
    id: "tokyo-night",
    label: "Tokyo Night",
    description: "Deep indigo with electric blue and cyan",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#1a1b26", "#16161e", "#24283b", "#292e42"),
      "--accent-primary": "#7aa2f7",
      "--accent-primary-dim": "#5f87e8",
      "--accent-secondary": "#7dcfff",
      "--accent-secondary-dim": "#56c4e0",
      "--status-success": "#9ece6a",
      "--status-warning": "#e0af68",
      "--status-danger": "#f7768e",
      "--status-info": "#7dcfff",
      "--status-neutral": "#565f89",
      "--text-primary": "#c0caf5",
      "--text-secondary": "#a9b1d6",
      "--text-muted": "#565f89",
      "--text-on-accent": "#1a1b26",
      "--border-subtle": "rgba(122, 162, 247, 0.16)",
      "--border-strong": "rgba(122, 162, 247, 0.34)",
      "--border-accent": "rgba(122, 162, 247, 0.5)",
      "--glow-primary": "0 0 8px rgba(122, 162, 247, 0.55), 0 0 24px rgba(122, 162, 247, 0.25)",
      "--glow-secondary": "0 0 8px rgba(125, 207, 255, 0.55), 0 0 24px rgba(125, 207, 255, 0.25)",
      "--glow-danger": "0 0 8px rgba(247, 118, 142, 0.55), 0 0 24px rgba(247, 118, 142, 0.25)",
    },
  },
  {
    id: "terminal",
    label: "Terminal",
    description: "Green phosphor on black — classic CRT terminal",
    variables: {
      "color-scheme": "dark",
      ...SURFACE_TOKENS("#0a0a0a", "#0d0d0d", "#111111", "#1a1a1a"),
      "--accent-primary": "#00FF41",
      "--accent-primary-dim": "#00cc34",
      "--accent-secondary": "#00F0FF",
      "--accent-secondary-dim": "#00b8c4",
      "--status-success": "#00FF41",
      "--status-warning": "#FFB020",
      "--status-danger": "#FF3B30",
      "--status-info": "#00F0FF",
      "--status-neutral": "#64748b",
      "--text-primary": "#00FF41",
      "--text-secondary": "#00cc34",
      "--text-muted": "#009922",
      "--text-on-accent": "#0a0a0a",
      "--border-subtle": "rgba(0, 255, 65, 0.12)",
      "--border-strong": "rgba(0, 255, 65, 0.28)",
      "--border-accent": "rgba(0, 255, 65, 0.5)",
      "--glow-primary": "0 0 8px rgba(0, 255, 65, 0.55), 0 0 24px rgba(0, 255, 65, 0.25)",
      "--glow-secondary": "0 0 8px rgba(0, 240, 255, 0.55), 0 0 24px rgba(0, 240, 255, 0.25)",
      "--glow-danger": "0 0 8px rgba(255, 59, 48, 0.55), 0 0 24px rgba(255, 59, 48, 0.25)",
    },
  },
];

/* ------------------------------------------------------------------
   Static CSS: per-theme variable blocks + animated transition class.
   Generated once at module scope → deterministic for SSR/hydration.
   ------------------------------------------------------------------ */

const BASE_CSS =
  ":root{--accent-green:var(--status-success);--accent-cyan:var(--accent-secondary);--accent-amber:var(--status-warning)}";

const THEME_CSS =
  BASE_CSS +
  "\n" +
  THEMES.map((theme) => {
    const vars = Object.entries(theme.variables)
      .map(([key, value]) => `${key}:${value}`)
      .join(";");
    return `[data-theme="${theme.id}"]{${vars}}`;
  }).join("\n");

const TRANSITION_CSS = `
html.theme-transition,
html.theme-transition *,
html.theme-transition *::before,
html.theme-transition *::after {
  transition-property: background-color, border-color, color, fill, stroke, box-shadow;
  transition-duration: var(--duration-base, 200ms);
  transition-timing-function: var(--ease-standard, ease);
}
`;

/* ------------------------------------------------------------------ */

const THEME_IDS = new Set<string>(THEMES.map((t) => t.id));

export function isThemeId(value: string): value is ThemeId {
  return THEME_IDS.has(value);
}

function getInitialTheme(storageKey: string): ThemeId {
  if (typeof window === "undefined") return DEFAULT_THEME;
  try {
    const stored = window.localStorage.getItem(storageKey);
    if (stored && isThemeId(stored)) return stored;
  } catch {
    /* storage unavailable (private mode / quota) → fall through */
  }
  return DEFAULT_THEME;
}

export interface ThemeContextValue {
  /** Active theme id. */
  theme: ThemeId;
  /** Active theme definition (palette + metadata). */
  resolved: Theme;
  /** All available themes, in toggle order. */
  themes: Theme[];
  setTheme: (id: ThemeId) => void;
  toggleTheme: () => void;
}

const ThemeContext = React.createContext<ThemeContextValue | null>(null);

interface ThemeProviderProps {
  children: ReactNode;
  /** Theme used when nothing is stored. Defaults to "matrix". */
  defaultTheme?: ThemeId;
  /** localStorage key. Defaults to "argus-theme". */
  storageKey?: string;
}

export function ThemeProvider({
  children,
  defaultTheme = DEFAULT_THEME,
  storageKey = STORAGE_KEY,
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<ThemeId>(() =>
    getInitialTheme(storageKey),
  );

  // Animate the switch: enable transitions *before* the attribute flips,
  // then disable once the animation window has elapsed. Skipped entirely
  // when the user prefers reduced motion.
  React.useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const root = document.documentElement;
    root.classList.add("theme-transition");
    const timeout = window.setTimeout(
      () => root.classList.remove("theme-transition"),
      350,
    );
    return () => {
      root.classList.remove("theme-transition");
      window.clearTimeout(timeout);
    };
  }, [theme]);

  // Persist + apply after the transition class is in place.
  React.useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      window.localStorage.setItem(storageKey, theme);
    } catch {
      /* non-fatal: theme still applies for this session */
    }
  }, [theme, storageKey]);

  const setTheme = React.useCallback(
    (id: ThemeId) => {
      if (isThemeId(id)) setThemeState(id);
    },
    [],
  );

  const toggleTheme = React.useCallback(() => {
    setThemeState((prev) => {
      const index = THEMES.findIndex((t) => t.id === prev);
      const next = THEMES[(index + 1) % THEMES.length];
      return defaultTheme ? next.id : next.id;
    });
  }, []);

  const value = React.useMemo<ThemeContextValue>(() => {
    const resolved =
      THEMES.find((t) => t.id === theme) ?? THEMES[0];
    return { theme, resolved, themes: THEMES, setTheme, toggleTheme };
  }, [theme, setTheme, toggleTheme]);

  return (
    <ThemeContext.Provider value={value}>
      {/* Static variable + transition rules; safe to render during SSR. */}
      <style id="argus-theme-vars">{THEME_CSS}</style>
      <style id="argus-theme-transition">{TRANSITION_CSS}</style>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  const context = React.useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within a <ThemeProvider>");
  }
  return context;
}

/* ------------------------------------------------------------------
   useReducedMotion — reactive prefers-reduced-motion detection

   Components use this to conditionally render animations:
     const reduced = useReducedMotion();
     if (reduced) return <StaticVersion />;
     return <AnimatedVersion />;
   ------------------------------------------------------------------ */

const REDUCED_MOTION_QUERY = "(prefers-reduced-motion: reduce)";

export function useReducedMotion(): boolean {
  const [reduced, setReduced] = React.useState<boolean>(() => {
    if (typeof window === "undefined") return false;
    return window.matchMedia(REDUCED_MOTION_QUERY).matches;
  });

  React.useEffect(() => {
    const mql = window.matchMedia(REDUCED_MOTION_QUERY);
    const handler = (event: MediaQueryListEvent) => {
      setReduced(event.matches);
    };
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, []);

  return reduced;
}

export default ThemeProvider;

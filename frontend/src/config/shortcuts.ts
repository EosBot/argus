import type { ThemeId } from "../components/ThemeProvider";
import type { ShortcutMap } from "../hooks/useKeyboardShortcuts";

/** Logical action that a keyboard combo can trigger. */
export type ShortcutAction =
  | "focusSearch"
  | "newInvestigation"
  | "closeModal"
  | "toggleSettings"
  | "exportView"
  | `setTheme:${ThemeId}`;

/**
 * Declarative shortcut registry: lowercase combo → action.
 * Combos avoid browser-reserved chords (ctrl+w, ctrl+t, ctrl+shift+t).
 */
export const SHORTCUTS: Record<string, ShortcutAction> = {
  "ctrl+k": "focusSearch",
  "ctrl+n": "newInvestigation",
  "ctrl+,": "toggleSettings",
  "ctrl+1": "setTheme:matrix",
  "ctrl+2": "setTheme:dracula",
  "ctrl+3": "setTheme:nord",
  "ctrl+4": "setTheme:gruvbox",
  "ctrl+5": "setTheme:tokyo-night",
  "ctrl+6": "setTheme:terminal",
  escape: "closeModal",
  "ctrl+shift+e": "exportView",
};

/** Implementations for every ShortcutAction, supplied by the app. */
export interface ShortcutActions {
  focusSearch: () => void;
  newInvestigation: () => void;
  closeModal: () => void;
  toggleSettings: () => void;
  exportView: () => void;
  setTheme: (id: ThemeId) => void;
}

/** Resolve the declarative SHORTCUTS registry into executable handlers. */
export function createShortcuts(actions: ShortcutActions): ShortcutMap {
  const handlers: Record<ShortcutAction, () => void> = {
    focusSearch: actions.focusSearch,
    newInvestigation: actions.newInvestigation,
    closeModal: actions.closeModal,
    toggleSettings: actions.toggleSettings,
    exportView: actions.exportView,
    "setTheme:matrix": () => actions.setTheme("matrix"),
    "setTheme:dracula": () => actions.setTheme("dracula"),
    "setTheme:nord": () => actions.setTheme("nord"),
    "setTheme:gruvbox": () => actions.setTheme("gruvbox"),
    "setTheme:tokyo-night": () => actions.setTheme("tokyo-night"),
    "setTheme:terminal": () => actions.setTheme("terminal"),
  };

  const map: ShortcutMap = {};
  for (const [combo, action] of Object.entries(SHORTCUTS)) {
    map[combo] = handlers[action];
  }
  return map;
}
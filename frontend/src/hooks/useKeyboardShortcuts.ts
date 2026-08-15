"use client";

import { useEffect, useRef } from "react";

export type ShortcutHandler = () => void;
export type ShortcutMap = Record<string, ShortcutHandler>;

interface ParsedShortcut {
  ctrl: boolean;
  alt: boolean;
  shift: boolean;
  meta: boolean;
  key: string;
}

function parseShortcut(combo: string): ParsedShortcut | null {
  const parts = combo.toLowerCase().split("+");
  let ctrl = false;
  let alt = false;
  let shift = false;
  let meta = false;
  const keys: string[] = [];
  for (const part of parts) {
    switch (part) {
      case "ctrl":
      case "control":
        ctrl = true;
        break;
      case "alt":
      case "option":
        alt = true;
        break;
      case "shift":
        shift = true;
        break;
      case "meta":
      case "cmd":
      case "command":
      case "win":
      case "super":
        meta = true;
        break;
      default:
        keys.push(part);
    }
  }
  if (keys.length !== 1) return null;
  return { ctrl, alt, shift, meta, key: keys[0] };
}

function normalizeCode(code: string): string | null {
  const match = /^(?:Key|Digit)([A-Z0-9])$/.exec(code);
  return match ? match[1].toLowerCase() : null;
}

function matches(event: KeyboardEvent, shortcut: ParsedShortcut): boolean {
  if (event.ctrlKey !== shortcut.ctrl) return false;
  if (event.altKey !== shortcut.alt) return false;
  if (event.shiftKey !== shortcut.shift) return false;
  if (event.metaKey !== shortcut.meta) return false;

  const key = event.key.toLowerCase();
  if (key === shortcut.key) return true;

  // Fall back to the physical key (e.g. "Digit1", "KeyK") so combos
  // keep working across keyboard layouts.
  const code = normalizeCode(event.code);
  return code !== null && code === shortcut.key;
}

function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.tagName === "INPUT" ||
    target.tagName === "TEXTAREA" ||
    target.tagName === "SELECT" ||
    target.isContentEditable
  );
}

/**
 * Global keyboard shortcut handler. The map is "combo" → handler, e.g.
 * `{ "ctrl+k": () => focusSearch(), escape: () => close() }`.
 * Combos are lowercase, "+"-joined, with optional ctrl/alt/shift/meta
 * modifiers. Matched combos call preventDefault. Events originating in
 * editable fields are ignored unless the combo is `escape`.
 */
export function useKeyboardShortcuts(map: ShortcutMap): void {
  const mapRef = useRef(map);
  mapRef.current = map;

  useEffect(() => {
    const parsed = new Map<string, ParsedShortcut>();
    for (const combo of Object.keys(mapRef.current)) {
      const shortcut = parseShortcut(combo);
      if (shortcut) parsed.set(combo, shortcut);
    }

    const handler = (event: KeyboardEvent): void => {
      // Escape must still work while a field is focused (closes modals/panels).
      if (event.key !== "Escape" && isEditableTarget(event.target)) return;

      for (const [combo, shortcut] of parsed) {
        if (matches(event, shortcut)) {
          event.preventDefault();
          mapRef.current[combo]?.();
          return;
        }
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
}

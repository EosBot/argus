"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { useTheme, type ThemeId } from "../ThemeProvider";

export interface CommandItem {
  id: string;
  label: string;
  shortcut?: string;
  category?: string;
  action: () => void;
}

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onNewInvestigation?: () => void;
  onExport?: () => void;
}

const THEME_COMMANDS: Array<{ id: ThemeId; label: string; shortcut: string }> = [
  { id: "matrix", label: "Matrix", shortcut: "Ctrl+1" },
  { id: "dracula", label: "Dracula", shortcut: "Ctrl+2" },
  { id: "nord", label: "Nord", shortcut: "Ctrl+3" },
  { id: "gruvbox", label: "Gruvbox", shortcut: "Ctrl+4" },
  { id: "tokyo-night", label: "Tokyo Night", shortcut: "Ctrl+5" },
  { id: "terminal", label: "Terminal", shortcut: "Ctrl+6" },
];

export default function CommandPalette({
  isOpen,
  onClose,
  onNewInvestigation,
  onExport,
}: CommandPaletteProps) {
  const { setTheme, theme } = useTheme();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const commands: CommandItem[] = useMemo(() => {
    const items: CommandItem[] = [
      {
        id: "new-investigation",
        label: "New Investigation",
        shortcut: "Ctrl+N",
        category: "Actions",
        action: () => {
          onNewInvestigation?.();
          onClose();
        },
      },
      ...THEME_COMMANDS.map((t) => ({
        id: `theme-${t.id}`,
        label: `Theme: ${t.label}`,
        shortcut: t.shortcut,
        category: "Themes",
        action: () => {
          setTheme(t.id);
          onClose();
        },
      })),
      {
        id: "export-view",
        label: "Export View",
        shortcut: "Ctrl+Shift+E",
        category: "Actions",
        action: () => {
          onExport?.();
          onClose();
        },
      },
    ];
    return items;
  }, [setTheme, onClose, onNewInvestigation, onExport]);

  const filtered = useMemo(() => {
    if (!query.trim()) return commands;
    const q = query.toLowerCase();
    return commands.filter(
      (c) =>
        c.label.toLowerCase().includes(q) ||
        c.category?.toLowerCase().includes(q),
    );
  }, [query, commands]);

  // Reset selection when filter changes
  useEffect(() => {
    setSelectedIndex(0);
  }, [filtered]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  const execute = useCallback(
    (item: CommandItem) => {
      item.action();
    },
    [],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setSelectedIndex((i) => Math.min(i + 1, filtered.length - 1));
          break;
        case "ArrowUp":
          e.preventDefault();
          setSelectedIndex((i) => Math.max(i - 1, 0));
          break;
        case "Enter":
          e.preventDefault();
          if (filtered[selectedIndex]) {
            execute(filtered[selectedIndex]);
          }
          break;
        case "Escape":
          e.preventDefault();
          onClose();
          break;
      }
    },
    [filtered, selectedIndex, execute, onClose],
  );

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return;
    const selected = listRef.current.children[selectedIndex] as HTMLElement | undefined;
    selected?.scrollIntoView({ block: "nearest" });
  }, [selectedIndex]);

  // Group by category
  const grouped = useMemo(() => {
    const groups: Record<string, CommandItem[]> = {};
    for (const item of filtered) {
      const cat = item.category ?? "Other";
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(item);
    }
    return groups;
  }, [filtered]);

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="cp-overlay" onClick={onClose}>
          <motion.div
            className="cp-container"
            initial={{ opacity: 0, scale: 0.95, y: -20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: -20 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-label="Command palette"
          >
            {/* Search input */}
            <div className="cp-input-wrap">
              <svg className="cp-search-icon" viewBox="0 0 16 16" fill="none" width="14" height="14">
                <circle cx="6.5" cy="6.5" r="4.5" stroke="currentColor" strokeWidth="1.5" />
                <path d="M10 10l4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
              <input
                ref={inputRef}
                type="text"
                className="cp-input"
                placeholder="Type a command..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                aria-label="Search commands"
                data-command-palette
              />
            </div>

            {/* Results */}
            <div className="cp-results" ref={listRef} role="listbox">
              {filtered.length === 0 && (
                <div className="cp-empty">No commands found</div>
              )}
              {Object.entries(grouped).map(([category, items]) => (
                <div key={category} className="cp-group">
                  <div className="cp-group-label">{category}</div>
                  {items.map((item) => {
                    const globalIndex = filtered.indexOf(item);
                    const isSelected = globalIndex === selectedIndex;
                    const isThemeActive =
                      item.id === `theme-${theme}`;
                    return (
                      <div
                        key={item.id}
                        className={`cp-item ${isSelected ? "cp-item-selected" : ""}`}
                        onClick={() => execute(item)}
                        onMouseEnter={() => setSelectedIndex(globalIndex)}
                        role="option"
                        aria-selected={isSelected}
                      >
                        <span className="cp-item-label">{item.label}</span>
                        <div className="cp-item-right">
                          {isThemeActive && (
                            <span className="cp-active-badge">active</span>
                          )}
                          {item.shortcut && (
                            <kbd className="cp-shortcut">{item.shortcut}</kbd>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ))}
            </div>

            {/* Footer */}
            <div className="cp-footer">
              <span>↑↓ Navigate</span>
              <span>↵ Select</span>
              <span>Esc Close</span>
            </div>
          </motion.div>

          {/* Scoped styles */}
          <style>{`
            .cp-overlay {
              position: fixed;
              inset: 0;
              z-index: 1100;
              display: flex;
              align-items: flex-start;
              justify-content: center;
              padding-top: 15vh;
              background: rgba(0, 0, 0, 0.6);
              backdrop-filter: blur(4px);
            }
            .cp-container {
              width: 100%;
              max-width: 520px;
              background: var(--surface-1, #0b1120);
              border: 1px solid var(--border-accent, rgba(0, 255, 65, 0.5));
              border-radius: 12px;
              box-shadow: var(--glow-primary, 0 0 8px rgba(0,255,65,0.55)), 0 16px 48px rgba(0,0,0,0.65);
              overflow: hidden;
              font-family: var(--font-mono, monospace);
            }
            .cp-input-wrap {
              display: flex;
              align-items: center;
              gap: 10px;
              padding: 12px 16px;
              border-bottom: 1px solid var(--border-subtle, rgba(148,163,184,0.16));
            }
            .cp-search-icon {
              color: var(--text-muted, #64748b);
              flex-shrink: 0;
            }
            .cp-input {
              flex: 1;
              background: transparent;
              border: none;
              outline: none;
              color: var(--text-primary, #f8fafc);
              font-family: var(--font-mono, monospace);
              font-size: 14px;
            }
            .cp-input::placeholder {
              color: var(--text-muted, #64748b);
            }
            .cp-results {
              max-height: 320px;
              overflow-y: auto;
              padding: 6px;
            }
            .cp-group-label {
              padding: 6px 10px 2px;
              font-size: 10px;
              font-weight: 600;
              letter-spacing: 0.08em;
              text-transform: uppercase;
              color: var(--text-muted, #64748b);
            }
            .cp-item {
              display: flex;
              align-items: center;
              justify-content: space-between;
              padding: 8px 10px;
              border-radius: 6px;
              cursor: pointer;
              transition: background 0.1s ease;
              font-size: 13px;
              color: var(--text-secondary, #94a3b8);
            }
            .cp-item-selected {
              background: rgba(0, 255, 65, 0.08);
              color: var(--accent-primary, #00FF41);
            }
            .cp-item-right {
              display: flex;
              align-items: center;
              gap: 8px;
            }
            .cp-active-badge {
              font-size: 10px;
              color: var(--accent-primary, #00FF41);
              text-transform: uppercase;
              letter-spacing: 0.05em;
            }
            .cp-shortcut {
              font-family: var(--font-mono, monospace);
              font-size: 10px;
              padding: 2px 6px;
              border-radius: 4px;
              background: var(--surface-3, #1a2438);
              color: var(--text-muted, #64748b);
              border: 1px solid var(--border-subtle, rgba(148,163,184,0.16));
            }
            .cp-empty {
              padding: 20px;
              text-align: center;
              color: var(--text-muted, #64748b);
              font-size: 13px;
            }
            .cp-footer {
              display: flex;
              gap: 16px;
              padding: 8px 16px;
              border-top: 1px solid var(--border-subtle, rgba(148,163,184,0.16));
              font-size: 10px;
              color: var(--text-muted, #64748b);
            }
            .cp-results::-webkit-scrollbar { width: 6px; }
            .cp-results::-webkit-scrollbar-thumb {
              background: var(--border-strong, rgba(148,163,184,0.32));
              border-radius: 3px;
            }
            .cp-results::-webkit-scrollbar-track { background: transparent; }
          `}</style>
        </div>
      )}
    </AnimatePresence>
  );
}

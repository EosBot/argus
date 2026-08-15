'use client'

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
} from 'react'
import { Terminal, type IDecoration, type IMarker } from 'xterm'

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

type LineKind = 'stdout' | 'stderr' | 'info'
type ConnStatus = 'connecting' | 'connected' | 'disconnected' | 'closed'

interface TerminalPaneProps {
  /** WebSocket URL to stream terminal output from. */
  wsUrl?: string
  /** Text shown in the terminal title bar (breadcrumb). */
  breadcrumb?: string
  /** Text shown in the terminal title bar (legacy). */
  title?: string
  /** Max number of lines kept in the searchable/exportable buffer. */
  scrollback?: number
  /** Automatically connect on mount (default true). */
  autoConnect?: boolean
  /** Convenience height, applied to the frame. */
  height?: string | number
  className?: string
  style?: CSSProperties
  /** Modelo LLM a usar nas mensagens de chat (padrão "auto"). */
  model?: string
  /** Investigation receiving research evidence. */
  investigationId?: string
}

interface BufferLine {
  text: string
  kind: LineKind
}

interface Match {
  line: number
  start: number
  end: number
}

const DEFAULT_WS_PATH = '/ws/terminal'

const ANSI: Record<LineKind, string> = {
  stdout: '\x1b[32m', // green
  stderr: '\x1b[31m', // red
  info: '\x1b[36m',   // cyan
}

const RESET = '\x1b[0m'

/* ------------------------------------------------------------------ */
/* ARGUS prompt (true-color ANSI)                                      */
/* ------------------------------------------------------------------ */

const ARGUS_GREEN = '\x1b[38;2;0;255;65m'
const ARGUS_CYAN = '\x1b[38;2;0;240;255m'
const ARGUS_AMBER = '\x1b[38;2;255;176;32m'
const ARGUS_MUTED = '\x1b[38;2;100;116;139m'
const PROMPT = `${ARGUS_GREEN}argus${ARGUS_CYAN}@${ARGUS_GREEN}investigador${ARGUS_MUTED}:${ARGUS_CYAN}~/operações${ARGUS_AMBER} ›${RESET} `

/* ------------------------------------------------------------------ */
/* Injected styles (self-contained; avoids Next.js global-CSS import)  */
/* opencode-inspired: dark canvas, mono, 4px radii, dense, minimal     */
/* ------------------------------------------------------------------ */

const INJECTED_STYLES = `
.ts-terminal {
  display: flex;
  flex-direction: column;
  border-radius: 4px;
  overflow: hidden;
  background: #060b15;
  border: 1px solid rgba(0, 255, 65, 0.18);
  box-shadow: 0 0 0 1px rgba(0, 255, 65, 0.04), 0 14px 42px rgba(0, 0, 0, 0.42), 0 0 32px rgba(0, 255, 65, .05);
  font-family: var(--font-mono, monospace);
}

/* ---- Titlebar (opencode layout: left / center / right) ---- */
.ts-terminal .ts-titlebar {
  display: flex;
  align-items: center;
  gap: 12px;
  height: 38px;
  padding: 0 10px;
  background: var(--surface-2, #111a2e);
  border-bottom: 1px solid var(--border-subtle, rgba(148, 163, 184, 0.08));
  user-select: none;
  flex: none;
  position: relative;
}
.ts-terminal .ts-titlebar::after { content: ''; position: absolute; left: 0; right: 0; bottom: -1px; height: 1px; background: linear-gradient(90deg, transparent, rgba(0,255,65,.5), rgba(0,240,255,.5), transparent); opacity: .55; }
.ts-terminal .ts-titlebar-left {
  display: flex;
  align-items: center;
  gap: 7px;
  flex: none;
  min-width: 0;
}
.ts-terminal .ts-logo {
  width: 20px;
  height: 20px;
  flex: none;
  filter: drop-shadow(0 0 4px rgba(0, 255, 65, 0.4));
}
.ts-terminal .ts-app-name {
  font-family: var(--font-mono, monospace);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.10em;
  color: var(--accent-primary, #00FF41);
  text-shadow: 0 0 10px rgba(0, 255, 65, 0.35);
  flex: none;
  white-space: nowrap;
}
.ts-terminal .ts-signal-label { color: var(--accent-secondary, #00F0FF); font-size: 9px; letter-spacing: .12em; white-space: nowrap; }
.ts-terminal .ts-titlebar-center {
  flex: 1;
  min-width: 0;
  text-align: center;
  font-family: var(--font-mono, monospace);
  font-size: 11px;
  color: var(--text-muted, #64748b);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  letter-spacing: 0.02em;
}
.ts-terminal .ts-titlebar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: none;
}
.ts-terminal .ts-status {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex: none;
  background: var(--status-warning, #FFB020);
}
.ts-terminal .ts-status-connected {
  background: var(--status-success, #00FF41);
  box-shadow: 0 0 6px rgba(0, 255, 65, 0.6);
}
.ts-terminal .ts-status-connecting {
  background: var(--status-warning, #FFB020);
  animation: ts-pulse 1.2s ease-in-out infinite;
}
.ts-terminal .ts-status-disconnected,
.ts-terminal .ts-status-closed {
  background: var(--status-danger, #FF3B30);
}
@keyframes ts-pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}
@keyframes ts-radar { to { transform: rotate(360deg); } }
.ts-terminal .ts-tools {
  display: flex;
  gap: 2px;
  flex: none;
}
.ts-terminal .ts-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-secondary, #94a3b8);
  font-family: var(--font-mono, monospace);
  font-size: 11px;
  line-height: 1;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  letter-spacing: 0.02em;
  transition: background 0.12s, color 0.12s, border-color 0.12s;
}
.ts-terminal .ts-btn:hover {
  background: var(--surface-3, #1a2438);
  color: var(--text-primary, #f8fafc);
  border-color: var(--border-subtle, rgba(148, 163, 184, 0.16));
}
.ts-terminal .ts-btn:active {
  background: rgba(0, 255, 65, 0.08);
}

/* ---- Body ---- */
.ts-terminal .ts-body { position: relative; flex: 1; min-height: 0; display: flex; overflow: hidden; background: radial-gradient(circle at 75% 10%, rgba(0,240,255,.05), transparent 28%), #060b15; }
.ts-terminal .ts-body::before { content: ''; position: absolute; inset: 0; pointer-events: none; opacity: .28; background-image: linear-gradient(rgba(0,255,65,.035) 1px, transparent 1px), linear-gradient(90deg, rgba(0,255,65,.035) 1px, transparent 1px); background-size: 32px 32px; mask-image: linear-gradient(120deg, #000, transparent 65%); }
.ts-terminal .ts-body::after { content: ''; position: absolute; width: 380px; aspect-ratio: 1; right: -170px; bottom: -250px; border: 1px solid rgba(0,240,255,.10); border-radius: 50%; box-shadow: 0 0 0 18px rgba(0,240,255,.018), 0 0 0 52px rgba(0,240,255,.012); animation: ts-radar 18s linear infinite; pointer-events: none; }
.ts-terminal .ts-term-host { flex: 1; min-width: 0; padding: 6px 8px 8px; }

/* ---- Search overlay ---- */
.ts-terminal .ts-search {
  position: absolute;
  top: 6px;
  right: 8px;
  z-index: 20;
  display: flex;
  align-items: center;
  gap: 6px;
  background: var(--surface-2, #111a2e);
  border: 1px solid var(--border-strong, rgba(148, 163, 184, 0.24));
  border-radius: 4px;
  padding: 4px 6px;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);
  font-family: var(--font-mono, monospace);
}
.ts-terminal .ts-search input {
  background: var(--surface-1, #0b1120);
  border: 1px solid var(--border-subtle, rgba(148, 163, 184, 0.12));
  color: var(--text-primary, #f8fafc);
  font-family: var(--font-mono, monospace);
  font-size: 12px;
  padding: 3px 6px;
  border-radius: 4px;
  width: 160px;
  outline: none;
}
.ts-terminal .ts-search input:focus {
  border-color: var(--border-accent, rgba(0, 255, 65, 0.5));
  box-shadow: 0 0 0 1px rgba(0, 255, 65, 0.15);
}
.ts-terminal .ts-search .ts-count {
  font-size: 11px;
  color: var(--text-muted, #64748b);
  min-width: 48px;
  text-align: center;
  white-space: nowrap;
}
.ts-terminal .ts-search .ts-nav { display: flex; gap: 2px; }
.ts-terminal .ts-search .ts-navbtn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-secondary, #94a3b8);
  width: 22px;
  height: 22px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 11px;
  line-height: 1;
  display: flex;
  align-items: center;
  justify-content: center;
}
.ts-terminal .ts-search .ts-navbtn:hover:not(:disabled) {
  color: var(--text-primary, #f8fafc);
  background: var(--surface-3, #1a2438);
}
.ts-terminal .ts-search .ts-navbtn:disabled { opacity: 0.3; cursor: default; }

/* ---- xterm (scoped) ---- */
.ts-terminal .xterm { font-family: var(--font-mono, monospace); position: relative; user-select: none; -ms-user-select: none; -webkit-user-select: none; }
.ts-terminal .xterm.focus, .ts-terminal .xterm:focus { outline: none; }
.ts-terminal .xterm .xterm-viewport {
  background-color: transparent;
  overflow-y: scroll;
  cursor: default;
  position: absolute;
  right: 0; left: 0; top: 0; bottom: 0;
}
.ts-terminal .xterm .xterm-screen { position: relative; }
.ts-terminal .xterm .xterm-screen canvas { display: block; }
.ts-terminal .xterm .xterm-rows { position: absolute; left: 0; top: 0; }
.ts-terminal .xterm .xterm-helper-textarea {
  position: absolute;
  opacity: 0;
  left: -9999em;
  top: 0;
  width: 0;
  height: 0;
  z-index: -10;
  white-space: nowrap;
  overflow: hidden;
  resize: none;
}
.ts-terminal .xterm .xterm-decoration-container { position: absolute; top: 0; left: 0; right: 0; z-index: 5; }
.ts-terminal .xterm .xterm-decoration { pointer-events: none; }
.ts-terminal .xterm .xterm-decoration.bottom { background: rgba(255, 176, 32, 0.12); }
.ts-terminal .xterm .xterm-decoration.top { background: rgba(255, 176, 32, 0.35); }
.ts-terminal .xterm .xterm-viewport::-webkit-scrollbar { width: 6px; }
.ts-terminal .xterm .xterm-viewport::-webkit-scrollbar-thumb {
  background: var(--border-strong, rgba(148, 163, 184, 0.24));
  border-radius: 3px;
}
.ts-terminal .xterm .xterm-viewport::-webkit-scrollbar-thumb:hover {
  background: var(--text-muted, #64748b);
}
.ts-terminal .xterm .xterm-viewport::-webkit-scrollbar-track { background: transparent; }

@media (prefers-reduced-motion: reduce) {
  .ts-terminal .ts-status-connecting, .ts-terminal .ts-body::after { animation: none !important; }
}
`

function defaultWsUrl(): string {
  if (typeof window === 'undefined') return ''
  const proto = window.location.protocol === 'https:' ? 'wss://' : 'ws://'
  return `${proto}${window.location.host}${DEFAULT_WS_PATH}`
}

const ArgusMark = () => (
  <svg
    className="ts-logo"
    width="20"
    height="20"
    viewBox="0 0 32 32"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path
      d="M16 2L28 8.5v15L16 30 4 23.5v-15L16 2z"
      stroke="#00FF41"
      strokeWidth="1.5"
      fill="rgba(0,255,65,0.06)"
    />
    <circle cx="16" cy="16" r="4" stroke="#00FF41" strokeWidth="1.2" />
    <circle cx="16" cy="16" r="8" stroke="#00FF41" strokeWidth="0.8" opacity="0.5" />
    <path
      d="M16 4v4M16 24v4M4 16h4M24 16h4"
      stroke="#00FF41"
      strokeWidth="0.8"
      strokeLinecap="round"
    />
  </svg>
)

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export default function TerminalPane({
  wsUrl,
  breadcrumb,
  title = 'argus-terminal',
  scrollback = 5000,
  autoConnect = true,
  height,
  className,
  style,
  model = 'auto',
  investigationId,
}: TerminalPaneProps) {
  const frameRef = useRef<HTMLDivElement>(null)
  const hostRef = useRef<HTMLDivElement>(null)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const styleTagRef = useRef<HTMLStyleElement | null>(null)

  const termRef = useRef<Terminal | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectDelayRef = useRef(1000)
  const investigationIdRef = useRef(investigationId)
  const intentionalCloseRef = useRef(false)

  const linesRef = useRef<BufferLine[]>([])
  const matchesRef = useRef<Match[]>([])
  const decorationsRef = useRef<{ dec: IDecoration; marker: IMarker }[]>([])

  const searchOpenRef = useRef(false)
  const searchQueryRef = useRef('')
  const currentMatchRef = useRef(0)
  const urlRef = useRef(wsUrl ?? defaultWsUrl())
  const scrollbackRef = useRef(scrollback)

  const [status, setStatus] = useState<ConnStatus>(
    autoConnect ? 'connecting' : 'closed',
  )
  const [searchOpen, setSearchOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [matchCount, setMatchCount] = useState(0)
  const [currentMatch, setCurrentMatch] = useState(0)

  const historyKey = `argus:terminal-history:${investigationId || 'session'}`

  const persistHistory = useCallback(() => {
    if (typeof window === 'undefined') return
    try {
      const history = linesRef.current.slice(-scrollbackRef.current)
      window.localStorage.setItem(historyKey, JSON.stringify(history))
    } catch {
      // Storage can be unavailable in private mode or when quota is full.
    }
  }, [historyKey])

  /* ------------------------------ helpers ------------------------- */

  const disposeDecorations = useCallback(() => {
    for (const { dec, marker } of decorationsRef.current) {
      try {
        dec.dispose()
      } catch {
        /* already disposed */
      }
      try {
        marker.dispose()
      } catch {
        /* already disposed */
      }
    }
    decorationsRef.current = []
  }, [])

  const appendLines = useCallback(
    (text: string, kind: LineKind) => {
      const lines = linesRef.current
      const parts = text.split('\n')
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i]
        if (i === 0) {
          const last = lines[lines.length - 1]
          if (last) {
            last.text += part
          } else if (part !== '') {
            lines.push({ text: part, kind })
          }
        } else {
          lines.push({ text: part, kind })
        }
      }
      const cap = scrollbackRef.current
      if (lines.length > cap) lines.splice(0, lines.length - cap)
    },
    [],
  )

  const write = useCallback(
    (kind: LineKind, data: string) => {
      const term = termRef.current
      if (!term) return
      term.write(`${ANSI[kind]}${data}${RESET}`)
      appendLines(data, kind)
      persistHistory()
      // Keep search results fresh while the search bar is active.
      if (searchOpenRef.current && searchQueryRef.current) {
        runSearch(searchQueryRef.current)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [appendLines, persistHistory],
  )

  const clearTerminal = useCallback(() => {
    termRef.current?.clear()
    linesRef.current = []
    if (typeof window !== 'undefined') window.localStorage.removeItem(historyKey)
    disposeDecorations()
    matchesRef.current = []
    setMatchCount(0)
    setCurrentMatch(0)
  }, [disposeDecorations, historyKey])

  const exportOutput = useCallback(() => {
    const text = linesRef.current.map((l) => l.text).join('\n') + '\n'
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${title.replace(/[^a-z0-9-_]/gi, '-')}-${new Date()
      .toISOString()
      .replace(/[:.]/g, '-')}.log`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }, [title])

  const fit = useCallback(() => {
    const term = termRef.current
    const host = hostRef.current
    if (!term || !host) return
    const rect = host.getBoundingClientRect()
    if (rect.width < 10 || rect.height < 10) return
    const fontSize = (term.options.fontSize as number) || 13
    const cellWidth = Math.ceil(fontSize * 0.602)
    const cellHeight = Math.ceil(fontSize * 1.2)
    const cols = Math.max(2, Math.floor(rect.width / cellWidth) - 1)
    const rows = Math.max(2, Math.floor(rect.height / cellHeight) - 1)
    if (cols !== term.cols || rows !== term.rows) term.resize(cols, rows)
  }, [])

  /* ------------------------------ search -------------------------- */

  const runSearch = useCallback(
    (rawQuery: string) => {
      const term = termRef.current
      disposeDecorations()
      const q = rawQuery.toLowerCase()
      if (!q || !term) {
        matchesRef.current = []
        setMatchCount(0)
        setCurrentMatch(0)
        return
      }
      const matches: Match[] = []
      linesRef.current.forEach((line, lineIdx) => {
        const text = line.text.toLowerCase()
        let idx = text.indexOf(q)
        while (idx !== -1) {
          matches.push({ line: lineIdx, start: idx, end: idx + q.length })
          idx = text.indexOf(q, idx + 1)
        }
      })
      matchesRef.current = matches
      setMatchCount(matches.length)
      setCurrentMatch(matches.length ? Math.min(currentMatchRef.current, matches.length - 1) : 0)

      if (!matches.length) return

      const buffer = term.buffer.active
      const cursorLine = buffer.baseY + buffer.cursorY

      const addDecoration = (m: Match, isCurrent: boolean) => {
        const marker = term.registerMarker(m.line - cursorLine)
        if (!marker) return
        const dec = term.registerDecoration({
          marker,
          x: m.start,
          width: m.end - m.start,
          layer: isCurrent ? 'top' : 'bottom',
          backgroundColor: isCurrent ? '#FFB020' : '#5A4300',
          overviewRulerOptions: {
            color: isCurrent ? '#FFD76A' : '#FFB020',
            position: 'left',
          },
        })
        if (dec) decorationsRef.current.push({ dec, marker })
      }

      matches.forEach((m, i) => addDecoration(m, i === currentMatchRef.current))
      term.scrollToLine(Math.max(0, matches[currentMatchRef.current].line))
    },
    [disposeDecorations],
  )

  const goToMatch = useCallback(
    (index: number) => {
      const matches = matchesRef.current
      if (!matches.length) return
      const clamped = Math.max(0, Math.min(index, matches.length - 1))
      currentMatchRef.current = clamped
      setCurrentMatch(clamped)
      runSearch(searchQueryRef.current)
      termRef.current?.scrollToLine(Math.max(0, matches[clamped].line))
    },
    [runSearch],
  )

  const toggleSearch = useCallback(
    (open: boolean) => {
      searchOpenRef.current = open
      setSearchOpen(open)
      if (open) {
        setTimeout(() => searchInputRef.current?.focus(), 0)
      } else {
        disposeDecorations()
        matchesRef.current = []
        setMatchCount(0)
        setCurrentMatch(0)
        termRef.current?.focus()
      }
    },
    [disposeDecorations],
  )

  /* ------------------------------ websocket ----------------------- */

  const connect = useCallback(() => {
    if (!autoConnect || intentionalCloseRef.current) return
    const url = urlRef.current
    if (!url) return
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return
    }
    setStatus('connecting')
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      reconnectDelayRef.current = 1000
      setStatus('connected')
    }

    ws.onmessage = (ev: MessageEvent) => {
      const handle = async (raw: unknown) => {
        let text: string
        if (typeof raw === 'string') text = raw
        else if (raw instanceof Blob) text = await raw.text()
        else if (raw instanceof ArrayBuffer) text = new TextDecoder().decode(raw)
        else text = String(raw)
        handleMessage(text)
      }
      void handle(ev.data)
    }

    ws.onclose = () => {
      wsRef.current = null
      if (intentionalCloseRef.current) {
        setStatus('closed')
        return
      }
      setStatus('disconnected')
      const delay = reconnectDelayRef.current
      reconnectDelayRef.current = Math.min(delay * 2, 10000)
      reconnectTimerRef.current = setTimeout(connect, delay)
    }

    ws.onerror = () => {
      setStatus('disconnected')
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoConnect])

  const handleMessage = useCallback(
    (raw: string) => {
      let text = raw
      if (text.startsWith('data: ')) text = text.slice(6)
      text = text.replace(/\n\n$/, '')

      let type = 'stdout'
      let data = text
      type ParsedMessage = { type?: unknown; content?: unknown; data?: unknown; message?: unknown; status?: unknown; results?: unknown; query?: unknown; sources?: unknown }
      let obj: ParsedMessage = {}
      try {
        const parsed: unknown = JSON.parse(text)
        if (parsed && typeof parsed === 'object') {
          obj = parsed as ParsedMessage
          if (typeof obj.type === 'string') type = obj.type
          const content = obj.content ?? obj.data ?? obj.message
          if (content !== undefined && content !== null) data = String(content)
        }
      } catch {
        /* plain text -> stdout */
      }
      window.dispatchEvent(new CustomEvent('argus:terminal-event', {
        detail: { type, content: data, ts: Date.now() },
      }))
      if (type === 'clear') {
        clearTerminal()
        return
      }
      if (type === 'research') {
        const status = typeof obj.status === 'string' ? obj.status : undefined
        const results = typeof obj.results === 'number' ? obj.results : undefined
        const q = typeof obj.query === 'string' ? obj.query : undefined
        window.dispatchEvent(new CustomEvent('argus:research', {
          detail: { query: q ?? '', results: results ?? 0, status: status ?? 'unknown', ts: Date.now() },
        }))
        if (status === 'searching') {
          write('info', `\r\n🔍 Pesquisando em múltiplas fontes Tor: ${q ?? ''}\r\n`)
        } else if (status === 'done') {
          write('info', `\r\n✓ Pesquisa concluída: ${results ?? 0} resultados\r\n`)
          if (Array.isArray(obj.sources)) {
            for (const source of obj.sources) {
              if (source && typeof source === 'object' && 'link' in source) {
                const item = source as { link?: unknown; title?: unknown; source_engine?: unknown }
                const title = typeof item.title === 'string' ? item.title : 'Fonte sem título'
                const engine = typeof item.source_engine === 'string' ? item.source_engine : 'engine desconhecida'
                write('info', `  ↳ [${engine}] ${title}\r\n    ${String(item.link)}\r\n`)
              }
            }
          }
        }
        return
      }
      const kind: LineKind = type === 'stderr' ? 'stderr' : type === 'info' ? 'info' : 'stdout'
      write(kind, data)
    },
    [clearTerminal, write],
  )

  /* ------------------------------ lifecycle ----------------------- */

  useEffect(() => {
    urlRef.current = wsUrl ?? defaultWsUrl()
  }, [wsUrl])

  useEffect(() => {
    scrollbackRef.current = scrollback
  }, [scrollback])

  useEffect(() => {
    investigationIdRef.current = investigationId
  }, [investigationId])

  useEffect(() => {
    // Fresh mount (incl. StrictMode dev double-mount) must be able to
    // connect again — the previous cleanup set intentionalCloseRef=true.
    intentionalCloseRef.current = false
    const frame = frameRef.current
    const host = hostRef.current
    if (!frame || !host) return

    // Inject scoped styles once per mount.
    const styleTag = document.createElement('style')
    styleTag.textContent = INJECTED_STYLES
    document.head.appendChild(styleTag)
    styleTagRef.current = styleTag

    let term: Terminal | null = null
    let ro: ResizeObserver | null = null
    let rafId: number | null = null
    let keyHandler: ((e: KeyboardEvent) => void) | null = null

    // Defer terminal.open() to next frame so the container has valid
    // dimensions before xterm's Viewport tries to read them.
    rafId = requestAnimationFrame(() => {
      const rect = host.getBoundingClientRect()
      if (rect.width < 10 || rect.height < 10) return

      const terminal = new Terminal({
        scrollback: scrollbackRef.current,
        convertEol: true,
        cursorBlink: true,
        allowProposedApi: true,
        overviewRulerWidth: 6,
        fontSize: 13,
        fontFamily:
          "'JetBrains Mono','Fira Code',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace",
        theme: { background: 'transparent', foreground: '#f8fafc' },
      })
      term = terminal
      terminal.open(host)
      termRef.current = terminal

      // Restore the searchable transcript for the selected investigation.
      // This keeps a page refresh from erasing the operator's local console context.
      try {
        const stored = window.localStorage.getItem(historyKey)
        if (stored) {
          const history = JSON.parse(stored) as unknown
          if (Array.isArray(history)) {
            const valid = history.filter((line): line is BufferLine => (
              !!line && typeof line === 'object' &&
              typeof (line as BufferLine).text === 'string' &&
              ((line as BufferLine).kind === 'stdout' || (line as BufferLine).kind === 'stderr' || (line as BufferLine).kind === 'info')
            )).slice(-scrollbackRef.current)
            linesRef.current = valid
            for (const line of valid) {
              terminal.write(`${ANSI[line.kind]}${line.text}${RESET}\r\n`)
            }
          }
        }
      } catch {
        linesRef.current = []
      }

      terminal.registerLinkProvider({
        provideLinks(lineNumber, callback) {
          const value = terminal.buffer.active.getLine(lineNumber - 1)?.translateToString(true) ?? ''
          const matches = Array.from(value.matchAll(/https?:\/\/[^\s]+\.onion[^\s]*/gi))
          callback(matches.map((match) => ({
            text: match[0],
            range: {
              start: { x: (match.index ?? 0) + 1, y: lineNumber },
              end: { x: (match.index ?? 0) + match[0].length + 1, y: lineNumber },
            },
            activate: (_event, url) => window.dispatchEvent(new CustomEvent('argus:open-safe-browser', { detail: { url } })),
            hover: (_event, url) => { host.title = `Abrir com isolamento: ${url}` },
            leave: () => { host.title = '' },
          })))
        },
      })

      let inputBuffer = ''

      const showPrompt = () => {
        terminal.write(`\r\n${PROMPT}`)
        inputBuffer = ''
      }

      showPrompt()

      terminal.onData((data) => {
        if (data === '\r') {
          if (inputBuffer.trim()) {
            appendLines(inputBuffer, 'stdout')
            persistHistory()
            terminal.write('\r\n')
            const ws = wsRef.current
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: "chat", messages: [{ role: "user", content: inputBuffer }], model, investigation_id: investigationIdRef.current }))
            }
          } else {
            showPrompt()
          }
        } else if (data === '\x7f') {
          if (inputBuffer.length > 0) {
            inputBuffer = inputBuffer.slice(0, -1)
            terminal.write('\b \b')
          }
        } else if (data >= ' ') {
          inputBuffer += data
          terminal.write(data)
        }
      })

      // Fit after open and on subsequent resizes.
      fit()
      terminal.focus()
      ro = new ResizeObserver(() => fit())
      ro.observe(host)

      if (typeof document !== 'undefined' && 'fonts' in document) {
        void document.fonts.ready.then(() => fit())
      }

      if (autoConnect) connect()
    })

    // Global key handling: Ctrl/Cmd+F toggles search, Esc closes.
    keyHandler = (e: KeyboardEvent) => {
      const within = frame.contains(e.target as Node)
      if (!within) return
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'f') {
        e.preventDefault()
        if (e.target === searchInputRef.current) return
        toggleSearch(!searchOpenRef.current)
      } else if (e.key === 'Escape' && searchOpenRef.current) {
        e.preventDefault()
        toggleSearch(false)
      }
    }
    document.addEventListener('keydown', keyHandler, true)

    const frameStyle = frame.style
    const prevOverflow = frameStyle.overflow

    return () => {
      intentionalCloseRef.current = true
      if (keyHandler) document.removeEventListener('keydown', keyHandler, true)
      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current)
      if (wsRef.current) {
        wsRef.current.onclose = null
        wsRef.current.onmessage = null
        wsRef.current.onerror = null
        wsRef.current.close()
        wsRef.current = null
      }
      disposeDecorations()
      ro?.disconnect()
      if (rafId !== null) cancelAnimationFrame(rafId)
      term?.dispose()
      termRef.current = null
      styleTagRef.current?.remove()
      styleTagRef.current = null
      void prevOverflow
      void frameStyle
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoConnect, connect, disposeDecorations, fit, historyKey, persistHistory, toggleSearch, appendLines])

  /* ------------------------------ render -------------------------- */

  const statusLabel: Record<ConnStatus, string> = {
    connecting: 'connecting',
    connected: 'connected',
    disconnected: 'reconnecting',
    closed: 'offline',
  }

  const breadcrumbText = breadcrumb ?? title

  return (
    <div
      ref={frameRef}
      className={`ts-terminal ${className ?? ''}`}
      style={{ height: height ?? '100%', ...style }}
    >
      <div className="ts-titlebar">
        <div className="ts-titlebar-left">
          <ArgusMark />
          <span className="ts-app-name">ARGUS</span>
          <span className="ts-signal-label">/ LIVE FEED</span>
        </div>
        <span className="ts-titlebar-center">{breadcrumbText}</span>
        <div className="ts-titlebar-right">
          <span
            className={`ts-status ts-status-${status}`}
            title={`connection: ${statusLabel[status]}`}
          />
          <div className="ts-tools">
            <button
              type="button"
              className="ts-btn"
              title="Search buffer (Ctrl+F)"
              onClick={() => toggleSearch(!searchOpenRef.current)}
            >
              Search
            </button>
            <button
              type="button"
              className="ts-btn"
              title="Export output to .log file"
              onClick={exportOutput}
            >
              Export
            </button>
            <button
              type="button"
              className="ts-btn"
              title="Clear terminal"
              onClick={clearTerminal}
            >
              Clear
            </button>
            {status === 'disconnected' && (
              <button
                type="button"
                className="ts-btn"
                title="Reconnect"
                onClick={() => {
                  intentionalCloseRef.current = false
                  reconnectDelayRef.current = 1000
                  connect()
                }}
              >
                Reconnect
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="ts-body">
        <div ref={hostRef} className="ts-term-host" />
        {searchOpen && (
          <div className="ts-search">
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Find…"
              value={query}
              spellCheck={false}
              onChange={(e) => {
                const value = e.target.value
                searchQueryRef.current = value
                setQuery(value)
                currentMatchRef.current = 0
                runSearch(value)
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault()
                  if (e.shiftKey) goToMatch(currentMatchRef.current - 1)
                  else goToMatch(currentMatchRef.current + 1)
                }
              }}
            />
            <span className="ts-count">
              {matchCount ? `${currentMatch + 1}/${matchCount}` : '0 matches'}
            </span>
            <div className="ts-nav">
              <button
                type="button"
                className="ts-navbtn"
                title="Previous (Shift+Enter)"
                disabled={matchCount === 0}
                onClick={() => goToMatch(currentMatchRef.current - 1)}
              >
                ↑
              </button>
              <button
                type="button"
                className="ts-navbtn"
                title="Next (Enter)"
                disabled={matchCount === 0}
                onClick={() => goToMatch(currentMatchRef.current + 1)}
              >
                ↓
              </button>
              <button
                type="button"
                className="ts-navbtn"
                title="Close (Esc)"
                onClick={() => toggleSearch(false)}
              >
                ✕
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

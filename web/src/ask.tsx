import { useEffect, useLayoutEffect, useRef } from "react"
import { ArrowUp, ArrowUpRight, Check, GripHorizontal, History, MessageCircle, MessageSquarePlus, RotateCcw, X } from "lucide-react"
import { Link } from "react-router"
import { api } from "@/api"
import { getConversation, newConversation, selectConversation, updateConversation, useChatHistory, useConversation, type Turn } from "@/lib/ask-conversation"

import { clampChat, type ChatPosition } from "@/lib/chat-position"

const suggestions = [
  "Are we affected by CVE-2023-4863?",
  "Check CVE-2025-56200 against our packages",
]

export function AskWindow({ workspaceId, onClose, position, onPositionChange, historyOpen, onHistoryChange }: {
  workspaceId: string
  historyOpen: boolean
  onHistoryChange: (open: boolean) => void
  onClose: () => void
  position: ChatPosition | null
  onPositionChange: (position: ChatPosition) => void
}) {
  const { id: chatId, draft: question, turns, saved } = useConversation(workspaceId)
  const history = useChatHistory(workspaceId)
  const busy = turns.some((turn) => turn.status === "checking")
  const panel = useRef<HTMLElement>(null)
  const historyToggle = useRef<HTMLButtonElement>(null)
  const drag = useRef<{ x: number; y: number; left: number; top: number } | null>(null)
  const positionNow = useRef(position)
  useLayoutEffect(() => { positionNow.current = position }, [position])

  function moveTo(next: ChatPosition | null) {
    const rect = panel.current?.getBoundingClientRect()
    if (rect) onPositionChange(clampChat(next, rect.width, rect.height, window.innerWidth, window.innerHeight))
  }

  function toggleHistory(open = !historyOpen) {
    const rect = panel.current?.getBoundingClientRect()
    if (rect) {
      const width = Math.min(open ? 628 : 420, window.innerWidth - 24)
      onPositionChange(clampChat({ x: rect.x - (width - rect.width), y: rect.y }, width, rect.height, window.innerWidth, window.innerHeight))
    }
    onHistoryChange(open)
    if (!open) historyToggle.current?.focus()
  }

  useLayoutEffect(() => {
    const fit = () => {
      const rect = panel.current?.getBoundingClientRect()
      if (!rect) return
      const next = clampChat(positionNow.current, rect.width, rect.height, window.innerWidth, window.innerHeight)
      if (positionNow.current?.x !== next.x || positionNow.current?.y !== next.y) onPositionChange(next)
    }
    fit()
    const observer = new ResizeObserver(fit)
    if (panel.current) observer.observe(panel.current)
    window.addEventListener("resize", fit)
    return () => { observer.disconnect(); window.removeEventListener("resize", fit) }
  }, [onPositionChange])
  const composer = useRef<HTMLTextAreaElement>(null)
  const messages = useRef<HTMLDivElement>(null)

  function setQuestion(draft: string) {
    updateConversation(workspaceId, (current) => ({ ...current, draft }), chatId)
  }

  function setTurns(update: (turns: Turn[]) => Turn[]) {
    updateConversation(workspaceId, (current) => ({ ...current, turns: update(current.turns) }), chatId)
  }

  useEffect(() => {
    const previousFocus = document.activeElement
    const element = panel.current
    composer.current?.focus()
    return () => {
      if (element?.contains(document.activeElement) && previousFocus instanceof HTMLElement) previousFocus.focus()
    }
  }, [])

  useEffect(() => {
    const area = composer.current
    if (!area) return
    area.style.height = "auto"
    area.style.height = `${Math.min(area.scrollHeight, 144)}px`
  }, [question])

  useEffect(() => {
    const area = messages.current
    if (area) area.scrollTop = turns.length ? area.scrollHeight : 0
  }, [turns])

  async function send(retry?: Turn) {
    const text = (retry?.question ?? question).trim()
    if (!text || getConversation(workspaceId).turns.some((turn) => turn.status === "checking")) return
    const id = retry?.id ?? crypto.randomUUID()
    const turn: Turn = { id, question: text, status: "checking" }
    setTurns((current) => retry ? current.map((item) => item.id === id ? turn : item) : [...current, turn])
    if (!retry) setQuestion("")
    composer.current?.focus()
    try {
      const result = await api.ask(text)
      setTurns((current) => current.map((item) => item.id === id ? { ...item, status: "answered", answer: result.case } : item))
    } catch (exc) {
      setTurns((current) => current.map((item) => item.id === id ? {
        ...item, status: "error", error: exc instanceof Error ? exc.message : "The request could not be completed.",
      } : item))
    }
  }

  return (
    <section
      ref={panel}
      id="sibyl-chat"
      role="dialog"
      aria-modal="false"
      aria-labelledby="ask-title"
      style={position ? { left: position.x, top: position.y } : { right: 24, bottom: 92 }}
      onKeyDown={(event) => { if (event.key === "Escape" && !event.defaultPrevented) { event.stopPropagation(); if (historyOpen) toggleHistory(false); else onClose() } }}
      className={`fixed z-40 flex h-[min(620px,calc(100dvh-112px))] ${historyOpen ? "w-[min(628px,calc(100vw-24px))]" : "w-[min(420px,calc(100vw-24px))]"} min-h-0 overflow-hidden rounded-2xl bg-panel text-foreground shadow-[0_16px_56px_-12px_rgba(0,0,0,0.55)] ring-1 ring-border selection:bg-primary/25`}
    >
      {historyOpen ? (
        <aside id="sibyl-chat-history" aria-label="Chat history" className="flex min-h-0 w-[min(208px,34vw)] shrink-0 flex-col border-r border-border bg-surface">
          <header className="flex min-h-[61px] shrink-0 items-center justify-between gap-1 border-b border-border px-3">
            <h3 className="text-xs font-medium text-muted-foreground">History</h3>
            <button type="button" aria-label="Close chat history" onClick={() => toggleHistory(false)} className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-raised hover:text-foreground">
              <X className="size-3.5" aria-hidden="true" />
            </button>
          </header>
          <div className="shrink-0 border-b border-border p-2">
            <button type="button" onClick={() => { newConversation(workspaceId); composer.current?.focus() }} className="flex min-h-10 w-full items-center gap-2 rounded-lg px-2 text-left text-xs font-medium text-primary hover:bg-primary/10">
              <MessageSquarePlus className="size-4 shrink-0" aria-hidden="true" />New chat
            </button>
          </div>
          <nav aria-label="Saved chats" className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-2 [scrollbar-color:var(--input)_transparent] [scrollbar-width:thin]">
            {[...history.chats].sort((a, b) => b.updatedAt - a.updatedAt).map((chat) => (
              <button type="button" key={chat.id} onClick={() => selectConversation(workspaceId, chat.id)} aria-current={chat.id === chatId ? "true" : undefined} title={chat.turns[0]?.question || chat.draft.trim() || "New chat"} className="mb-1 flex min-h-16 w-full items-start gap-2 rounded-lg px-2 py-3 text-left hover:bg-raised aria-current:bg-primary/10">
                <span className="min-w-0 flex-1">
                  <span className="line-clamp-2 text-xs font-medium leading-5 [overflow-wrap:anywhere]">{chat.turns[0]?.question || chat.draft.trim() || "New chat"}</span>
                  <span className="mt-1 block text-[11px] leading-4 text-muted-foreground"><time dateTime={new Date(chat.updatedAt).toISOString()}>{new Date(chat.updatedAt).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}</time>{!chat.turns.length && chat.draft.trim() ? " · Draft" : ""}</span>
                </span>
                {chat.id === chatId ? <Check className="mt-0.5 size-3.5 shrink-0 text-primary" aria-hidden="true" /> : null}
              </button>
            ))}
          </nav>
        </aside>
      ) : null}
      <div className="flex min-h-0 min-w-0 flex-1 flex-col">
        <header className="flex shrink-0 items-center justify-between gap-1 border-b border-border px-3 py-2">
          <button
            type="button"
            aria-label="Move chat window"
            aria-describedby="chat-move-hint"
            className="flex min-h-11 min-w-0 flex-1 touch-none select-none items-center gap-2 rounded-lg px-2 text-left cursor-grab active:cursor-grabbing"
            onPointerDown={(event) => {
              if (event.button !== 0) return
              const rect = panel.current!.getBoundingClientRect()
              drag.current = { x: event.clientX, y: event.clientY, left: rect.left, top: rect.top }
              event.currentTarget.setPointerCapture(event.pointerId)
            }}
            onPointerMove={(event) => {
              const start = drag.current
              if (start) moveTo({ x: start.left + event.clientX - start.x, y: start.top + event.clientY - start.y })
            }}
            onPointerUp={(event) => {
              drag.current = null
              if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId)
            }}
            onPointerCancel={() => { drag.current = null }}
            onLostPointerCapture={() => { drag.current = null }}
            onKeyDown={(event) => {
              const directions: Record<string, [number, number]> = { ArrowLeft: [-24, 0], ArrowRight: [24, 0], ArrowUp: [0, -24], ArrowDown: [0, 24] }
              const delta = directions[event.key]
              if (delta && position) { event.preventDefault(); moveTo({ x: position.x + delta[0], y: position.y + delta[1] }) }
              if (event.key === "Home") { event.preventDefault(); moveTo(null) }
            }}
          >
            <MessageCircle className="size-4 shrink-0 text-primary" aria-hidden="true" />
            <span id="ask-title" className="truncate text-sm font-medium">Ask Sibyl</span>
            <GripHorizontal className="ml-auto hidden size-4 shrink-0 text-muted-foreground sm:block" aria-hidden="true" />
          </button>
          <span id="chat-move-hint" className="sr-only">Drag to move, or use arrow keys. Home returns to the bottom right.</span>
          <div className="flex items-center gap-1">
            <button ref={historyToggle} type="button" aria-label="Chat history" aria-expanded={historyOpen} aria-controls={historyOpen ? "sibyl-chat-history" : undefined} title="Chat history" onClick={() => toggleHistory()} className="flex size-10 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-raised hover:text-foreground aria-expanded:bg-raised aria-expanded:text-primary">
              <History className="size-4" aria-hidden="true" />
            </button>
          <button type="button" aria-label="Close Ask Sibyl" onClick={onClose} className="flex size-10 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-raised hover:text-foreground">
            <X className="size-5" aria-hidden="true" />
          </button>
          </div>
        </header>

        <div ref={messages} role="log" aria-label="Conversation with Sibyl" aria-live="polite" aria-relevant="additions text" className="flex min-h-0 flex-1 flex-col overflow-y-auto overscroll-contain px-5 [scrollbar-color:var(--input)_transparent] [scrollbar-width:thin] sm:px-6">
          {turns.length === 0 ? (
            <div className="my-auto flex flex-col items-center py-4 text-center">
              <h3 className="display max-w-xs text-[28px] leading-tight">What would you like to check?</h3>
              <p className="mt-3 max-w-72 text-sm leading-6 text-muted-foreground">Ask about a CVE to check whether it affects packages in your workspace.</p>
              <div className="mt-6 flex w-full max-w-sm flex-col gap-2">
                {suggestions.map((text) => (
                  <button key={text} type="button" onClick={() => { setQuestion(text); composer.current?.focus() }} className="flex min-h-11 items-center justify-between gap-3 rounded-xl border border-border px-4 py-3 text-left text-sm text-muted-foreground transition-colors hover:border-input hover:bg-surface hover:text-foreground">
                    <span>{text}</span><ArrowUpRight className="size-4 shrink-0" aria-hidden="true" />
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex flex-col gap-8 py-6">
              {turns.map((turn) => (
                <div key={turn.id} className="flex min-w-0 flex-col gap-6">
                  <div className="ml-auto max-w-[88%] rounded-2xl rounded-br-md bg-raised px-4 py-3">
                    <span className="sr-only">You: </span>
                    <p className="whitespace-pre-wrap text-sm leading-6 [overflow-wrap:anywhere]">{turn.question}</p>
                  </div>
                  <div className="min-w-0">
                    <div className="mb-2 flex items-center gap-2 text-sm font-medium"><MessageCircle className="size-4 text-primary" aria-hidden="true" />Sibyl</div>
                    {turn.status === "checking" ? (
                      <p className="sib-pulse text-sm leading-6 text-muted-foreground">Checking the evidence…</p>
                    ) : turn.status === "error" ? (
                      <div className="text-sm leading-6">
                        <p>I couldn’t complete this check.</p>
                        <p className="mt-1 whitespace-pre-wrap text-muted-foreground [overflow-wrap:anywhere]">{turn.error}</p>
                        <button type="button" disabled={busy} onClick={() => void send(turn)} className="mt-3 inline-flex min-h-10 items-center gap-2 rounded-md px-2 text-primary underline-offset-4 hover:bg-raised hover:underline disabled:opacity-50"><RotateCcw className="size-3.5" aria-hidden="true" />Retry question</button>
                      </div>
                    ) : turn.answer ? (
                      <div className="flex flex-col gap-3 text-sm leading-6 [overflow-wrap:anywhere]">
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                          <span className="mono font-medium">{turn.answer.vuln_id}</span>
                          <span className="rounded-md bg-raised px-2 py-0.5 text-xs capitalize">{turn.answer.verdict.replaceAll("_", " ")}</span>
                        </div>
                        <p className="text-muted-foreground">{turn.answer.package}@{turn.answer.version} · Priority {turn.answer.score}</p>
                        {turn.answer.exploited ? <p className="text-critical">Listed by CISA as exploited in the wild.</p> : null}
                        <p className="whitespace-pre-wrap">{turn.answer.rationale}</p>
                        <Link to={`/cases/${encodeURIComponent(turn.answer.case_id)}`} className="inline-flex min-h-10 items-center gap-1.5 self-start text-primary underline-offset-4 hover:underline">Open case file<ArrowUpRight className="size-4" aria-hidden="true" /></Link>
                      </div>
                    ) : (
                      <p className="text-sm leading-6">I couldn’t find a matching case for this question. That doesn’t confirm your packages are unaffected. Try a specific CVE identifier or review the workspace’s case files.</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <footer className="shrink-0 px-4 pt-3 pb-[max(16px,env(safe-area-inset-bottom))] sm:px-6">
          <form onSubmit={(event) => { event.preventDefault(); void send() }} className="rounded-2xl border border-input bg-surface p-3 focus-within:border-primary">
            <label htmlFor="ask-message" className="sr-only">Message Sibyl</label>
            <textarea
              ref={composer}
              id="ask-message"
              rows={2}
              style={{ outline: "none" }}
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
                  event.preventDefault()
                  void send()
                }
              }}
              placeholder="Ask about a CVE…"
              aria-describedby="ask-hint"
              className="block max-h-36 min-h-14 w-full resize-none bg-transparent px-1 py-1 text-base leading-6 text-foreground caret-primary outline-none placeholder:text-muted-foreground focus-visible:outline-none sm:text-sm"
            />
            <div className="mt-2 flex items-center justify-between gap-3">
              <span className="px-1 text-xs text-muted-foreground">{busy ? "Checking your question" : "Shift + Enter for a new line"}</span>
              <button type="submit" disabled={busy || !question.trim()} aria-label="Send message" className="flex size-10 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground transition-colors enabled:hover:bg-primary-strong disabled:bg-raised disabled:text-muted-foreground">
                <ArrowUp className="size-5" aria-hidden="true" />
              </button>
            </div>
          </form>
          <p id="ask-hint" className="mt-3 text-center text-xs leading-5 text-muted-foreground">{saved ? "Chat saved in this browser." : "Browser storage unavailable. Chat kept until you reload."} Each question is checked independently.</p>
        </footer>
      </div>
    </section>
  )
}

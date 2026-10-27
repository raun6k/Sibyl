import { useCallback, useSyncExternalStore } from "react"
import type { ReportCase } from "@/api"

export type Turn = {
  id: string
  question: string
  status: "checking" | "answered" | "error"
  answer?: ReportCase | null
  error?: string
}

type Chat = { id: string; draft: string; turns: Turn[]; createdAt: number; updatedAt: number }
type History = { activeId: string; chats: Chat[]; saved: boolean }
type Conversation = Chat & { saved: boolean }
const histories = new Map<string, History>()
const listeners = new Set<() => void>()
const key = (workspaceId: string) => `sibyl-chat:v2:${workspaceId}`

function emptyChat(): Chat {
  return { id: crypto.randomUUID(), draft: "", turns: [], createdAt: Date.now(), updatedAt: Date.now() }
}

function validTurn(value: unknown): value is Turn {
  if (!value || typeof value !== "object") return false
  const turn = value as Turn
  if (typeof turn.id !== "string" || typeof turn.question !== "string" || !["checking", "answered", "error"].includes(turn.status)) return false
  if (turn.error != null && typeof turn.error !== "string") return false
  if (turn.answer != null) {
    const answer = turn.answer
    if (![answer.case_id, answer.package, answer.version, answer.vuln_id, answer.verdict, answer.rationale].every((field) => typeof field === "string")) return false
    if (typeof answer.score !== "number") return false
  }
  return true
}

function validChat(value: unknown): value is Chat {
  if (!value || typeof value !== "object") return false
  const chat = value as Chat
  return typeof chat.id === "string" && typeof chat.draft === "string" && Number.isFinite(chat.createdAt) && Number.isFinite(chat.updatedAt) && Array.isArray(chat.turns) && chat.turns.every(validTurn)
}

function restore(chat: Chat): Chat {
  return { ...chat, turns: chat.turns.map((turn) => turn.status === "checking" ? {
    ...turn, status: "error", error: "This check was interrupted when the page reloaded. Retry your question.",
  } : turn) }
}

function persist(workspaceId: string, history: History) {
  try {
    localStorage.setItem(key(workspaceId), JSON.stringify({ version: 2, activeId: history.activeId, chats: history.chats }))
    history.saved = true
  } catch {
    // Keep all chats in memory when browser storage is disabled or full.
    history.saved = false
  }
}

export function getChatHistory(workspaceId: string): History {
  const cached = histories.get(workspaceId)
  if (cached) return cached
  const initial = emptyChat()
  let history: History = { activeId: initial.id, chats: [initial], saved: true }
  try {
    const raw = localStorage.getItem(key(workspaceId))
    if (raw) {
      const stored = JSON.parse(raw)
      if (stored?.version === 2 && Array.isArray(stored.chats) && stored.chats.length && stored.chats.every(validChat) && new Set(stored.chats.map((chat: Chat) => chat.id)).size === stored.chats.length) {
        history = { activeId: stored.chats.some((chat: Chat) => chat.id === stored.activeId) ? stored.activeId : stored.chats[0].id, chats: stored.chats.map(restore), saved: true }
      }
    } else {
      // Bring the previously saved current conversation into history without losing it.
      const legacy = localStorage.getItem(`sibyl-chat:v1:${workspaceId}`)
      if (legacy) {
        const stored = JSON.parse(legacy)
        if (stored?.version === 1 && typeof stored.draft === "string" && Array.isArray(stored.turns) && stored.turns.every(validTurn)) {
          history.chats = [restore({ ...initial, draft: stored.draft, turns: stored.turns })]
          persist(workspaceId, history)
        }
      }
    }
  } catch {
    history.saved = false
  }
  histories.set(workspaceId, history)
  return history
}

export function getConversation(workspaceId: string): Conversation {
  const history = getChatHistory(workspaceId)
  return { ...history.chats.find((chat) => chat.id === history.activeId)!, saved: history.saved }
}

function publish(workspaceId: string, history: History) {
  persist(workspaceId, history)
  histories.set(workspaceId, history)
  listeners.forEach((listener) => listener())
}

export function updateConversation(workspaceId: string, update: (current: Conversation) => Pick<Conversation, "draft" | "turns">, chatId = getChatHistory(workspaceId).activeId) {
  const history = getChatHistory(workspaceId)
  publish(workspaceId, { ...history, chats: history.chats.map((chat) => {
    if (chat.id !== chatId) return chat
    const { draft, turns } = update({ ...chat, saved: history.saved })
    return { ...chat, draft, turns, updatedAt: Date.now() }
  }) })
}

export function newConversation(workspaceId: string) {
  const history = getChatHistory(workspaceId)
  const current = history.chats.find((chat) => chat.id === history.activeId)!
  if (!current.draft.trim() && !current.turns.length) return
  const unused = history.chats.find((chat) => !chat.draft.trim() && !chat.turns.length)
  const chat = unused ?? emptyChat()
  publish(workspaceId, { ...history, activeId: chat.id, chats: unused ? history.chats : [chat, ...history.chats] })
}

export function selectConversation(workspaceId: string, chatId: string) {
  const history = getChatHistory(workspaceId)
  if (history.chats.some((chat) => chat.id === chatId)) publish(workspaceId, { ...history, activeId: chatId })
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function useChatHistory(workspaceId: string) {
  const snapshot = useCallback(() => getChatHistory(workspaceId), [workspaceId])
  return useSyncExternalStore(subscribe, snapshot)
}

export function useConversation(workspaceId: string): Conversation {
  const history = useChatHistory(workspaceId)
  return { ...history.chats.find((chat) => chat.id === history.activeId)!, saved: history.saved }
}

import { useOutletContext } from "react-router"
import type { RunState, WorkspaceInfo } from "@/api"

export type SourceHealth = { source: string; records: number; status: string }

// What the shell shares with every page: the current workspace, its runs, source health and the global actions.
export type Workspace = {
  workspace: WorkspaceInfo
  workspaces: WorkspaceInfo[]
  switchWorkspace: (id: string) => void
  refreshWorkspaces: () => Promise<WorkspaceInfo[]>
  inbox: number
  refreshInbox: () => void
  runs: RunState[] | null
  sources: SourceHealth[] | null
  refreshRuns: () => void
  openRunDialog: () => void
}

export function useWorkspace() {
  return useOutletContext<Workspace>()
}

const KEY = "sibyl-workspace"

export function rememberedWorkspace(): string {
  try {
    return localStorage.getItem(KEY) ?? ""
  } catch {
    return ""
  }
}

export function rememberWorkspace(id: string) {
  try {
    localStorage.setItem(KEY, id)
  } catch {
    // The choice still holds for this visit.
  }
}

// A demo is an explicit choice for this browser session, never a first-visit fallback.
export function demoSession(): boolean {
  try { return sessionStorage.getItem("sibyl-demo") === "active" } catch { return false }
}

export function setDemoSession(active: boolean) {
  try {
    if (active) sessionStorage.setItem("sibyl-demo", "active")
    else sessionStorage.removeItem("sibyl-demo")
  } catch { /* The current visit still works without storage. */ }
}

export function demoTourOpen(): boolean {
  try { return sessionStorage.getItem("sibyl-tour-dismissed") !== "yes" } catch { return true }
}

export function setDemoTourOpen(open: boolean) {
  try {
    if (open) sessionStorage.removeItem("sibyl-tour-dismissed")
    else sessionStorage.setItem("sibyl-tour-dismissed", "yes")
  } catch { /* Keep the current interaction available without storage. */ }
}

export function pickWorkspace(list: WorkspaceInfo[], wanted: string): WorkspaceInfo | null {
  if (demoSession()) return list.find((item) => item.is_demo) ?? null
  return list.find((item) => item.workspace_id === wanted && !item.is_demo) ?? list.find((item) => !item.is_demo) ?? null
}

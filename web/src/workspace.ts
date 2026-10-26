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
  openAsk: () => void
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

// The workspace to open: the remembered one, else the first of your own, else the demo.
export function pickWorkspace(list: WorkspaceInfo[], wanted: string): WorkspaceInfo | null {
  return list.find((item) => item.workspace_id === wanted) ?? list.find((item) => !item.is_demo) ?? list[0] ?? null
}

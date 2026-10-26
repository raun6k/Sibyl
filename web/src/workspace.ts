import { useOutletContext } from "react-router"
import type { RunState } from "@/api"

export type SourceHealth = { source: string; records: number; status: string }

// What the shell shares with every page: runs, source health and the two global actions.
export type Workspace = {
  runs: RunState[] | null
  sources: SourceHealth[] | null
  refreshRuns: () => void
  openRunDialog: () => void
  openAsk: () => void
}

export function useWorkspace() {
  return useOutletContext<Workspace>()
}

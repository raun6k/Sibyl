import { BrowserRouter, Route, Routes } from "react-router"
import { NewWorkspace, Shell } from "@/shell"
import { Overview } from "@/overview"
import { RunsScreen } from "@/runs"
import { RunScreen } from "@/run"
import { PatchList } from "@/patches"
import { CaseScreen } from "@/case"
import { Queue } from "@/queue"
import { MemoryScreen } from "@/memory"
import { Repositories } from "@/repos"
import { Services } from "@/services"
import { InboxScreen } from "@/inbox"
import { ActivityScreen } from "@/activity"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Overview />} />
          <Route path="runs" element={<RunsScreen />} />
          <Route path="runs/:runId" element={<RunScreen />} />
          <Route path="patches" element={<PatchList />} />
          <Route path="cases/*" element={<CaseScreen />} />
          <Route path="queue" element={<Queue />} />
          <Route path="memory" element={<MemoryScreen />} />
          <Route path="repositories" element={<Repositories />} />
          <Route path="services" element={<Services />} />
          <Route path="inbox" element={<InboxScreen />} />
          <Route path="activity" element={<ActivityScreen />} />
          <Route path="start" element={<NewWorkspace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

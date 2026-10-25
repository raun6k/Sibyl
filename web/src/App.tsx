import { BrowserRouter, Route, Routes } from "react-router"
import { Shell } from "@/shell"
import { Inventory } from "@/inventory"
import { RunScreen } from "@/run"
import { PatchList } from "@/patches"
import { CaseScreen } from "@/case"
import { Queue } from "@/queue"
import { MemoryScreen } from "@/memory"

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Shell />}>
          <Route index element={<Inventory />} />
          <Route path="runs/:runId" element={<RunScreen />} />
          <Route path="patches" element={<PatchList />} />
          <Route path="cases/*" element={<CaseScreen />} />
          <Route path="queue" element={<Queue />} />
          <Route path="memory" element={<MemoryScreen />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

import { useCallback, useEffect, useMemo, useState } from "react"
import { Link } from "react-router"
import { ArrowRight, Clock3, Search } from "lucide-react"
import { PageHeader } from "@/components/page-header"
import { Select } from "@/components/ui/select"
import { duration } from "@/lib/format"
import { api, type RunState } from "@/api"
import { Loading, PanelError } from "@/states"
import { useWorkspace } from "@/workspace"

export function RunsScreen() {
  const { workspace, openRunDialog } = useWorkspace()
  const [runs, setRuns] = useState<RunState[] | null>(null)
  const [error, setError] = useState("")
  const load = useCallback(() => {
    api.runs().then((body) => { setRuns(body.runs); setError("") }).catch((exc: Error) => setError(exc.message))
  }, [])
  useEffect(() => { load(); window.addEventListener("sibyl-runs", load); return () => window.removeEventListener("sibyl-runs", load) }, [load, workspace.workspace_id])
  const active = runs?.some((run) => run.status === "RUNNING" || run.status === "QUEUED") ?? false
  useEffect(() => {
    if (!active) return
    const timer = window.setInterval(load, 5000)
    return () => window.clearInterval(timer)
  }, [active, load])
  const [query, setQuery] = useState("")
  const [status, setStatus] = useState("all")
  const sorted = useMemo(() => [...(runs ?? [])].sort((a, b) => (b.started ?? 0) - (a.started ?? 0)), [runs])
  const visible = sorted.filter((run) => (status === "all" || run.status === status) && `${run.run_id} ${run.services?.join(" ") || "Whole workspace"} ${run.trigger}`.toLowerCase().includes(query.toLowerCase()))
  return (
    <div>
      <PageHeader title="All runs" meta={runs ? `${runs.length} saved ${runs.length === 1 ? "run" : "runs"} · newest first` : "Loading run history…"} actions={<button type="button" onClick={openRunDialog} className="btn-gold min-h-9 rounded-full px-5 text-sm font-medium">Run triage</button>} />
      <main className="mx-auto max-w-[1200px] px-6 py-8 pb-24 sm:px-10">
        {error ? <PanelError message={error} onRetry={load} /> : null}
        {runs == null ? !error ? <Loading label="Run history" /> : null : <>
          <div className="mb-5 flex flex-wrap gap-3">
            <label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3"><Search className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" /><span className="sr-only">Search runs</span><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search a service or run ID…" className="min-h-10 min-w-0 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground" /></label>
            <Select aria-label="Run status" value={status} onValueChange={setStatus} className="w-auto min-w-36"><option value="all">All statuses</option><option value="DONE">Completed</option><option value="RUNNING">Running</option><option value="QUEUED">Queued</option><option value="FAILED">Failed</option></Select>
          </div>
          {!visible.length ? <p className="py-8 text-sm text-muted-foreground">{runs.length ? "No runs match these filters." : "No runs yet. Start a triage to create your first run."}</p> : <ol className="divide-y divide-border rounded-2xl border border-border bg-surface">
            {visible.map((run) => <li key={run.run_id}><Link to={`/runs/${run.run_id}`} className="flex min-w-0 items-center gap-4 px-5 py-4 text-foreground no-underline hover:bg-raised/40">
              <Clock3 className="size-4 shrink-0 text-primary" aria-hidden="true" />
              <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-x-3 gap-y-1"><span className="text-sm font-medium">Run #{sorted.length - sorted.indexOf(run)}</span><span className={`text-xs ${run.status === "FAILED" ? "text-critical" : run.status === "DONE" ? "text-success" : "text-primary"}`}>{run.status === "DONE" ? "Completed" : run.status === "RUNNING" ? "Running" : run.status === "QUEUED" ? "Queued" : run.status === "FAILED" ? "Failed" : run.status}</span></div><p className="mt-1 truncate text-xs text-muted-foreground">{run.services?.length ? run.services.join(", ") : "Whole workspace"}</p><p className="mt-1 text-[11px] text-muted-foreground">{run.started ? new Date(run.started * 1000).toLocaleString(undefined, { timeZone: "Asia/Kolkata", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "Start time unavailable"} · {run.trigger?.replaceAll("_", " ") || "manual"}{run.status === "DONE" ? ` · ${run.counts.ranked} affected · ${run.counts.needs_human} need review` : ""}</p></div>
              <span className="num shrink-0 text-xs text-muted-foreground">{run.status === "QUEUED" ? "Waiting" : duration(run.elapsed_seconds)}</span><ArrowRight className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
            </Link></li>)}
          </ol>}
        </>}
      </main>
    </div>
  )
}

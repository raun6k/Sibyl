import { useEffect, useState } from "react"
import { Link, useParams } from "react-router"
import { api, streamRun, type RunState, type TraceEvent } from "@/api"
import { Empty, PanelError } from "@/states"

const STAGES = ["PLANNED", "COLLECTING", "MAPPING", "MATCHING", "CRITIQUE", "PRIORITISING", "REPORTING", "DONE"]

export function RunScreen() {
  const { runId = "" } = useParams()
  const [run, setRun] = useState<RunState | null>(null)
  const [events, setEvents] = useState<TraceEvent[]>([])
  const [error, setError] = useState("")
  const [open, setOpen] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    api.run(runId).then(setRun).catch((exc: Error) => setError(exc.message))
    streamRun(runId, (event) => {
      setEvents((current) => [event, ...current.filter((item) => item.event_id !== event.event_id)])
      if (event.type === "state" && typeof event.payload.to === "string") {
        const next = String(event.payload.to)
        if (next === "DONE") window.dispatchEvent(new Event("sibyl-queue"))
        setRun((current) => current ? { ...current, stage: next, status: next === "DONE" || next === "FAILED" ? next : current.status } : current)
      }
    }, controller.signal).catch((exc: Error) => {
      if (exc.name !== "AbortError") setError(exc.message)
    })
    const timer = window.setInterval(() => {
      api.run(runId).then(setRun).catch(() => undefined)
    }, 2000)
    return () => {
      controller.abort()
      window.clearInterval(timer)
    }
  }, [runId])

  const queries = events.filter((event) => event.type === "tool")
  const llm = events.filter((event) => event.type === "llm_call")
  const sendbacks = events.filter((event) => event.type === "recheck" || event.payload.action === "recheck")
  const stage = run?.stage ?? "PLANNED"

  return (
    <main className="mx-auto grid max-w-[1376px] gap-6 px-4 py-6 lg:grid-cols-[1fr_320px] sm:px-8">
      <section>
        <h1 className="text-2xl font-semibold">Run</h1>
        <p className="mono text-sm text-muted-foreground">{runId}</p>
        <ol className="mt-4 flex flex-wrap gap-2" aria-label="Stages">
          {STAGES.map((name) => (
            <li key={name} className={`rounded-md px-2 py-1 text-xs ${name === stage ? "bg-primary text-primary-foreground" : "bg-raised text-muted-foreground"}`}>{name}</li>
          ))}
        </ol>
        {error ? <PanelError message={error} onRetry={() => window.location.reload()} /> : null}
        {events.length === 0 && !error ? <p className="mt-6 text-muted-foreground">Waiting for the first event…</p> : null}
        <ol className="mt-4 flex flex-col gap-2" aria-label="Agent trace">
          {events.map((event) => (
            <li key={event.event_id} className="rounded-lg border border-border bg-surface p-3">
              <div className="flex flex-wrap items-center gap-2 text-sm">
                <span className="mono text-xs text-muted-foreground">{event.ts?.slice(11, 19)}</span>
                <span className="font-medium">{event.actor}</span>
                <span>{event.type}</span>
                {event.payload.action === "recheck" || event.type === "recheck" ? <span aria-label="send-back">↩</span> : null}
                {event.payload.rerouted ? <span aria-label="fallback">◐</span> : null}
                {event.type === "llm_call" ? <ModelChip payload={event.payload} /> : null}
              </div>
              {event.type === "tool" ? (
                <div className="mt-2">
                  <button type="button" className="text-sm" aria-expanded={open === event.event_id} onClick={() => setOpen(open === event.event_id ? null : event.event_id)}>
                    Zetaris SQL · {String(event.payload.rows)} rows · {String(event.payload.ms)} ms
                  </button>
                  {open === event.event_id ? <pre className="mono mt-2 overflow-x-auto rounded-md bg-raised p-3 text-xs">{String(event.payload.sql)}</pre> : null}
                </div>
              ) : null}
              {event.payload.reason ? <p className="mt-1 text-sm text-muted-foreground">{String(event.payload.reason)}</p> : null}
            </li>
          ))}
        </ol>
      </section>
      <aside className="flex flex-col gap-4">
        <div className="rounded-xl border border-border bg-surface p-4">
          <h2 className="text-sm font-semibold">Budget</h2>
          <Meter label="Time" value={run?.budget.seconds ?? 0} max={run?.budget.max_seconds || 1} unit="s" />
          <Meter label="Tokens" value={run?.budget.tokens ?? 0} max={run?.budget.max_tokens || 1} unit="" />
        </div>
        <div className="rounded-xl border border-border bg-surface p-4">
          <h2 className="text-sm font-semibold">Source health</h2>
          {(run?.degraded_sources.length ?? 0) === 0 ? <p className="text-sm text-muted-foreground">No source marked degraded.</p> : null}
          {run?.degraded_sources.map((source) => <p key={source} className="text-sm">◐ {source}</p>)}
        </div>
        <div className="rounded-xl border border-border bg-surface p-4">
          <h2 className="text-sm font-semibold">Receipt so far</h2>
          <p className="text-sm">{queries.length} Zetaris queries, {queries.reduce((sum, event) => sum + Number(event.payload.ms || 0), 0)} ms</p>
          <p className="text-sm">{llm.length} model calls</p>
          <p className="text-sm">{sendbacks.length} critic send-backs</p>
          {run?.status === "DONE" ? <Link to="/patches">Open the patch list →</Link> : null}
          {events.length === 0 ? <Empty title="No receipt yet" action="Wait for the run" href={`/runs/${runId}`} /> : null}
        </div>
      </aside>
    </main>
  )
}

function ModelChip({ payload }: { payload: Record<string, unknown> }) {
  const routed = String(payload.routed_model || "")
  const requested = String(payload.requested_model || "")
  const error = String(payload.error_code || "")
  const mode = String(payload.mode || "")
  const honoured = payload.mode_honoured
  return (
    <span className="rounded-md bg-raised px-2 py-0.5 text-xs">
      {String(payload.lane || "lane")}
      {requested ? ` · requested ${requested}` : ""}
      {mode ? ` · ran ${mode}${honoured === false ? " (not the requested mode)" : ""}` : ""}
      {routed ? ` · routed ${routed}` : ""}
      {payload.tokens != null ? ` · ${String(payload.tokens)} tok` : ""}
      {payload.latency_ms != null ? ` · ${String(payload.latency_ms)} ms` : ""}
      {error ? ` · error ${error}` : ""}
    </span>
  )
}

function Meter({ label, value, max, unit }: { label: string; value: number; max: number; unit: string }) {
  const ratio = Math.min(1, value / max)
  return (
    <div className="mt-3">
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{label}</span>
        <span className="num">{Math.round(value)}{unit} / {Math.round(max)}{unit}</span>
      </div>
      <div className="mt-1 h-1 rounded-full bg-raised"><div className="h-1 rounded-full bg-primary" style={{ width: `${ratio * 100}%` }} /></div>
    </div>
  )
}

import { useEffect, useMemo, useRef, useState } from "react"
import { Link, useParams } from "react-router"
import { ArrowLeft, ArrowRight, Check, ChevronDown, Download, Search } from "lucide-react"
import { api, streamRun, type RunState, type TraceEvent } from "@/api"
import { PageHeader } from "@/components/page-header"
import { RunProgress } from "@/components/run-progress"
import { Select } from "@/components/ui/select"
import { duration, SOURCE_LABEL, STAGES } from "@/lib/format"
import { filterTrace, traceCategory, tracePage, traceSummary, TRACE_FILTERS, type TraceFilter } from "@/lib/run-trace"
import { Loading, PanelError } from "@/states"
import { useWorkspace } from "@/workspace"

export function RunScreen() {
  const { runId = "" } = useParams()
  return <RunDetails key={runId} runId={runId} />
}

function RunDetails({ runId }: { runId: string }) {
  const { runs } = useWorkspace()
  const [run, setRun] = useState<RunState | null>(null)
  const [events, setEvents] = useState<TraceEvent[]>([])
  const [error, setError] = useState("")
  const [streamError, setStreamError] = useState("")
  const [loaded, setLoaded] = useState(false)
  const [category, setCategory] = useState<TraceFilter>("all")
  const [actor, setActor] = useState("")
  const [query, setQuery] = useState("")
  const [page, setPage] = useState(0)
  const [retry, setRetry] = useState(0)
  const trace = useRef<HTMLElement>(null)
  const scrollingLog = useRef<HTMLOListElement>(null)

  useEffect(() => {
    const controller = new AbortController()
    let active = true
    let frame = 0
    let timer = 0
    const buffer = new Map<string, TraceEvent>()
    const commit = () => { frame = 0; if (active) setEvents([...buffer.values()]) }
    const poll = async () => {
      try {
        const state = await api.run(runId)
        if (!active) return
        setRun(state)
        setError("")
        if (state.status !== "DONE" && state.status !== "FAILED") timer = window.setTimeout(poll, 3000)
      } catch (exc) {
        if (active) setError(exc instanceof Error ? exc.message : "The run could not be loaded.")
      }
    }
    void poll()
    streamRun(runId, (event) => {
      if (!active) return
      buffer.set(event.event_id, event)
      if (!frame) frame = requestAnimationFrame(commit)
      if (event.type === "state" && typeof event.payload.to === "string") {
        const stage = event.payload.to
        setRun((current) => current && current.status !== "DONE" && current.status !== "FAILED" ? { ...current, stage, status: stage === "DONE" || stage === "FAILED" ? stage : current.status } : current)
        if (stage === "DONE" || stage === "FAILED") {
          window.dispatchEvent(new Event("sibyl-runs"))
          if (stage === "DONE") window.dispatchEvent(new Event("sibyl-queue"))
        }
      }
    }, controller.signal).then(() => {
      if (!active) return
      if (frame) cancelAnimationFrame(frame)
      commit()
      setLoaded(true)
      setStreamError("")
      api.run(runId).then((state) => { if (active) setRun(state) }).catch(() => undefined)
    }).catch((exc: Error) => {
      if (active && exc.name !== "AbortError") { commit(); setStreamError("The trace connection was interrupted. Reload it to retrieve the remaining events.") }
    })
    return () => { active = false; controller.abort(); clearTimeout(timer); if (frame) cancelAnimationFrame(frame) }
  }, [runId, retry])

  const stats = useMemo(() => ({
    queries: events.filter((event) => traceCategory(event) === "queries"),
    models: events.filter((event) => traceCategory(event) === "models"),
    rechecks: events.filter((event) => traceCategory(event) === "rechecks"),
    reused: events.filter((event) => event.type === "reuse").length,
  }), [events])
  const actors = useMemo(() => [...new Set(events.map((event) => event.actor))].sort(), [events])
  const ordered = useMemo(() => [...events].reverse(), [events])
  const filtered = useMemo(() => filterTrace(ordered, category, actor, query), [ordered, category, actor, query])
  const slice = tracePage(filtered, page)
  const number = (runs ?? []).findIndex((item) => item.run_id === runId) + 1
  const finished = run?.status === "DONE" || run?.status === "FAILED"
  const stage = STAGES.includes(run?.stage as (typeof STAGES)[number]) ? run!.stage : [...events].reverse().find((event) => event.type === "state" && STAGES.includes(event.payload.to as (typeof STAGES)[number]))?.payload.to as string || "PLANNED"

  function reload() { setLoaded(false); setStreamError(""); setError(""); setRetry((value) => value + 1) }
  function chooseCategory(value: TraceFilter) { setCategory(value); setPage(0); if (scrollingLog.current) scrollingLog.current.scrollTop = 0 }
  function jump(value: TraceFilter) { chooseCategory(value); trace.current?.scrollIntoView({ behavior: "instant", block: "start" }) }
  function turnPage(value: number) { setPage(value); if (scrollingLog.current) scrollingLog.current.scrollTop = 0 }

  return (
    <div>
      <PageHeader title={number ? `Run #${number}` : "Run details"} meta={run ? `${run.status === "DONE" ? "Completed" : run.status === "FAILED" ? "Failed" : run.status === "QUEUED" ? "Queued" : "Running"} · ${duration(run.elapsed_seconds)} · ${run.services?.length ? run.services.join(", ") : "Whole workspace"}` : "Loading run…"} actions={<><Link to="/runs" className="inline-flex min-h-9 items-center gap-2 rounded-lg border border-border px-3 text-xs text-foreground no-underline hover:bg-raised"><ArrowLeft className="size-3.5" aria-hidden="true" />All runs</Link>{run?.status === "DONE" ? <a href={`/api/runs/${encodeURIComponent(runId)}/report.md`} download={`sibyl-run-${runId}.md`} className="inline-flex min-h-9 items-center gap-2 rounded-lg bg-primary/15 px-3 text-xs font-medium text-primary no-underline hover:bg-primary/25"><Download className="size-3.5" aria-hidden="true" />Run report</a> : null}</>} />
      <main className="mx-auto flex max-w-[1200px] flex-col gap-5 px-6 py-6 pb-24 sm:px-10">
        {error ? <PanelError message={error} onRetry={reload} /> : null}
        {!run && !error ? <Loading label="Run details" /> : null}
        {run ? <>
          <section aria-label="Run progress" className="rounded-2xl border border-border bg-surface p-5">
            <RunProgress stage={stage} status={run.status} />
            <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-4 text-xs text-muted-foreground">
              <span><span className="num font-medium text-foreground">{run.counts.ranked}</span> affected</span><span><span className="num font-medium text-foreground">{run.counts.needs_human}</span> need review</span><span><span className="num font-medium text-foreground">{run.counts.closed}</span> closed</span>
              <details className="ml-auto min-w-0"><summary className="cursor-pointer text-[11px]">Run metadata</summary><dl className="mt-3 space-y-2 text-[11px] [overflow-wrap:anywhere]"><div><dt className="text-muted-foreground">Run ID</dt><dd className="mono mt-1">{runId}</dd></div><div><dt>Started</dt><dd>{run.started ? new Date(run.started * 1000).toLocaleString(undefined, { timeZone: "Asia/Kolkata" }) : "Unavailable"}</dd></div><div><dt>Trigger</dt><dd>{run.trigger?.replaceAll("_", " ") || "manual"}</dd></div><div><dt>Mode</dt><dd>{run.incremental ? "Incremental" : "Full scan"}</dd></div></dl></details>
            </div>
            {run.error ? <details className="mt-4 text-xs leading-5"><summary className="cursor-pointer text-critical">Run error details</summary><pre className="mono mt-2 max-h-40 overflow-y-auto whitespace-pre-wrap rounded-lg bg-panel p-3 [overflow-wrap:anywhere]">{run.error}</pre></details> : null}
          </section>
          <div className="@container rounded-2xl border border-border bg-surface">
            <div className="grid @min-[700px]:grid-cols-[1fr_1fr_1.2fr]">
              <section aria-label="Budget" className="min-w-0 p-5"><h2 className="text-xs font-medium">Budget</h2><Meter label="Time" value={run.budget.seconds} max={run.budget.max_seconds} unit="s" /><Meter label="Tokens" value={run.budget.tokens} max={run.budget.max_tokens} unit="" /></section>
              <section aria-label="Source health" className="min-w-0 border-t border-border p-5 @min-[700px]:border-t-0 @min-[700px]:border-l"><h2 className="text-xs font-medium">Source health</h2>{!run.degraded_sources.length ? <p className="mt-3 flex items-start gap-2 text-xs leading-5 text-muted-foreground"><Check className="mt-0.5 size-3.5 shrink-0 text-success" aria-hidden="true" />No source reported as degraded.</p> : <><p className="mt-3 text-xs text-primary">{run.degraded_sources.length} degraded {run.degraded_sources.length === 1 ? "source" : "sources"}</p><ul className="mt-2 flex flex-wrap gap-1.5">{run.degraded_sources.map((source) => <li key={source} className="rounded-md bg-primary/10 px-2 py-1 text-[11px] text-primary">{SOURCE_LABEL[source] || source}</li>)}</ul></>}</section>
              <section aria-label="Run receipts" className="min-w-0 border-t border-border p-5 @min-[700px]:border-t-0 @min-[700px]:border-l"><h2 className="text-xs font-medium">{finished ? "Run receipts" : "Receipts so far"}</h2><div className="mt-3 grid grid-cols-2 gap-2">
                <button type="button" onClick={() => jump("queries")} className="rounded-lg px-2 py-1.5 text-left text-xs hover:bg-raised"><span className="num font-medium text-primary">{stats.queries.length.toLocaleString()}</span><span className="mt-1 block text-[11px] text-muted-foreground">Queries · {Math.round(stats.queries.reduce((sum, event) => sum + Number(event.payload.ms || 0), 0)).toLocaleString()} ms</span></button>
                <button type="button" onClick={() => jump("models")} className="rounded-lg px-2 py-1.5 text-left text-xs hover:bg-raised"><span className="num font-medium text-primary">{stats.models.length.toLocaleString()}</span><span className="mt-1 block text-[11px] text-muted-foreground">Model calls</span></button>
                <button type="button" onClick={() => jump("rechecks")} className="rounded-lg px-2 py-1.5 text-left text-xs hover:bg-raised"><span className="num font-medium text-primary">{stats.rechecks.length.toLocaleString()}</span><span className="mt-1 block text-[11px] text-muted-foreground">Critic rechecks</span></button>
                <button type="button" onClick={() => jump("decisions")} className="rounded-lg px-2 py-1.5 text-left text-xs hover:bg-raised"><span className="num font-medium text-primary">{run.reused ?? stats.reused}</span><span className="mt-1 block text-[11px] text-muted-foreground">Verdicts reused</span></button>
              </div><p className="mt-2 text-[11px] text-muted-foreground">{loaded ? "Full trace loaded" : streamError ? "Partial trace · reload below" : "Receiving events…"}</p></section>
            </div>
          </div>
        </> : null}
        <section ref={trace} data-demo="trace" aria-label="Agent trace" className="scroll-mt-36 min-w-0 rounded-2xl border border-border bg-surface">
          <div className="border-b border-border p-4 sm:p-5">
            <div className="flex flex-wrap items-baseline justify-between gap-2"><h2 className="text-sm font-medium">Agent trace <span className="num ml-2 text-xs font-normal text-muted-foreground">{events.length.toLocaleString()} events{!loaded && !streamError ? " · receiving" : ""}</span></h2><span className="text-[11px] text-muted-foreground">Newest first · expand any row for the full payload</span></div>
            {streamError ? <div role="alert" className="mt-3 text-xs leading-5 text-critical">{streamError}<button type="button" onClick={reload} className="ml-2 min-h-8 rounded-md border border-border px-2 text-foreground hover:bg-raised">Reload trace</button></div> : null}
            <div className="mt-4 flex flex-wrap gap-1.5" aria-label="Trace categories">{TRACE_FILTERS.map((filter) => <button key={filter.id} type="button" aria-pressed={category === filter.id} onClick={() => chooseCategory(filter.id)} className="min-h-8 rounded-lg px-2.5 text-xs text-muted-foreground hover:bg-raised aria-pressed:bg-primary/15 aria-pressed:text-primary">{filter.label}<span className="num ml-1.5 text-[10px]">{filter.id === "all" ? events.length : events.filter((event) => traceCategory(event) === filter.id).length}</span></button>)}</div>
            <div className="mt-3 flex flex-wrap gap-2"><label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-border bg-panel px-3"><Search className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" /><span className="sr-only">Search trace</span><input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0) }} placeholder="Search a case, query, request, or error…" className="min-h-9 w-full min-w-0 bg-transparent text-xs outline-none placeholder:text-muted-foreground" /></label><Select aria-label="Filter by agent" value={actor || "all"} onValueChange={(value) => { setActor(value === "all" ? "" : value); setPage(0) }} className="min-h-9 w-auto text-xs"><option value="all">All agents</option>{actors.map((name) => <option key={name} value={name}>{name}</option>)}</Select></div>
          </div>
          {!filtered.length ? <p className="px-5 py-8 text-xs text-muted-foreground">{loaded ? events.length ? "No events match these filters." : "No trace events were recorded." : run?.status === "QUEUED" ? "Events appear when this run starts." : "Waiting for trace events…"}</p> : <ol ref={scrollingLog} aria-label="Trace events" className="max-h-[480px] min-w-0 divide-y divide-border overflow-y-auto overscroll-contain [scrollbar-color:var(--input)_transparent] [scrollbar-width:thin]">{slice.events.map((event) => <TraceRow key={event.event_id} event={event} />)}</ol>}
          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3 text-xs"><p className="num text-muted-foreground">{filtered.length ? `${slice.current * 20 + 1}–${Math.min((slice.current + 1) * 20, filtered.length)} of ${filtered.length.toLocaleString()}` : "0 events"}</p><div className="flex items-center gap-2"><button type="button" aria-label="Previous trace page" disabled={slice.current === 0} onClick={() => turnPage(slice.current - 1)} className="flex min-h-9 items-center gap-1.5 rounded-lg border border-border px-3 hover:bg-raised disabled:opacity-40"><ArrowLeft className="size-3.5" aria-hidden="true" />Previous</button><Select aria-label="Trace page" value={slice.current + 1} onValueChange={(value) => turnPage(Number(value) - 1)} className="num min-h-9 w-auto px-2 text-xs">{Array.from({ length: slice.pages }, (_, index) => <option key={index} value={index + 1}>{index + 1} / {slice.pages}</option>)}</Select><button type="button" aria-label="Next trace page" disabled={slice.current >= slice.pages - 1} onClick={() => turnPage(slice.current + 1)} className="flex min-h-9 items-center gap-1.5 rounded-lg border border-border px-3 hover:bg-raised disabled:opacity-40">Next<ArrowRight className="size-3.5" aria-hidden="true" /></button></div></div>
        </section>
      </main>
    </div>
  )
}

function TraceRow({ event }: { event: TraceEvent }) {
  const category = traceCategory(event)
  return <li className="min-w-0"><details className="group/event">
    <summary className="flex min-w-0 cursor-pointer list-none items-center gap-3 px-4 py-3 hover:bg-raised/40 sm:px-5 [&::-webkit-details-marker]:hidden">
      <span className="num w-14 shrink-0 text-[10px] text-muted-foreground">{event.ts ? new Date(event.ts).toLocaleTimeString(undefined, { timeZone: "Asia/Kolkata", hour12: false }) : "—"}</span>
      <span className="w-20 shrink-0 truncate text-[11px] font-medium" title={event.actor}>{event.actor}</span>
      <span className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{traceSummary(event)}</span><ChevronDown className="size-3.5 shrink-0 text-muted-foreground transition-transform group-open/event:rotate-180" aria-hidden="true" />
    </summary>
    <div className="min-w-0 border-t border-border bg-panel px-4 py-3 sm:px-5"><p className="text-[11px] text-muted-foreground">{event.type} · {category} · {event.event_id}</p><pre className="mono mt-3 max-h-64 max-w-full overflow-auto whitespace-pre-wrap text-[11px] leading-5 [overflow-wrap:anywhere]">{JSON.stringify(event.payload, null, 2)}</pre></div>
  </details></li>
}

function Meter({ label, value, max, unit }: { label: string; value: number; max: number; unit: string }) {
  const ratio = max > 0 ? Math.max(0, Math.min(1, value / max)) : 0
  const over = max > 0 && value > max
  return <div className="mt-3"><div className="flex flex-wrap justify-between gap-1 text-[11px] text-muted-foreground"><span>{label}</span><span className="num">{Math.round(value).toLocaleString()}{unit} / {max > 0 ? `${Math.round(max).toLocaleString()}${unit}` : "No limit recorded"}</span></div><div role="progressbar" aria-label={`${label} budget used`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(ratio * 100)} className="mt-2 h-1.5 overflow-hidden rounded-full bg-raised"><div className={`h-full rounded-full ${over ? "bg-critical" : "bg-primary"}`} style={{ width: `${ratio * 100}%` }} /></div></div>
}

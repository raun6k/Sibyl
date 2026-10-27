import { useEffect, useMemo, useState } from "react"
import { Link, useSearchParams } from "react-router"
import { createColumnHelper, flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type SortingState } from "@tanstack/react-table"
import { ArrowDown, ArrowUp, Check, Copy, Flame, Minus, Search, X } from "lucide-react"
import { api, type BaselineRow, type Report, type ReportCase } from "@/api"
import { PageHeader } from "@/components/page-header"
import { Select } from "@/components/ui/select"
import { Empty, Loading, PanelError } from "@/states"
import { useWorkspace } from "@/workspace"

type Row = ReportCase & { branch: string }

const helper = createColumnHelper<Row>()
const SOURCES = [
  { id: "osv", label: "OSV", name: "OSV.dev" },
  { id: "ghsa", label: "GHSA", name: "GitHub Advisories" },
  { id: "cna", label: "CNA", name: "CVE.org (CNA)" },
  { id: "cisa", label: "CISA", name: "CISA ADP" },
  { id: "nvd", label: "NVD", name: "NVD" },
  { id: "euvd", label: "EUVD", name: "ENISA EUVD" },
] as const

const VIEWS = [
  { id: "all", label: "All cases", hint: "Every case Sibyl holds" },
  { id: "patch", label: "Patch now", hint: "Affected and ranked" },
  { id: "exploited", label: "Exploited", hint: "In CISA KEV or ENISA EUVD" },
  { id: "needs_human", label: "Needs you", hint: "Waiting on your decision" },
  { id: "closed", label: "Not affected", hint: "Closed with a source" },
] as const

type ViewId = (typeof VIEWS)[number]["id"]

function inView(card: Row, view: string) {
  if (view === "patch") return card.branch === "ranked" && card.verdict === "affected"
  if (view === "exploited") return card.branch === "ranked" && card.exploited
  if (view === "needs_human") return card.branch === "needs_human"
  if (view === "closed") return card.branch === "closed"
  return true
}

function serviceOf(card: ReportCase) {
  return card.case_id.split(":")[1] ?? ""
}

export function PatchList() {
  const { workspace } = useWorkspace()
  const [params] = useSearchParams()
  const [report, setReport] = useState<Report | null>(null)
  const [runs, setRuns] = useState<{ run_id: string; status: string }[]>([])
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState("")
  const [view, setView] = useState<string>(params.get("filter") === "affected" ? "patch" : params.get("filter") || "all")
  const [query, setQuery] = useState(params.get("q") || "")
  const [service, setService] = useState(params.get("service") || "")
  const [compare, setCompare] = useState(false)
  const [baseline, setBaseline] = useState<BaselineRow[]>([])
  const [sorting, setSorting] = useState<SortingState>([{ id: "score", desc: true }])

  useEffect(() => {
    api.runs().then(async (body) => {
      setRuns(body.runs)
      // Every case as the World Model holds it now, across runs and services.
      if (body.runs.some((run) => run.status === "DONE")) setReport(await api.current())
      setLoaded(true)
    }).catch((exc: Error) => setError(exc.message))
  }, [])

  useEffect(() => {
    if (!compare) return
    api.baselines("fixtures").then((body) => setBaseline(body.rows)).catch((exc: Error) => setError(exc.message))
  }, [compare])

  const all = useMemo<Row[]>(() => report ? [
    ...report.ranked.map((card) => ({ ...card, branch: "ranked" })),
    ...report.needs_human.map((card) => ({ ...card, branch: "needs_human" })),
    ...report.closed.map((card) => ({ ...card, branch: "closed" })),
  ] : [], [report])

  const services = useMemo(() => [...new Set(all.map(serviceOf))].filter(Boolean).sort(), [all])
  const counts = useMemo(() => Object.fromEntries(VIEWS.map((item) => [item.id, all.filter((card) => inView(card, item.id)).length])), [all])

  const rows = useMemo(() => all.filter((card) => {
    if (!inView(card, view)) return false
    if (service && serviceOf(card) !== service) return false
    if (query) {
      const blob = `${card.vuln_id} ${card.package} ${card.case_id}`.toLowerCase()
      if (!blob.includes(query.toLowerCase())) return false
    }
    return true
  }), [all, view, query, service])

  const misses = useMemo(() => {
    const predicted = new Set(baseline.filter((row) => row.prediction === "affected").map((row) => `${row.service_id}:${row.package}:${row.version}:${row.vuln_id}`))
    return new Set(rows.filter((card) => card.verdict === "affected" && !predicted.has(keyOf(card))).map((card) => card.case_id))
  }, [baseline, rows])

  const columns = useMemo(() => [
    // Only ranked cases carry a priority; the rest sort below them.
    helper.accessor((row) => row.branch === "ranked" ? Number(row.score) || 0 : -1, { id: "score", header: "Priority", cell: (info) => <Priority card={info.row.original} /> }),
    helper.accessor("vuln_id", {
      header: "Vulnerability",
      cell: (info) => (
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="flex items-center gap-1.5">
            <Link to={`/cases/${encodeURIComponent(info.row.original.case_id)}`} className="mono whitespace-nowrap text-[13px] text-primary hover:underline">{info.getValue()}</Link>
            <CopyButton value={info.getValue()} />
          </span>
          <span className="text-xs text-muted-foreground"><span className="text-foreground">{info.row.original.package}</span>@{info.row.original.version}</span>
        </div>
      ),
    }),
    helper.display({ id: "service", header: "Service", cell: (info) => <span className="whitespace-nowrap rounded-md bg-raised px-2 py-0.5 text-xs">{serviceOf(info.row.original)}</span> }),
    helper.accessor("verdict", { header: "Verdict", cell: (info) => <Verdict card={info.row.original} /> }),
    helper.accessor("confidence", { header: "Confidence", cell: (info) => <Confidence card={info.row.original} /> }),
    helper.display({ id: "signals", header: "Signals", cell: (info) => <Signals card={info.row.original} /> }),
    helper.display({ id: "agreement", header: "Source agreement", cell: (info) => <Agreement card={info.row.original} /> }),
    helper.display({
      id: "miss",
      header: "",
      cell: (info) => compare && misses.has(info.row.original.case_id) ? <span className="whitespace-nowrap rounded-md bg-high/15 px-2 py-0.5 text-xs text-high">NVD-only misses</span> : null,
    }),
  ], [compare, misses])

  // TanStack Table returns fresh functions each render; the React Compiler skips memoizing this component.
  // oxlint-disable-next-line react/incompatible-library
  const table = useReactTable({ data: rows, columns, state: { sorting }, onSortingChange: setSorting, getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel() })
  const filtered = view !== "all" || Boolean(query) || Boolean(service)

  function clear() {
    setView("all")
    setQuery("")
    setService("")
  }

  return (
    <div>
      <PageHeader
        title="Patch list"
        meta={report ? `${all.length} cases across ${services.length} ${services.length === 1 ? "service" : "services"}${runs[0] ? ` · latest run ${runs[0].run_id.slice(0, 8)}` : ""}` : "What to patch first, with a source on every verdict"}
      />
      <main className="mx-auto flex max-w-[1440px] flex-col gap-5 px-6 py-8 pb-24 sm:px-10">
        {error ? <PanelError message={error} onRetry={() => window.location.reload()} /> : null}
        {!loaded && !error ? <Loading label="Patch list" /> : null}
        {loaded && !report ? <Empty title="No triage has finished in this workspace yet." action="Open services" href="/services" /> : null}
        {report ? (
          <>
            <div role="tablist" aria-label="Case views" className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
              {VIEWS.map((item) => <ViewCard key={item.id} id={item.id} label={item.label} hint={item.hint} count={counts[item.id] ?? 0} active={view === item.id} onSelect={() => setView(item.id)} />)}
            </div>

            <div className="flex flex-wrap items-center gap-2 rounded-xl border border-border bg-surface p-2">
              <label className="relative min-w-[220px] flex-1">
                <span className="sr-only">Search cases</span>
                <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-dim" aria-hidden="true" />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search CVE or package" className="input h-10 border-transparent bg-transparent !pl-9 hover:bg-raised/50" />
              </label>
              <div className="h-6 w-px bg-border max-sm:hidden" aria-hidden="true" />
              <div className="w-full sm:w-52">
                <Select value={service || "__all"} onValueChange={(value) => setService(value === "__all" ? "" : value)} aria-label="Service" className="border-transparent bg-transparent">
                  <option value="__all">All services</option>
                  {services.map((name) => <option key={name} value={name}>{name}</option>)}
                </Select>
              </div>
              {workspace.is_demo ? (
                <button type="button" role="switch" aria-checked={compare} onClick={() => setCompare(!compare)} className="flex min-h-10 items-center gap-2.5 rounded-lg px-3 text-sm text-muted-foreground hover:bg-raised/50">
                  <span className={`relative h-5 w-9 rounded-full transition-colors ${compare ? "bg-primary" : "bg-raised"}`}><span className={`absolute top-0.5 size-4 rounded-full bg-foreground transition-transform ${compare ? "translate-x-[18px]" : "translate-x-0.5"}`} /></span>
                  Compare with NVD-only
                </button>
              ) : null}
              <div className="ml-auto flex items-center gap-3 px-2 text-xs text-muted-foreground">
                {compare ? <span className="text-high">{misses.size} missed by NVD-only</span> : null}
                <span className="num">{rows.length} of {all.length}</span>
                {filtered ? <button type="button" onClick={clear} className="flex items-center gap-1 rounded-md px-2 py-1 hover:bg-raised hover:text-foreground"><X className="size-3.5" aria-hidden="true" />Clear</button> : null}
              </div>
            </div>

            {rows.length === 0 ? <Empty title="Nothing matches these filters." action="Clear filters" onClick={clear} /> : (
              <div className="overflow-x-auto rounded-xl border border-border bg-surface">
                <table className="w-full min-w-[1080px] text-sm">
                  <thead className="text-left text-xs text-muted-foreground">
                    {table.getHeaderGroups().map((group) => (
                      <tr key={group.id} className="border-b border-border">
                        {group.headers.map((header) => {
                          const sorted = header.column.getIsSorted()
                          const label = flexRender(header.column.columnDef.header, header.getContext())
                          return (
                            <th key={header.id} className="px-4 py-3 font-medium" aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}>
                              {header.column.getCanSort() ? (
                                <button type="button" onClick={header.column.getToggleSortingHandler()} className="inline-flex items-center gap-1 hover:text-foreground">
                                  {label}
                                  {sorted === "asc" ? <ArrowUp className="size-3" aria-hidden="true" /> : sorted === "desc" ? <ArrowDown className="size-3" aria-hidden="true" /> : null}
                                </button>
                              ) : label}
                            </th>
                          )
                        })}
                      </tr>
                    ))}
                  </thead>
                  <tbody>
                    {table.getRowModel().rows.map((row) => (
                      <tr data-demo="patch" key={row.id} className="border-t border-border/60 hover:bg-raised/40">
                        {row.getVisibleCells().map((cell) => <td key={cell.id} className="px-4 py-3 align-middle">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <details className="text-xs leading-5 text-muted-foreground">
              <summary className="w-fit cursor-pointer hover:text-foreground">How priority, confidence and agreement are worked out</summary>
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                <p><span className="text-foreground">Priority</span> = 40 × exploited + 20 × EPSS percentile + 15 × CVSS/10 + 15 × internet-facing + 10 × criticality.</p>
                <p><span className="text-foreground">Confidence</span> is the trust Sibyl gives the source that decided the verdict (0.95 for GHSA and OSV ranges), lowered when the verdict rests on advisory prose, an unresolved conflict or a missing source. Most cases rest on a clean GHSA or OSV range, so most read 0.95.</p>
                <p><span className="text-foreground">Source agreement</span> shows each source's position: green agrees with the verdict, red disagrees, grey is silent on this package.</p>
              </div>
            </details>
          </>
        ) : null}
      </main>
    </div>
  )
}

function ViewCard({ id, label, hint, count, active, onSelect }: { id: ViewId; label: string; hint: string; count: number; active: boolean; onSelect: () => void }) {
  const accent = id === "exploited" ? "bg-critical" : id === "patch" ? "bg-high" : id === "needs_human" ? "bg-primary" : id === "closed" ? "bg-success" : "bg-info"
  return (
    <button type="button" role="tab" aria-selected={active} onClick={onSelect} className={`group relative overflow-hidden rounded-xl border p-4 text-left transition-colors ${active ? "border-primary/60 bg-raised" : "border-border bg-surface hover:border-input hover:bg-raised/50"}`}>
      <span className={`absolute inset-y-0 left-0 w-1 ${accent} ${active ? "opacity-100" : "opacity-40 group-hover:opacity-70"}`} aria-hidden="true" />
      <span className="block text-xs font-medium text-muted-foreground">{label}</span>
      <span className="num mt-1 block text-[28px] font-semibold leading-9">{count}</span>
      <span className="block truncate text-xs text-dim">{hint}</span>
    </button>
  )
}

function Priority({ card }: { card: Row }) {
  const score = Number(card.score) || 0
  const tone = score >= 70 ? "bg-critical" : score >= 40 ? "bg-high" : score >= 20 ? "bg-medium" : "bg-low"
  if (card.branch !== "ranked") return <span className="text-xs text-dim">—</span>
  return (
    <div className="flex w-24 flex-col gap-1.5" title={Object.entries(card.score_factors || {}).map(([name, value]) => `${name} ${value}`).join(" · ")}>
      <span className="num text-sm font-semibold">{score.toFixed(1)}</span>
      <span className="h-1 w-full overflow-hidden rounded-full bg-raised"><span className={`block h-full rounded-full ${tone}`} style={{ width: `${Math.min(100, score)}%` }} /></span>
    </div>
  )
}

function Verdict({ card }: { card: Row }) {
  if (card.branch === "needs_human") return <span className="whitespace-nowrap rounded-md bg-primary/15 px-2 py-0.5 text-xs text-primary">Needs you</span>
  if (card.verdict === "affected") return <span className="whitespace-nowrap rounded-md bg-high/15 px-2 py-0.5 text-xs text-high">Affected</span>
  return <span className="whitespace-nowrap rounded-md bg-success/15 px-2 py-0.5 text-xs text-success">Not affected</span>
}

const FACTOR_LABEL: Record<string, string> = {
  source_trust: "source trust",
  llm_text: "read from prose",
  blocking_conflict: "unresolved conflict",
  degraded_source: "source missing",
}

function Confidence({ card }: { card: Row }) {
  const value = Number(card.confidence) || 0
  const tone = value >= 0.8 ? "bg-success" : value >= 0.5 ? "bg-medium" : "bg-critical"
  const why = (card.confidence_factors || []).filter((factor) => factor.name !== "base" && factor.name !== "hmem_unavailable").map((factor) => `${FACTOR_LABEL[factor.name] ?? factor.name} × ${factor.value}`).join(", ")
  return (
    <div className="flex w-24 flex-col gap-1.5" title={why ? `Confidence ${value} = ${why}` : undefined}>
      <span className="num text-sm">{value.toFixed(2)}</span>
      <span className="h-1 w-full overflow-hidden rounded-full bg-raised"><span className={`block h-full rounded-full ${tone}`} style={{ width: `${value * 100}%` }} /></span>
    </div>
  )
}

function Signals({ card }: { card: Row }) {
  const epss = Number(card.epss_percentile ?? 0)
  const cvss = Number(card.cvss ?? 0)
  const cvssTone = cvss >= 9 ? "text-critical" : cvss >= 7 ? "text-high" : cvss >= 4 ? "text-medium" : "text-low"
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {card.exploited ? <span className="inline-flex items-center gap-1 whitespace-nowrap rounded-md bg-critical/15 px-2 py-0.5 text-critical"><Flame className="size-3" aria-hidden="true" />Exploited</span> : null}
      {cvss ? <span className={`num whitespace-nowrap rounded-md bg-raised px-2 py-0.5 ${cvssTone}`} title={[card.cvss_source, card.cvss_version].filter(Boolean).join(" ") || undefined}>CVSS {cvss.toFixed(1)}</span> : null}
      {epss ? <span className="num whitespace-nowrap rounded-md bg-raised px-2 py-0.5 text-muted-foreground" title="EPSS percentile: how likely exploitation is, against all CVEs">EPSS {epss >= 0.99 ? (epss * 100).toFixed(1) : Math.round(epss * 100)}%</span> : null}
      {!card.exploited && !cvss && !epss ? <span className="text-dim">—</span> : null}
    </div>
  )
}

function stance(card: ReportCase, source: string) {
  const position = card.positions.find((item) => item.source === source || (source === "cisa" && item.source === "cisa-adp") || item.source.startsWith(`${source}:`))
  if (!position || position.verdict === "not_listed") return { state: "silent" as const, position }
  return { state: position.verdict === card.verdict ? "agrees" as const : "disagrees" as const, position }
}

function Agreement({ card }: { card: Row }) {
  const stances = SOURCES.map((source) => ({ source, ...stance(card, source.id) }))
  const agree = stances.filter((item) => item.state === "agrees").length
  const disagree = stances.filter((item) => item.state === "disagrees").length
  const summary = `${agree} agree${disagree ? `, ${disagree} disagree` : ""}, ${SOURCES.length - agree - disagree} silent`
  return (
    <div className="flex items-center gap-2" aria-label={summary}>
      <div className="flex gap-1">
        {stances.map(({ source, state, position }) => {
          const style = state === "agrees" ? "border-success/40 bg-success/15 text-success" : state === "disagrees" ? "border-critical/50 bg-critical/15 text-critical" : "border-border text-dim"
          const Icon = state === "agrees" ? Check : state === "disagrees" ? X : Minus
          const title = `${source.name}: ${state === "silent" ? "silent on this package" : `${position?.verdict.replaceAll("_", " ")}${position?.bound ? `, fixed in ${position.bound}` : ""}`}`
          return (
            <span key={source.id} title={title} className={`inline-flex h-6 items-center gap-0.5 rounded-md border px-1.5 text-[10px] font-medium tracking-wide ${style}`}>
              <Icon className="size-2.5" aria-hidden="true" />{source.label}
            </span>
          )
        })}
      </div>
      {disagree ? <span className="whitespace-nowrap text-xs text-critical">conflict</span> : null}
    </div>
  )
}

function CopyButton({ value }: { value: string }) {
  const [done, setDone] = useState(false)
  return (
    <button type="button" aria-label={`Copy ${value}`} title="Copy" onClick={() => { navigator.clipboard.writeText(value).then(() => { setDone(true); setTimeout(() => setDone(false), 1200) }).catch(() => undefined) }} className="rounded p-0.5 text-dim hover:bg-raised hover:text-foreground">
      {done ? <Check className="size-3.5 text-success" aria-hidden="true" /> : <Copy className="size-3.5" aria-hidden="true" />}
    </button>
  )
}

function keyOf(card: ReportCase) {
  return `${serviceOf(card)}:${card.package}:${card.version}:${card.vuln_id}`
}

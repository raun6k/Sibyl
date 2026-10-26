import { useEffect, useMemo, useState } from "react"
import { Link, useSearchParams } from "react-router"
import { createColumnHelper, flexRender, getCoreRowModel, getSortedRowModel, useReactTable, type SortingState } from "@tanstack/react-table"
import { api, type BaselineRow, type Report, type ReportCase } from "@/api"
import { Empty, Loading, PanelError } from "@/states"
import { useWorkspace } from "@/workspace"

const helper = createColumnHelper<ReportCase>()
const GLYPHS = ["osv", "ghsa", "cna", "cisa", "nvd", "euvd"] as const

export function PatchList() {
  const { workspace } = useWorkspace()
  const [params] = useSearchParams()
  const [report, setReport] = useState<Report | null>(null)
  const [runs, setRuns] = useState<{ run_id: string; status: string }[]>([])
  const [error, setError] = useState("")
  const [filter, setFilter] = useState(params.get("filter") || "all")
  const [query, setQuery] = useState(params.get("q") || "")
  const [service, setService] = useState(params.get("service") || "")
  const [compare, setCompare] = useState(false)
  const [baseline, setBaseline] = useState<BaselineRow[]>([])
  const [sorting, setSorting] = useState<SortingState>([{ id: "score", desc: true }])

  useEffect(() => {
    api.runs().then(async (body) => {
      setRuns(body.runs)
      const done = body.runs.find((run) => run.status === "DONE")
      if (!done) {
        setReport(null)
        return
      }
      setReport(await api.report(done.run_id))
    }).catch((exc: Error) => setError(exc.message))
  }, [])

  useEffect(() => {
    if (!compare) return
    api.baselines("fixtures").then((body) => setBaseline(body.rows)).catch((exc: Error) => setError(exc.message))
  }, [compare])

  const rows = useMemo(() => {
    if (!report) return []
    const all = [
      ...report.ranked.map((card) => ({ ...card, branch: "ranked" })),
      ...report.needs_human.map((card) => ({ ...card, branch: "needs_human" })),
      ...report.closed.map((card) => ({ ...card, branch: "closed" })),
    ]
    return all.filter((card) => {
      if (filter === "affected" && !(card.verdict === "affected" && card.branch !== "needs_human")) return false
      if (filter === "needs_human" && card.branch !== "needs_human") return false
      if (filter === "closed" && card.branch !== "closed") return false
      if (filter === "patch" && !(card.verdict === "affected" && card.branch === "ranked")) return false
      if (service && !card.case_id.includes(service)) return false
      if (query) {
        const blob = `${card.vuln_id} ${card.package} ${card.case_id}`.toLowerCase()
        if (!blob.includes(query.toLowerCase())) return false
      }
      return true
    })
  }, [report, filter, query, service])

  const misses = useMemo(() => {
    const predicted = new Set(baseline.filter((row) => row.prediction === "affected").map((row) => `${row.service_id}:${row.package}:${row.version}:${row.vuln_id}`))
    return new Set(rows.filter((card) => card.verdict === "affected" && !predicted.has(keyOf(card))).map((card) => card.case_id))
  }, [baseline, rows])

  const columns = useMemo(() => [
    helper.accessor("score", { header: "Priority", cell: (info) => <span className="num">{info.getValue()}</span> }),
    helper.accessor("vuln_id", {
      header: "CVE",
      cell: (info) => (
        <span className="mono inline-flex items-center gap-1">
          <Link to={`/cases/${encodeURIComponent(info.row.original.case_id)}`}>{info.getValue()}</Link>
          <button type="button" aria-label={`Copy ${info.getValue()}`} onClick={() => navigator.clipboard.writeText(info.getValue())}>Copy</button>
        </span>
      ),
    }),
    helper.display({ id: "component", header: "Component", cell: (info) => `${info.row.original.package}@${info.row.original.version}` }),
    helper.display({ id: "service", header: "Service", cell: (info) => info.row.original.case_id.split(":")[1] ?? "" }),
    helper.accessor("verdict", { header: "Verdict" }),
    helper.accessor("confidence", { header: "Confidence", cell: (info) => <span className="num">{info.getValue()}</span> }),
    helper.accessor("exploited", { header: "Exploited", cell: (info) => (info.getValue() ? "Yes" : "No") }),
    helper.display({
      id: "epss",
      header: "EPSS",
      cell: (info) => <span className="num">{formatFactor(info.row.original.epss_percentile)}</span>,
    }),
    helper.display({
      id: "cvss",
      header: "CVSS",
      cell: (info) => {
        const card = info.row.original
        const detail = [card.cvss_source, card.cvss_version].filter(Boolean).join(" ")
        return <span className="num" title={detail || undefined}>{formatFactor(card.cvss)}</span>
      },
    }),
    helper.display({
      id: "glyphs",
      header: "Agreement",
      cell: (info) => {
        const label = GLYPHS.map((name) => {
          const position = info.row.original.positions.find((item) => item.source === name || (name === "cisa" && item.source === "cisa-adp"))
          return `${name} ${position?.verdict ?? "none"}`
        }).join(", ")
        return <span aria-label={label}>{GLYPHS.map((name) => glyph(info.row.original, name)).join(" ")}</span>
      },
    }),
    helper.display({
      id: "miss",
      header: "",
      cell: (info) => compare && misses.has(info.row.original.case_id) ? <span>NVD-only misses</span> : null,
    }),
  ], [compare, misses])

  const table = useReactTable({ data: rows, columns, state: { sorting }, onSortingChange: setSorting, getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel() })

  const kpis = [
    ["patch", "Patch now", report?.ranked.length ?? 0],
    ["affected", "Affected", (report?.ranked.length ?? 0)],
    ["needs_human", "Needs human", report?.needs_human.length ?? 0],
    ["closed", "Not affected", report?.closed.length ?? 0],
  ] as const

  return (
    <main className="mx-auto flex max-w-[1440px] flex-col gap-4 px-4 py-6 sm:px-8">
      <h1 className="text-2xl font-semibold">Patch list</h1>
      {error ? <PanelError message={error} onRetry={() => window.location.reload()} /> : null}
      {!report && !error ? <Loading label="Patch list" /> : null}
      {report ? (
        <>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            {kpis.map(([id, label, value]) => (
              <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(filter === id ? "all" : id)} className={`rounded-xl border border-border bg-surface p-4 text-left ${filter === id ? "ring-2 ring-primary" : ""}`}>
                <div className="text-xs text-muted-foreground">{label}</div>
                <div className="num text-[28px] font-semibold">{value}</div>
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Filter rows" aria-label="Filter rows" className="h-8 rounded-md border border-input bg-background px-2" />
            {workspace.is_demo ? (
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={compare} onChange={(event) => setCompare(event.target.checked)} />
                Compare with an NVD-only matcher
              </label>
            ) : null}
            {compare ? <span className="text-sm">{misses.size} NVD-only misses</span> : null}
          </div>
          {rows.length === 0 ? <Empty title="Nothing matches this filter" action="Clear filter" onClick={() => { setFilter("all"); setQuery(""); setService("") }} /> : null}
          <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full min-w-[960px] text-sm">
              <thead className="bg-surface text-left">
                {table.getHeaderGroups().map((group) => (
                  <tr key={group.id}>
                    {group.headers.map((header) => (
                      <th key={header.id} className="px-3 py-2 font-medium">
                        {header.column.getCanSort() ? (
                          <button type="button" onClick={header.column.getToggleSortingHandler()}>{flexRender(header.column.columnDef.header, header.getContext())}</button>
                        ) : flexRender(header.column.columnDef.header, header.getContext())}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr key={row.id} className="border-t border-border">
                    {row.getVisibleCells().map((cell) => <td key={cell.id} className="px-3 py-2 align-top">{flexRender(cell.column.columnDef.cell, cell.getContext())}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground">
            score = 40×exploited + 20×EPSS percentile + 15×CVSS/10 + 15×internet-facing + 10×criticality.
            Glyphs: OSV GHSA CNA CISA NVD EUVD. ★ agrees, ✕ disagrees, — silent.
            {runs[0] ? ` Latest run ${runs[0].run_id.slice(0, 8)}.` : ""}
          </p>
        </>
      ) : null}
    </main>
  )
}

function formatFactor(value: number | undefined) {
  const number = Number(value ?? 0)
  if (!Number.isFinite(number)) return "0"
  return String(Math.round(number * 10000) / 10000)
}

function keyOf(card: ReportCase) {
  const service = card.case_id.split(":")[1] ?? ""
  return `${service}:${card.package}:${card.version}:${card.vuln_id}`
}

function glyph(card: ReportCase, source: string) {
  const position = card.positions.find((item) => item.source === source || (source === "cisa" && item.source === "cisa-adp"))
  if (!position) return "—"
  if (position.verdict === "not_listed") return "—"
  if (position.verdict === card.verdict) return "★"
  return "✕"
}

import { useEffect, useState } from "react"
import { Link, useParams } from "react-router"
import { api, type CaseFile } from "@/api"
import { Loading, PanelError } from "@/states"

const MARK: Record<string, string> = { star: "★", miss: "✕", partial: "◐", none: "—" }

export function CaseScreen() {
  const params = useParams()
  const caseId = params["*"] ? decodeURIComponent(params["*"]) : ""
  const [file, setFile] = useState<CaseFile | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!caseId) return
    api.case(caseId).then(setFile).catch((exc: Error) => setError(exc.message))
  }, [caseId])

  const card = file?.case
  return (
    <main className="mx-auto flex max-w-[1100px] flex-col gap-4 px-4 py-6 sm:px-8">
      <p className="text-sm text-muted-foreground"><Link to="/patches">Patch list</Link> / Case file</p>
      {error ? <PanelError message={error} onRetry={() => window.location.reload()} /> : null}
      {!file && !error ? <Loading label="Case file" /> : null}
      {card && file ? (
        <>
          <h1 className="mono text-2xl font-semibold">{card.vuln_id}</h1>
          <p>{card.package}@{card.version} · {card.verdict} · resolution {card.resolution || "—"} · method {card.method}</p>
          <p className="max-w-3xl text-muted-foreground">{card.rationale}</p>
          <div className="grid gap-4 lg:grid-cols-2">
            <section className="rounded-xl border border-border bg-surface p-4">
              <h2 className="font-semibold">Confidence {card.confidence}</h2>
              <ul className="mt-2 flex flex-col gap-1 text-sm">
                {card.confidence_factors.map((factor) => (
                  <li key={factor.name} className="flex justify-between gap-3"><span>{factor.name}</span><span className="num">× {factor.value}</span></li>
                ))}
              </ul>
              {(card.low_trust_flags ?? []).map((flag) => <p key={flag} className="mt-2 text-sm">Flagged: {flag}</p>)}
            </section>
            <section className="rounded-xl border border-border bg-surface p-4">
              <h2 className="font-semibold">Priority {card.score}</h2>
              {Object.entries(card.score_factors).map(([name, value]) => (
                <div key={name} className="mt-2">
                  <div className="flex justify-between text-xs"><span>{name}</span><span className="num">{value}</span></div>
                  <div className="h-1 rounded-full bg-raised"><div className="h-1 rounded-full bg-primary" style={{ width: `${Math.min(100, Number(value))}%` }} /></div>
                </div>
              ))}
            </section>
          </div>
          <section className="overflow-x-auto rounded-xl border border-border">
            <h2 className="px-4 pt-4 font-semibold">Provenance</h2>
            <table className="mt-2 w-full min-w-[640px] text-sm">
              <thead>
                <tr>
                  <th className="px-3 py-2 text-left">Field</th>
                  {Object.keys(file.provenance.matrix[0]?.cells ?? {}).map((source) => <th key={source} className="px-3 py-2 text-left">{source}</th>)}
                </tr>
              </thead>
              <tbody>
                {file.provenance.matrix.map((row) => (
                  <tr key={row.field} className="border-t border-border">
                    <th className="px-3 py-2 text-left font-medium">{row.field}</th>
                    {Object.entries(row.cells).map(([source, mark]) => <td key={source} className="px-3 py-2">{MARK[mark] ?? "—"}</td>)}
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section>
            <h2 className="font-semibold">How Sibyl got here</h2>
            <ol className="mt-2 flex flex-col gap-2">
              {file.events.length === 0 ? <li className="text-muted-foreground">No trace events were stored for this case.</li> : null}
              {file.events.map((event) => (
                <li key={event.event_id} className="rounded-lg border border-border bg-surface p-3 text-sm">
                  <span className="font-medium">{event.actor}</span> {event.type}
                  {event.payload.action ? ` · ${String(event.payload.action)}` : ""}
                  {event.payload.reason ? <span className="mt-1 block text-muted-foreground">{String(event.payload.reason)}</span> : null}
                  {event.payload.quote ? <q className="mt-1 block">{String(event.payload.quote)}</q> : null}
                </li>
              ))}
            </ol>
          </section>
          <section>
            <h2 className="font-semibold">Evidence</h2>
            <ul className="mt-2 text-sm">
              {file.provenance.records.map((record) => (
                <li key={record.record_id} className="mono">{record.record_id} · {record.source} · {record.status} · {record.retrieved_at}</li>
              ))}
            </ul>
          </section>
        </>
      ) : null}
    </main>
  )
}

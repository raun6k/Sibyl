import { useEffect, useState } from "react"
import { Link } from "react-router"
import { api, type ReportCase } from "@/api"
import { Empty, Loading, PanelError } from "@/states"

export function Queue() {
  const [items, setItems] = useState<ReportCase[] | null>(null)
  const [error, setError] = useState("")
  const [current, setCurrent] = useState(0)
  const [decision, setDecision] = useState("affected")
  const [note, setNote] = useState("")
  const [remember, setRemember] = useState(true)
  const [scope, setScope] = useState("this_case")
  const [pending, setPending] = useState("")
  const [saved, setSaved] = useState("")

  function load() {
    setError("")
    api.queue().then((body) => setItems(body.needs_human)).catch((exc: Error) => setError(exc.message))
  }
  useEffect(load, [])

  const item = items?.[current]

  async function save() {
    if (!item) return
    setSaved("")
    try {
      const result = await api.resolve(item.case_id, { decision, note, user: "priya", remember, scope })
      setSaved(item.case_id)
      setPending(result.pending?.id ?? "")
      load()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "could not save")
    }
  }

  return (
    <main className="mx-auto flex max-w-[900px] flex-col gap-4 px-4 py-6 sm:px-8">
      <h1 className="text-2xl font-semibold">Needs human</h1>
      {error ? <PanelError message={error} onRetry={load} /> : null}
      {items == null && !error ? <Loading label="Needs human" /> : null}
      {items && items.length === 0 ? <Empty title="The queue is empty" action="Open patch list" href="/patches" /> : null}
      {item ? (
        <article className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-4">
          <h2 className="text-lg font-semibold">{item.question || `Is ${item.package}@${item.version} affected by ${item.vuln_id}?`}</h2>
          <ul className="flex flex-col gap-1 text-sm">
            {item.positions.length === 0 ? <li className="text-muted-foreground">No source position was recorded.</li> : null}
            {item.positions.map((position) => (
              <li key={position.source}>{position.source}: {position.verdict}{position.status && position.status !== "active" ? ` (${position.status})` : ""}{position.bound ? ` bound ${position.bound}` : ""}</li>
            ))}
          </ul>
          <fieldset className="flex flex-col gap-2 border-0 p-0">
            <legend className="text-sm font-medium">Decision</legend>
            {["affected", "not_affected", "accept_risk"].map((value) => (
              <label key={value} className="flex items-center gap-2">
                <input type="radio" name="decision" value={value} checked={decision === value} onChange={() => setDecision(value)} />
                {value === "affected" ? "Affected" : value === "not_affected" ? "Not affected" : "Accept risk"}
              </label>
            ))}
          </fieldset>
          <label className="flex flex-col gap-1 text-sm">
            Note
            <textarea value={note} onChange={(event) => setNote(event.target.value)} rows={3} className="rounded-md border border-input bg-background p-2" />
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
            Remember for future runs
          </label>
          <fieldset className="flex flex-col gap-2 border-0 p-0" disabled={!remember}>
            <legend className="text-sm">Scope</legend>
            <label className="flex items-center gap-2"><input type="radio" name="scope" checked={scope === "this_case"} onChange={() => setScope("this_case")} /> This case only</label>
            <label className="flex items-center gap-2"><input type="radio" name="scope" checked={scope === "adjust_trust"} onChange={() => setScope("adjust_trust")} /> Adjust source trust</label>
          </fieldset>
          <button type="button" onClick={save} className="h-10 rounded-md bg-primary font-semibold text-primary-foreground">Save resolution</button>
          {saved ? <p>Saved {saved}. {pending ? <Link to="/memory">Review the pending trust change →</Link> : "It applies on the next run."}</p> : null}
          <div className="flex gap-2">
            <button type="button" disabled={current === 0} onClick={() => setCurrent((value) => value - 1)}>Previous</button>
            <button type="button" disabled={!items || current >= items.length - 1} onClick={() => setCurrent((value) => value + 1)}>Next</button>
          </div>
        </article>
      ) : null}
    </main>
  )
}

import { useEffect, useState } from "react"
import { api, type MemorySnapshot } from "@/api"
import { Empty, Loading, PanelError } from "@/states"

export function MemoryScreen() {
  const [memory, setMemory] = useState<MemorySnapshot | null>(null)
  const [error, setError] = useState("")

  function load() {
    setError("")
    api.memory().then(setMemory).catch((exc: Error) => setError(exc.message))
  }
  useEffect(load, [])

  async function decide(id: string, approve: boolean) {
    try {
      if (approve) await api.approve(id)
      else await api.reject(id)
      load()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "could not update memory")
    }
  }

  return (
    <main className="mx-auto flex max-w-[1000px] flex-col gap-4 px-4 py-6 sm:px-8">
      <h1 className="text-2xl font-semibold">Memory</h1>
      <p className="rounded-lg border border-border bg-surface p-3 text-sm">A low-trust source cannot overwrite a high-trust fact. Trust changes and new mappings stay pending until you approve them.</p>
      {error ? <PanelError message={error} onRetry={load} /> : null}
      {memory?.unavailable ? <PanelError message={memory.error || "H-MEM is unavailable. Trust falls back to the default table."} onRetry={load} /> : null}
      {!memory && !error ? <Loading label="Memory" /> : null}
      {memory ? (
        <>
          <section>
            <h2 className="font-semibold">Pending changes</h2>
            {memory.pending.length === 0 ? <Empty title="No pending changes" action="Open the queue" href="/queue" /> : null}
            <ul className="mt-2 flex flex-col gap-2">
              {memory.pending.map((change) => (
                <li key={change.id} className="rounded-xl border border-border bg-surface p-4">
                  <p className="font-medium">{change.kind === "trust" ? `Trust ${change.source} · ${change.field} · ${change.ecosystem || "*"}: ${change.previous} → ${change.weight}` : `${change.product} → ${change.purl}`}</p>
                  <p className="text-sm text-muted-foreground">{change.case_id ? `From ${change.case_id}. ` : ""}{change.reason}</p>
                  <div className="mt-2 flex gap-2">
                    <button type="button" onClick={() => decide(change.id, true)} className="rounded-md bg-primary px-3 py-1 text-primary-foreground">Approve</button>
                    <button type="button" onClick={() => decide(change.id, false)} className="rounded-md border border-border px-3 py-1">Reject</button>
                  </div>
                </li>
              ))}
            </ul>
          </section>
          <section className="overflow-x-auto">
            <h2 className="font-semibold">Trust ledger</h2>
            <table className="mt-2 w-full min-w-[640px] text-sm">
              <thead><tr><th className="px-2 py-1 text-left">Source</th><th className="text-left">Field</th><th className="text-left">Ecosystem</th><th className="text-left">Weight</th></tr></thead>
              <tbody>
                {memory.trust.filter((row) => !row.superseded).map((row) => (
                  <tr key={`${row.source}-${row.field}-${row.ecosystem}`} className="border-t border-border">
                    <td className="px-2 py-1">{row.source}</td>
                    <td>{row.field}</td>
                    <td>{row.ecosystem}</td>
                    <td>
                      <span className="inline-block h-1 rounded-full bg-primary align-middle" style={{ width: `${row.weight * 80}px` }} />
                      <span className="num ml-2">{row.weight}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
          <section>
            <h2 className="font-semibold">Learned mappings</h2>
            {memory.mappings.length === 0 ? <p className="text-sm text-muted-foreground">None approved yet.</p> : null}
            <ul>{memory.mappings.map((item) => <li key={item.product} className="mono text-sm">{item.product} → {item.purl}</li>)}</ul>
          </section>
          <section>
            <h2 className="font-semibold">Human resolutions</h2>
            <ul className="flex flex-col gap-2">
              {memory.resolutions.map((item) => (
                <li key={`${item.case_id}-${item.at}`} className="text-sm">
                  <span className="font-medium">{item.user || "someone"}</span> · {item.at?.slice(0, 10)} · {item.decision} · {item.scope}
                  <span className="block text-muted-foreground">{item.note}{item.expiry ? ` · expires ${item.expiry.slice(0, 10)}` : ""}</span>
                </li>
              ))}
            </ul>
          </section>
        </>
      ) : null}
    </main>
  )
}

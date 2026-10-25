import { useEffect, useState } from "react"
import { Link, useNavigate } from "react-router"
import { api, type RunState, type ServiceCard } from "@/api"
import { Empty, Loading, PanelError } from "@/states"

const SOURCES = ["osv", "ghsa", "nvd", "cve_org", "kev", "epss", "euvd"]
const WINDOWS = [7, 14, 30]

export function Inventory() {
  const [services, setServices] = useState<ServiceCard[] | null>(null)
  const [runs, setRuns] = useState<RunState[]>([])
  const [error, setError] = useState("")
  const [windowDays, setWindowDays] = useState(14)
  const [dataset, setDataset] = useState("fixtures")
  const [disabled, setDisabled] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()

  function load() {
    setError("")
    Promise.all([api.inventory(), api.runs(), api.sources()])
      .then(([inventory, runList]) => {
        setServices(inventory.services)
        setRuns(runList.runs)
      })
      .catch((exc: Error) => setError(exc.message))
  }

  useEffect(load, [])

  async function start() {
    setBusy(true)
    try {
      const started = await api.start({ dataset, disable_sources: disabled, window_days: windowDays })
      navigate(`/runs/${started.run_id}`)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "the run did not start")
      setBusy(false)
    }
  }

  return (
    <main className="mx-auto flex max-w-[1376px] flex-col gap-6 px-4 py-6 sm:px-8">
      <div>
        <h1 className="text-2xl font-semibold">Acme Payments</h1>
        <p className="text-muted-foreground">
          {services ? `${services.length} services · ${services.reduce((sum, item) => sum + item.components, 0)} components (PyPI, npm)` : "Loading services"}
        </p>
      </div>
      {error ? <PanelError message={error} onRetry={load} /> : null}
      <div className="flex flex-wrap items-start gap-6">
        <section className="flex min-w-0 flex-[999] flex-col gap-4 basis-[560px]">
          <h2 className="text-lg font-semibold">Services</h2>
          {services == null && !error ? <Loading label="Services" /> : null}
          {services && services.length === 0 ? <Empty title="No SBOMs yet" action="Use sample company" href="/" /> : null}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {services?.map((service) => (
              <article key={service.service_id} className="flex flex-col gap-3 rounded-xl border border-border bg-surface p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="mono font-medium">{service.name}</span>
                  <span className="rounded-full bg-raised px-2 text-xs">{service.internet_facing === "true" || service.internet_facing === "t" ? "Internet-facing" : "Internal"}</span>
                </div>
                <p className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                  <span>{service.pypi} PyPI · {service.npm} npm</span>
                  <span className="num">{service.components} components</span>
                  <span>SBOM {service.sbom_at ? String(service.sbom_at).slice(0, 10) : "—"}</span>
                </p>
                <div className="flex items-center gap-2">
                  <span className="w-20 text-xs text-muted-foreground">Criticality</span>
                  <span className="h-1 flex-1 overflow-hidden rounded-full bg-raised">
                    <span className="block h-1 bg-primary" style={{ width: `${Math.round(Number(service.criticality) * 100)}%` }} />
                  </span>
                  <span className="num w-8 text-right text-xs">{service.criticality}</span>
                </div>
                <div className="flex flex-wrap items-center gap-3 border-t border-border pt-3">
                  <span className="num font-semibold">! {service.affected} affected</span>
                  <span className="num text-primary">? {service.needs_human} need a human</span>
                  <Link className="ml-auto" to={`/patches?service=${service.service_id}`}>Open in patch list →</Link>
                </div>
              </article>
            ))}
          </div>
        </section>
        <aside aria-label="Start a run" className="flex w-full max-w-md flex-1 basis-[320px] flex-col gap-4">
          <div className="flex flex-col gap-4 rounded-xl border border-border bg-surface p-4">
            <h2 className="text-sm font-semibold">Run weekly triage</h2>
            <div>
              <span id="win-label" className="text-xs text-muted-foreground">CVEs published or changed in the last</span>
              <div role="group" aria-labelledby="win-label" className="mt-2 flex gap-0.5 rounded-md border border-input p-0.5">
                {WINDOWS.map((days) => (
                  <button key={days} type="button" aria-pressed={windowDays === days} onClick={() => setWindowDays(days)} className={`flex-1 rounded px-2 py-1 text-sm ${windowDays === days ? "bg-raised font-medium" : ""}`}>
                    {days} days
                  </button>
                ))}
              </div>
            </div>
            <label className="text-xs text-muted-foreground">
              Dataset
              <select value={dataset} onChange={(event) => setDataset(event.target.value)} className="mt-1 block h-8 w-full rounded-md border border-input bg-background px-2 text-sm text-foreground">
                <option value="fixtures">Fixtures</option>
                <option value="subset">Subset</option>
                <option value="full">Full snapshots</option>
              </select>
            </label>
            <fieldset className="flex flex-col gap-1 border-0 p-0">
              <legend className="mb-2 text-xs text-muted-foreground">Sources</legend>
              {SOURCES.map((source) => (
                <label key={source} className="flex h-8 items-center gap-2">
                  <input
                    type="checkbox"
                    checked={!disabled.includes(source)}
                    onChange={() => setDisabled((current) => current.includes(source) ? current.filter((item) => item !== source) : [...current, source])}
                  />
                  <span className="flex-1">{source}</span>
                </label>
              ))}
            </fieldset>
            <button type="button" disabled={busy} onClick={start} className="flex h-10 items-center justify-center rounded-md bg-primary font-semibold text-primary-foreground disabled:opacity-60">
              {busy ? "Starting…" : `Run weekly triage · ${windowDays} days`}
            </button>
          </div>
          <div className="rounded-xl border border-border bg-surface p-4">
            <h2 className="mb-2 text-sm font-semibold">Recent runs</h2>
            {runs.length === 0 ? <p className="text-sm text-muted-foreground">No runs yet. Start a weekly triage.</p> : null}
            {runs.slice(0, 6).map((run) => (
              <Link key={run.run_id} to={`/runs/${run.run_id}`} className="flex h-10 items-center gap-3 border-t border-border text-foreground no-underline">
                <span className="mono num w-16 text-muted-foreground">{run.run_id.slice(0, 8)}</span>
                <span className="flex-1">{run.dataset} · {run.stage}</span>
                <span className="text-xs">{run.degraded_sources.length ? "Degraded" : run.status}</span>
              </Link>
            ))}
          </div>
        </aside>
      </div>
    </main>
  )
}

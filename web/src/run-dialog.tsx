import { useEffect, useRef, useState } from "react"
import { useNavigate } from "react-router"
import { ChevronRight, X } from "lucide-react"
import { api } from "@/api"
import { SOURCE_LABEL, SOURCES } from "@/lib/format"
import type { SourceHealth } from "@/workspace"

const DATASETS = [
  { id: "fixtures", label: "Quick sample", note: "Hand-picked cases. A few minutes." },
  { id: "subset", label: "Acme subset", note: "Every Acme match. About 10 minutes." },
  { id: "full", label: "Full snapshot", note: "The whole download. About 10 minutes." },
]

// The sample snapshots cover one fixed window, so the window is stated, not chosen.
const SAMPLE_WINDOW_DAYS = 14

export function RunDialog({ sources, onClose }: { sources: SourceHealth[] | null; onClose: () => void }) {
  const [dataset, setDataset] = useState("fixtures")
  const [disabled, setDisabled] = useState<string[]>([])
  const [advanced, setAdvanced] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [scope, setScope] = useState<{ services: number; packages: number } | null>(null)
  const start = useRef<HTMLButtonElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    start.current?.focus()
    api.inventory().then((body) => setScope({ services: body.services.length, packages: body.components })).catch(() => undefined)
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") onClose()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [onClose])

  const enabled = SOURCES.length - disabled.length

  async function begin() {
    setBusy(true)
    setError("")
    try {
      const started = await api.start({ dataset, disable_sources: disabled, window_days: SAMPLE_WINDOW_DAYS })
      window.dispatchEvent(new Event("sibyl-runs"))
      onClose()
      navigate(`/runs/${started.run_id}`)
    } catch (exc) {
      const message = exc instanceof Error ? exc.message : ""
      setError(message.includes("already in progress") ? "A triage is already running. Wait for it to finish." : "The triage didn't start. Check that the API is running and try again.")
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-[var(--scrim)] p-4" role="presentation" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="run-title"
        className="flex max-h-[calc(100svh-32px)] w-full max-w-[560px] flex-col overflow-y-auto rounded-2xl border border-hairline bg-panel shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-4 px-8 pt-8">
          <div className="flex flex-col gap-2">
            <span className="eyebrow">New triage</span>
            <h2 id="run-title" className="display text-[32px] leading-[36px]">Consult the sources</h2>
          </div>
          <button type="button" aria-label="Close" onClick={onClose} className="rounded-md p-1.5 text-muted-foreground hover:bg-raised">
            <X className="size-5" aria-hidden="true" />
          </button>
        </div>

        <p className="px-8 pt-3 text-[15px] leading-6 text-muted-foreground">
          Sibyl will check{" "}
          <span className="text-foreground">{scope ? `${scope.packages} packages` : "every package"}</span> across{" "}
          <span className="text-foreground">{scope ? `${scope.services} services` : "your services"}</span> against{" "}
          <span className="text-foreground">{enabled} public sources</span>, settle where they disagree, and rank what to patch.
        </p>

        <ol className="mx-8 mt-6 grid grid-cols-3 gap-px overflow-hidden rounded-xl border border-border bg-border text-sm sm:grid-cols-6">
          {["Collect", "Map", "Match", "Critique", "Prioritise", "Report"].map((step, i) => (
            <li key={step} className="flex flex-col gap-0.5 bg-panel px-3 py-2.5">
              <span className="num text-xs text-dim">{i + 1}</span>
              <span>{step}</span>
            </li>
          ))}
        </ol>

        <p className="px-8 pt-4 text-sm text-muted-foreground">
          Window: advisories from the last <span className="text-foreground">{SAMPLE_WINDOW_DAYS} days</span>, fixed by the sample snapshot.
        </p>

        <div className="mx-8 mt-6 border-t border-hairline">
          <button
            type="button"
            aria-expanded={advanced}
            onClick={() => setAdvanced((open) => !open)}
            className="flex w-full items-center justify-between gap-3 py-4 text-left"
          >
            <span className="flex items-center gap-2 text-sm">
              <ChevronRight className={`size-4 text-dim transition-transform duration-150 ${advanced ? "rotate-90" : ""}`} aria-hidden="true" />
              Advanced: data and sources
            </span>
            <span className="text-xs text-muted-foreground">
              {DATASETS.find((item) => item.id === dataset)?.label} · {enabled} of {SOURCES.length} sources
            </span>
          </button>

          {advanced ? (
            <div className="flex flex-col gap-6 pb-2">
              <fieldset className="flex flex-col gap-2">
                <legend className="eyebrow mb-2">Data</legend>
                {DATASETS.map((item) => (
                  <label
                    key={item.id}
                    className={`flex cursor-pointer items-center gap-3 rounded-xl border px-4 py-3 transition-colors duration-75 ${
                      dataset === item.id ? "border-primary bg-raised" : "border-border hover:bg-raised/50"
                    }`}
                  >
                    <input type="radio" name="dataset" value={item.id} checked={dataset === item.id} onChange={() => setDataset(item.id)} className="accent-[var(--primary)]" />
                    <span className="flex flex-col">
                      <span className="text-sm font-medium">{item.label}</span>
                      <span className="text-xs text-muted-foreground">{item.note}</span>
                    </span>
                  </label>
                ))}
              </fieldset>

              <fieldset>
                <legend className="eyebrow mb-1">Sources</legend>
                <p className="mb-3 text-xs text-muted-foreground">Turn a source off to see how Sibyl copes when it's down.</p>
                <div className="flex flex-wrap gap-2">
                  {SOURCES.map((source) => {
                    const on = !disabled.includes(source)
                    const status = sources?.find((item) => item.source === source)?.status
                    return (
                      <button
                        key={source}
                        type="button"
                        aria-pressed={on}
                        onClick={() => setDisabled((current) => (on ? [...current, source] : current.filter((item) => item !== source)))}
                        className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm transition-colors duration-75 ${
                          on ? "border-hairline bg-raised text-foreground" : "border-dashed border-border text-dim line-through"
                        }`}
                      >
                        <span aria-hidden="true" className={on ? (status === "live" ? "text-success" : "text-primary") : "text-dim"}>
                          {on ? (status === "live" ? "●" : "◐") : "○"}
                        </span>
                        {SOURCE_LABEL[source]}
                      </button>
                    )
                  })}
                </div>
              </fieldset>
            </div>
          ) : null}
        </div>

        {error ? <p role="alert" className="mx-8 mt-2 text-sm text-critical">{error}</p> : null}

        <div className="mt-4 flex justify-end gap-3 border-t border-hairline px-8 py-5">
          <button type="button" onClick={onClose} className="rounded-full border border-hairline px-5 py-2.5 text-sm hover:bg-raised">
            Cancel
          </button>
          <button ref={start} type="button" disabled={busy} onClick={begin} className="btn-gold rounded-full px-6 py-2.5 text-sm font-medium disabled:opacity-60">
            {busy ? "Starting…" : "Begin triage"}
          </button>
        </div>
      </div>
    </div>
  )
}

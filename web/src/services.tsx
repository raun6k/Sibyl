import { Select } from "@/components/ui/select"
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react"
import { useNavigate } from "react-router"
import { Boxes, ChevronDown, FileJson, Globe, Lock, Pencil, Play, Trash2, Upload, X } from "lucide-react"
import { api, DATA_CLASSES, type Schedule, type ServiceRow } from "@/api"
import { PageHeader } from "@/components/page-header"
import { agoIso, ecosystemLabel, until } from "@/lib/format"
import { useWorkspace } from "@/workspace"

const POLICIES = [
  { id: "interval", label: "On a schedule" },
  { id: "on_change", label: "When code or advisories change" },
  { id: "manual", label: "Only when I ask" },
]
const INTERVALS = [
  { minutes: 360, label: "every 6 hours" },
  { minutes: 1440, label: "daily" },
  { minutes: 10080, label: "weekly" },
]

export function Services() {
  const { workspace, refreshInbox } = useWorkspace()
  const [services, setServices] = useState<ServiceRow[] | null>(null)
  const [error, setError] = useState("")
  const [editing, setEditing] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [schedule, setSchedule] = useState<Schedule | null>(null)
  const navigate = useNavigate()

  const load = useCallback(() => {
    api.services(workspace.workspace_id).then((body) => setServices(body.services)).catch((exc: Error) => setError(exc.message))
    api.schedule(workspace.workspace_id).then(setSchedule).catch(() => undefined)
  }, [workspace.workspace_id])

  async function runNow(service: ServiceRow) {
    try {
      const started = await api.triageService(service.service_id)
      window.dispatchEvent(new Event("sibyl-runs"))
      navigate(`/runs/${started.run_id}`)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "The triage did not start.")
    }
  }

  useEffect(load, [load])

  async function remove(service: ServiceRow) {
    if (!window.confirm(`Remove ${service.name}? Its packages and open questions go with it.`)) return
    try {
      await api.removeService(service.service_id)
      load()
      refreshInbox()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Removing failed.")
    }
  }

  return (
    <div>
      <PageHeader
        title="Services"
        meta={services ? `${services.length} services · ${services.reduce((sum, item) => sum + (item.components ?? 0), 0)} packages` : "Loading…"}
        actions={
          <button type="button" onClick={() => setAdding((open) => !open)} className="rounded-full border border-hairline px-5 py-2 text-sm hover:bg-raised">
            {adding ? "Close" : "Add a service by hand"}
          </button>
        }
      />
      <div className="mx-auto flex max-w-[1200px] flex-col gap-6 px-6 py-8 sm:px-10">
        {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
        {adding ? (
          <AddService
            workspaceId={workspace.workspace_id}
            onDone={() => {
              setAdding(false)
              load()
            }}
          />
        ) : null}
        {services && services.length === 0 ? (
          <p className="text-sm text-muted-foreground">No services yet. Connect a repository and Sibyl finds them, or add one by hand with its SBOM.</p>
        ) : null}
        {services == null ? <p className="text-sm text-muted-foreground">Loading services…</p> : null}
        {services?.map((service) => {
          const entry = schedule?.services.find((item) => item.service_id === service.service_id)
          return (
            <details data-demo="service" data-service={service.service_id} key={service.service_id} className="group/service min-w-0 rounded-2xl border border-border bg-surface">
              <summary className="flex min-w-0 cursor-pointer list-none items-center gap-3 rounded-2xl px-5 py-4 hover:bg-raised/40 [&::-webkit-details-marker]:hidden">
                <Boxes className="size-4 shrink-0 text-primary" aria-hidden="true" />
                <div className="flex min-w-0 flex-1 flex-wrap items-center justify-between gap-x-5 gap-y-1">
                  <span className="min-w-0 truncate text-sm font-medium">{service.name}</span>
                  <span className="text-xs text-muted-foreground">Last triaged {entry ? (entry.last_triage ? agoIso(entry.last_triage) : "never") : "unavailable"}</span>
                </div>
                <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open/service:rotate-180" aria-hidden="true" />
              </summary>
              <div className="@container min-w-0 border-t border-border px-5 py-5 [overflow-wrap:anywhere]">
                {editing === service.service_id ? (
                  <div>
                    <h3 className="mb-4 text-xs font-medium text-muted-foreground">Edit service</h3>
                    <EditService service={service} onDone={() => { setEditing(null); load(); refreshInbox() }} />
                  </div>
                ) : (
                  <>
                    <div className="grid gap-6 @min-[620px]:grid-cols-[minmax(0,1fr)_240px]">
                      <section aria-label={`${service.name} details`} className="min-w-0">
                        <h3 className="mb-4 text-xs font-medium text-muted-foreground">Service details</h3>
                        <dl className="grid grid-cols-2 gap-x-5 gap-y-4 text-xs">
                          <div><dt className="text-muted-foreground">Repository</dt><dd className="mt-1.5">{service.repo_id || "Added by hand"}</dd></div>
                          <div><dt className="text-muted-foreground">Path</dt><dd className="mono mt-1.5">{service.repo_id ? service.path || "(root)" : "—"}</dd></div>
                          <div><dt className="text-muted-foreground">Packages</dt><dd className="num mt-1.5">{service.components ?? 0}<span className="mt-1 block text-muted-foreground">{ecosystemLabel(service.ecosystems ?? {})}</span></dd></div>
                          <div><dt className="text-muted-foreground">Owning team</dt><dd className="mt-1.5">{service.team || "Not set"}</dd></div>
                          <div><dt className="text-muted-foreground">Exposure</dt><dd className="mt-1.5 flex items-center gap-1.5">{service.internet_facing ? <Globe className="size-3.5 text-primary" aria-hidden="true" /> : <Lock className="size-3.5 text-muted-foreground" aria-hidden="true" />}{service.internet_facing ? "Internet-facing" : "Internal"}</dd></div>
                          <div><dt className="text-muted-foreground">Data class</dt><dd className="mt-1.5">{service.data_class}</dd></div>
                          <div><dt className="text-muted-foreground">Criticality</dt><dd className="num mt-1.5">{Number(service.criticality).toFixed(1)} <span className="text-muted-foreground">/ 1</span></dd></div>
                        </dl>
                      </section>
                      <section aria-label={`${service.name} triage`} className="min-w-0 @min-[620px]:border-l @min-[620px]:border-border @min-[620px]:pl-5">
                        <h3 className="mb-4 text-xs font-medium text-muted-foreground">Triage</h3>
                        <dl className="space-y-4 text-xs">
                          <div><dt className="text-muted-foreground">Run policy</dt><dd className="mt-1.5 leading-5">{policyLabel(service)}</dd></div>
                          <div><dt className="text-muted-foreground">Next run</dt><dd className="mt-1.5 leading-5"><NextRun entry={entry} automatic={schedule?.automatic ?? true} /></dd></div>
                        </dl>
                      </section>
                    </div>
                    <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-4">
                      <div className="flex flex-wrap gap-2">
                        <button type="button" aria-label={`Run triage of ${service.name} now`} onClick={() => runNow(service)} className="flex min-h-9 items-center gap-2 rounded-lg bg-primary/15 px-3 text-xs font-medium text-primary hover:bg-primary/25"><Play className="size-3.5" aria-hidden="true" />Run triage</button>
                        <button type="button" aria-label={`Edit ${service.name}`} onClick={() => setEditing(service.service_id)} className="flex min-h-9 items-center gap-2 rounded-lg border border-border px-3 text-xs text-muted-foreground hover:bg-raised hover:text-foreground"><Pencil className="size-3.5" aria-hidden="true" />Edit service</button>
                      </div>
                      <button type="button" aria-label={`Remove ${service.name}`} onClick={() => remove(service)} className="flex min-h-9 items-center gap-2 rounded-lg px-3 text-xs text-critical hover:bg-critical/10"><Trash2 className="size-3.5" aria-hidden="true" />Remove</button>
                    </div>
                  </>
                )}
              </div>
            </details>
          )
        })}
        <p className="text-xs text-muted-foreground">
          What you set here counts as confirmed: Sibyl keeps it even when a later scan of the code suggests otherwise, and asks you instead.
        </p>
      </div>
    </div>
  )
}

function NextRun({ entry, automatic }: { entry?: Schedule["services"][number]; automatic: boolean }) {
  if (!automatic) return <span>When you start one</span>
  if (!entry) return <span>—</span>
  const next = entry.next_run
  const label = !next ? "Only when you ask" : next.startsWith("after") ? next : until(next)
  return (
    <span>
      <span className="text-foreground">{label}</span>
      <span className="block">last {agoIso(entry.last_triage)}</span>
    </span>
  )
}

function policyLabel(service: ServiceRow) {
  if (service.triage_policy === "manual") return "Only when you ask"
  if (service.triage_policy === "on_change") return "When code or advisories change"
  const every = INTERVALS.find((item) => item.minutes === service.triage_interval_minutes)?.label ?? `every ${service.triage_interval_minutes} min`
  return `Scheduled, ${every}`
}

function EditService({ service, onDone }: { service: ServiceRow; onDone: () => void }) {
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [policy, setPolicy] = useState(service.triage_policy)

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setBusy(true)
    try {
      await api.updateService(service.service_id, {
        name: String(form.get("name") || service.name),
        team: String(form.get("team") || ""),
        internet_facing: form.get("internet_facing") === "true",
        criticality: Number(form.get("criticality")),
        data_class: String(form.get("data_class")),
        triage_policy: policy,
        triage_interval_minutes: Number(form.get("interval") || service.triage_interval_minutes),
      })
      onDone()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Saving failed.")
      setBusy(false)
    }
  }

  return (
    <form onSubmit={save} className="grid gap-4 @min-[460px]:grid-cols-2 @min-[760px]:grid-cols-3">
          <label className="flex flex-col gap-1 text-xs @min-[760px]:col-span-1">
            Name
            <input name="name" defaultValue={service.name} className="input text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Team
            <input name="team" defaultValue={service.team} className="input text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Exposure
            <Select name="internet_facing" defaultValue={String(Boolean(service.internet_facing))} className="text-sm">
              <option value="true">Internet-facing</option>
              <option value="false">Internal</option>
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Criticality (0–1)
            <input name="criticality" type="number" min={0} max={1} step={0.1} defaultValue={service.criticality} className="input num text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Data
            <Select name="data_class" defaultValue={service.data_class} className="text-sm">
              {DATA_CLASSES.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </Select>
          </label>
          <label className="flex flex-col gap-1 text-xs @min-[760px]:col-span-2">
            Run triage
            <Select value={policy} onValueChange={(value) => setPolicy(value)} className="text-sm">
              {POLICIES.map((item) => (
                <option key={item.id} value={item.id}>{item.label}</option>
              ))}
            </Select>
          </label>
          {policy === "interval" ? (
            <label className="flex flex-col gap-1 text-xs">
              How often
              <Select name="interval" defaultValue={service.triage_interval_minutes} className="text-sm">
                {INTERVALS.map((item) => (
                  <option key={item.minutes} value={item.minutes}>{item.label}</option>
                ))}
              </Select>
            </label>
          ) : null}
          <div className="flex flex-wrap items-end justify-end gap-2 @min-[460px]:col-span-2 @min-[760px]:col-span-3">
            {error ? <p role="alert" className="mr-auto text-xs text-critical">{error}</p> : null}
            <button type="button" onClick={onDone} className="rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">Cancel</button>
            <button type="submit" disabled={busy} className="btn-gold rounded-full px-5 py-1.5 text-sm font-medium disabled:opacity-60">Save</button>
          </div>
    </form>
  )
}

function AddService({ workspaceId, onDone }: { workspaceId: string; onDone: () => void }) {
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const file = form.get("sbom")
    setBusy(true)
    setError("")
    try {
      let sbom: unknown = undefined
      if (file instanceof File && file.size) {
        try {
          sbom = JSON.parse(await file.text())
        } catch {
          throw new Error("The SBOM is not JSON. Upload a CycloneDX JSON file.")
        }
      }
      await api.addService(workspaceId, {
        name: String(form.get("name") || "").trim(),
        team: String(form.get("team") || "").trim(),
        internet_facing: form.get("internet_facing") === "true",
        criticality: Number(form.get("criticality") || 0.5),
        data_class: String(form.get("data_class") || "internal"),
        sbom,
      })
      onDone()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Adding failed.")
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-4 rounded-2xl border border-hairline bg-surface px-6 py-6 sm:grid-cols-3">
      <label className="flex flex-col gap-1.5 text-sm">
        Name
        <input name="name" required className="input" />
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Team
        <input name="team" className="input" />
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Exposure
        <Select name="internet_facing" defaultValue="false">
          <option value="true">Internet-facing</option>
          <option value="false">Internal</option>
        </Select>
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Criticality (0–1)
        <input name="criticality" type="number" min={0} max={1} step={0.1} defaultValue={0.5} className="input num" />
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Data
        <Select name="data_class" defaultValue="internal">
          {DATA_CLASSES.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </Select>
      </label>
      <SbomPicker />
      {error ? <p role="alert" className="text-sm text-critical sm:col-span-3">{error}</p> : null}
      <div className="flex justify-end sm:col-span-3">
        <button type="submit" disabled={busy} className="btn-gold rounded-full px-6 py-2 text-sm font-medium disabled:opacity-60">{busy ? "Adding…" : "Add service"}</button>
      </div>
    </form>
  )
}

// A styled stand-in for the native file input: the input stays in the form, hidden.
function SbomPicker() {
  const input = useRef<HTMLInputElement>(null)
  const [name, setName] = useState("")

  function clear() {
    if (input.current) input.current.value = ""
    setName("")
  }

  return (
    <div className="flex flex-col gap-1.5 text-sm">
      <span id="sbom-label">SBOM <span className="text-dim">(optional)</span></span>
      <input ref={input} id="sbom" name="sbom" type="file" accept=".json,application/json" className="sr-only" aria-labelledby="sbom-label" onChange={(event) => setName(event.target.files?.[0]?.name ?? "")} />
      {name ? (
        <div className="flex min-h-10 items-center gap-2 rounded-lg border border-border bg-panel px-3">
          <FileJson className="size-4 shrink-0 text-primary" aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate">{name}</span>
          <button type="button" onClick={clear} aria-label="Remove file" className="rounded p-0.5 text-dim hover:bg-raised hover:text-foreground"><X className="size-4" aria-hidden="true" /></button>
        </div>
      ) : (
        <button type="button" onClick={() => input.current?.click()} className="flex min-h-10 items-center gap-2 rounded-lg border border-dashed border-input bg-panel px-3 text-left text-muted-foreground transition-colors hover:border-primary/60 hover:text-foreground">
          <Upload className="size-4 shrink-0" aria-hidden="true" />
          Upload CycloneDX JSON
        </button>
      )}
    </div>
  )
}

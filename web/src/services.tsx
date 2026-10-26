import { useCallback, useEffect, useState, type FormEvent } from "react"
import { Globe, Lock, Pencil, Trash2, Upload } from "lucide-react"
import { api, DATA_CLASSES, type ServiceRow } from "@/api"
import { PageHeader } from "@/components/page-header"
import { ecosystemLabel } from "@/lib/format"
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

  const load = useCallback(() => {
    api.services(workspace.workspace_id).then((body) => setServices(body.services)).catch((exc: Error) => setError(exc.message))
  }, [workspace.workspace_id])

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
        eyebrow={workspace.name}
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
        {services?.length ? (
          <div className="overflow-x-auto rounded-2xl border border-hairline">
            <table className="w-full min-w-[880px] text-sm">
              <thead>
                <tr className="border-b border-hairline text-left text-xs text-muted-foreground">
                  <th className="px-4 py-3 font-medium">Service</th>
                  <th className="px-4 py-3 font-medium">Packages</th>
                  <th className="px-4 py-3 font-medium">Exposure</th>
                  <th className="px-4 py-3 font-medium">Team</th>
                  <th className="num px-4 py-3 text-right font-medium">Criticality</th>
                  <th className="px-4 py-3 font-medium">Data</th>
                  <th className="px-4 py-3 font-medium">Triage</th>
                  <th className="px-4 py-3"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {services.map((service) =>
                  editing === service.service_id ? (
                    <EditRow
                      key={service.service_id}
                      service={service}
                      onDone={() => {
                        setEditing(null)
                        load()
                        refreshInbox()
                      }}
                    />
                  ) : (
                    <tr key={service.service_id} className="border-b border-hairline last:border-0 hover:bg-raised/40">
                      <td className="px-4 py-3">
                        <span className="font-medium">{service.name}</span>
                        <span className="mono block text-xs text-muted-foreground">
                          {service.repo_id ? `${service.repo_id}/${service.path || ""}` : "added by hand"}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        <span className="num text-foreground">{service.components ?? 0}</span>
                        <span className="block text-xs">{ecosystemLabel(service.ecosystems ?? {})}</span>
                      </td>
                      <td className="px-4 py-3">
                        {service.internet_facing ? (
                          <span className="flex items-center gap-1.5"><Globe className="size-4 text-primary" aria-hidden="true" />Internet-facing</span>
                        ) : (
                          <span className="flex items-center gap-1.5 text-muted-foreground"><Lock className="size-4" aria-hidden="true" />Internal</span>
                        )}
                      </td>
                      <td className="px-4 py-3">{service.team || <span className="text-muted-foreground">—</span>}</td>
                      <td className="num px-4 py-3 text-right">{Number(service.criticality).toFixed(1)}</td>
                      <td className="px-4 py-3">{service.data_class}</td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">{policyLabel(service)}</td>
                      <td className="px-4 py-3">
                        <span className="flex justify-end gap-1">
                          <button type="button" aria-label={`Edit ${service.name}`} onClick={() => setEditing(service.service_id)} className="rounded-md p-1.5 text-muted-foreground hover:bg-raised hover:text-foreground">
                            <Pencil className="size-4" aria-hidden="true" />
                          </button>
                          <button type="button" aria-label={`Remove ${service.name}`} onClick={() => remove(service)} className="rounded-md p-1.5 text-muted-foreground hover:bg-raised hover:text-critical">
                            <Trash2 className="size-4" aria-hidden="true" />
                          </button>
                        </span>
                      </td>
                    </tr>
                  ),
                )}
              </tbody>
            </table>
          </div>
        ) : null}
        <p className="text-xs text-muted-foreground">
          What you set here counts as confirmed: Sibyl keeps it even when a later scan of the code suggests otherwise, and asks you instead.
        </p>
      </div>
    </div>
  )
}

function policyLabel(service: ServiceRow) {
  if (service.triage_policy === "manual") return "Only when you ask"
  if (service.triage_policy === "on_change") return "When code or advisories change"
  const every = INTERVALS.find((item) => item.minutes === service.triage_interval_minutes)?.label ?? `every ${service.triage_interval_minutes} min`
  return `Scheduled, ${every}`
}

function EditRow({ service, onDone }: { service: ServiceRow; onDone: () => void }) {
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
    <tr className="border-b border-hairline bg-raised/40">
      <td colSpan={8} className="px-4 py-4">
        <form onSubmit={save} className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
          <label className="flex flex-col gap-1 text-xs lg:col-span-2">
            Name
            <input name="name" defaultValue={service.name} className="input text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Team
            <input name="team" defaultValue={service.team} className="input text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Exposure
            <select name="internet_facing" defaultValue={String(Boolean(service.internet_facing))} className="input text-sm">
              <option value="true">Internet-facing</option>
              <option value="false">Internal</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Criticality (0–1)
            <input name="criticality" type="number" min={0} max={1} step={0.1} defaultValue={service.criticality} className="input num text-sm" />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Data
            <select name="data_class" defaultValue={service.data_class} className="input text-sm">
              {DATA_CLASSES.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs lg:col-span-3">
            Run triage
            <select value={policy} onChange={(event) => setPolicy(event.target.value)} className="input text-sm">
              {POLICIES.map((item) => (
                <option key={item.id} value={item.id}>{item.label}</option>
              ))}
            </select>
          </label>
          {policy === "interval" ? (
            <label className="flex flex-col gap-1 text-xs lg:col-span-1">
              How often
              <select name="interval" defaultValue={service.triage_interval_minutes} className="input text-sm">
                {INTERVALS.map((item) => (
                  <option key={item.minutes} value={item.minutes}>{item.label}</option>
                ))}
              </select>
            </label>
          ) : null}
          <div className="flex items-end justify-end gap-2 lg:col-span-2 lg:col-start-5">
            {error ? <p role="alert" className="mr-auto text-xs text-critical">{error}</p> : null}
            <button type="button" onClick={onDone} className="rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">Cancel</button>
            <button type="submit" disabled={busy} className="btn-gold rounded-full px-5 py-1.5 text-sm font-medium disabled:opacity-60">Save</button>
          </div>
        </form>
      </td>
    </tr>
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
        <select name="internet_facing" defaultValue="false" className="input">
          <option value="true">Internet-facing</option>
          <option value="false">Internal</option>
        </select>
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Criticality (0–1)
        <input name="criticality" type="number" min={0} max={1} step={0.1} defaultValue={0.5} className="input num" />
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        Data
        <select name="data_class" defaultValue="internal" className="input">
          {DATA_CLASSES.map((item) => (
            <option key={item} value={item}>{item}</option>
          ))}
        </select>
      </label>
      <label className="flex flex-col gap-1.5 text-sm">
        <span className="flex items-center gap-2"><Upload className="size-4 text-dim" aria-hidden="true" />CycloneDX SBOM (JSON)</span>
        <input name="sbom" type="file" accept=".json,application/json" className="text-sm" />
      </label>
      {error ? <p role="alert" className="text-sm text-critical sm:col-span-3">{error}</p> : null}
      <div className="flex justify-end sm:col-span-3">
        <button type="submit" disabled={busy} className="btn-gold rounded-full px-6 py-2 text-sm font-medium disabled:opacity-60">{busy ? "Adding…" : "Add service"}</button>
      </div>
    </form>
  )
}

import { useEffect, useMemo, useState, type ReactNode } from "react"
import { Link } from "react-router"
import { ArrowRight, Check, CheckCircle2, GitMerge, Scale, ShieldCheck, UserCheck, X } from "lucide-react"
import { api, type MemorySnapshot } from "@/api"
import { PageHeader } from "@/components/page-header"
import { Loading, PanelError } from "@/states"

const SOURCE_NAME: Record<string, string> = {
  osv: "OSV.dev",
  ghsa: "GitHub Advisories",
  cna: "CVE.org (CNA)",
  "cisa-adp": "CISA ADP",
  nvd: "NVD",
  "nvd-cpe": "NVD CPE match",
  euvd: "ENISA EUVD",
  "llm-extracted": "Read from prose",
}

const FIELD_NAME: Record<string, string> = {
  affected_ranges: "Ranges",
  fixed_version: "Fix",
  aliases: "Aliases",
  severity: "Severity",
  exploited: "Exploited",
  epss: "EPSS",
  withdrawn: "Withdrawn",
}

const FIELDS = Object.keys(FIELD_NAME)

type Resolution = MemorySnapshot["resolutions"][number]

function parseCase(caseId: string) {
  const parts = caseId.split(":")
  const purl = parts.slice(2, -1).join(":")
  const at = purl.lastIndexOf("@")
  const name = purl.slice(purl.indexOf("/") + 1, at > 0 ? at : undefined)
  return { service: parts[1] ?? "", vuln: parts[parts.length - 1] ?? "", pkg: name, version: at > 0 ? purl.slice(at + 1) : "" }
}

export function MemoryScreen() {
  const [memory, setMemory] = useState<MemorySnapshot | null>(null)
  const [error, setError] = useState("")

  function load() {
    setError("")
    api.memory().then(setMemory).catch((exc: Error) => setError(exc.message))
  }
  useEffect(() => {
    api.memory().then(setMemory).catch((exc: Error) => setError(exc.message))
  }, [])

  async function decide(id: string, approve: boolean) {
    try {
      if (approve) await api.approve(id)
      else await api.reject(id)
      load()
      window.dispatchEvent(new Event("sibyl-inbox"))
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "could not update memory")
    }
  }

  // The latest answer per case; an answer saved twice shows once.
  const resolutions = useMemo(() => {
    const latest = new Map<string, Resolution>()
    for (const item of memory?.resolutions ?? []) {
      const was = latest.get(item.case_id)
      if (!was || (item.at ?? "") > (was.at ?? "")) latest.set(item.case_id, item)
    }
    return [...latest.values()].sort((a, b) => (b.at ?? "").localeCompare(a.at ?? ""))
  }, [memory])

  const trust = useMemo(() => {
    const live = (memory?.trust ?? []).filter((row) => !row.superseded)
    const sources = [...new Set(live.map((row) => row.source))]
    const cell = (source: string, field: string) => live.find((row) => row.source === source && row.field === field && row.ecosystem === "*")
    const overrides = live.filter((row) => row.ecosystem !== "*")
    const best = (source: string) => Math.max(0, ...live.filter((row) => row.source === source).map((row) => row.weight))
    sources.sort((a, b) => best(b) - best(a))
    return { sources, cell, overrides, learned: live.filter((row) => row.source_actor !== "seed").length }
  }, [memory])

  return (
    <div>
      <PageHeader title="Memory" meta="What Sibyl has learned from you. It carries into every later run." />
      <main className="mx-auto flex max-w-[1200px] flex-col gap-8 px-6 py-8 pb-24 sm:px-10">
        {error ? <PanelError message={error} onRetry={load} /> : null}
        {memory?.unavailable ? <PanelError message={memory.error || "H-MEM is unavailable. Trust falls back to the default table."} onRetry={load} /> : null}
        {!memory && !error ? <Loading label="Memory" /> : null}
        {memory ? (
          <>
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              <Stat icon={<Scale className="size-4" />} label="Waiting for approval" value={memory.pending.length} tone={memory.pending.length ? "text-primary" : ""} />
              <Stat icon={<UserCheck className="size-4" />} label="Human resolutions" value={resolutions.length} />
              <Stat icon={<GitMerge className="size-4" />} label="Learned mappings" value={memory.mappings.length} />
              <Stat icon={<ShieldCheck className="size-4" />} label="Sources in the trust ledger" value={trust.sources.length} />
            </div>

            <Section title="Waiting for approval" description="Trust changes and new package mappings never apply on their own. They wait here until you approve them.">
              {memory.pending.length === 0 ? (
                <div className="flex items-center gap-3 rounded-xl border border-border bg-surface px-5 py-4">
                  <CheckCircle2 className="size-5 shrink-0 text-success" aria-hidden="true" />
                  <div className="text-sm">
                    <p className="font-medium">Nothing to approve</p>
                    <p className="text-xs leading-5 text-muted-foreground">A proposal appears here when you answer a case with “Propose a source-trust change”, or when Sibyl sees a source disagree with you again and again.</p>
                  </div>
                </div>
              ) : (
                <ul className="flex flex-col gap-3">
                  {memory.pending.map((change) => (
                    <li key={change.id} className="flex flex-wrap items-center gap-4 rounded-xl border border-primary/30 bg-surface px-5 py-4">
                      <div className="min-w-0 flex-1">
                        {change.kind === "trust" ? (
                          <>
                            <p className="text-sm font-medium">Trust in {SOURCE_NAME[change.source] ?? change.source} for {FIELD_NAME[change.field] ?? change.field}{change.ecosystem && change.ecosystem !== "*" ? ` on ${change.ecosystem}` : ""}</p>
                            <p className="num mt-1 flex items-center gap-2 text-sm"><span className="text-muted-foreground">{change.previous}</span><ArrowRight className="size-3.5 text-dim" aria-hidden="true" /><span className={change.weight < change.previous ? "text-high" : "text-success"}>{change.weight}</span></p>
                          </>
                        ) : (
                          <p className="mono text-sm">{change.product} <span className="text-dim">→</span> {change.purl}</p>
                        )}
                        <p className="mt-1 text-xs leading-5 text-muted-foreground">{change.reason}{change.case_id ? <> · <Link to={`/cases/${encodeURIComponent(change.case_id)}`} className="text-primary hover:underline">from {parseCase(change.case_id).vuln}</Link></> : null}</p>
                      </div>
                      <div className="flex gap-2">
                        <button type="button" onClick={() => decide(change.id, false)} className="flex min-h-9 items-center gap-1.5 rounded-lg border border-border px-3 text-sm hover:bg-raised"><X className="size-4" aria-hidden="true" />Reject</button>
                        <button type="button" onClick={() => decide(change.id, true)} className="flex min-h-9 items-center gap-1.5 rounded-lg bg-primary px-3 text-sm font-medium text-primary-foreground hover:bg-primary-strong"><Check className="size-4" aria-hidden="true" />Approve</button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </Section>

            <Section title="Trust ledger" description="How much Sibyl trusts each source, field by field. When sources disagree, the higher-trust one wins; a lower-trust source can never overwrite a higher-trust fact.">
              <div data-demo="memory" className="overflow-x-auto rounded-xl border border-border bg-surface">
                <table className="w-full min-w-[760px] text-sm">
                  <thead>
                    <tr className="border-b border-border text-xs text-muted-foreground">
                      <th className="px-4 py-3 text-left font-medium">Source</th>
                      {FIELDS.map((field) => <th key={field} className="px-2 py-3 text-center font-medium">{FIELD_NAME[field]}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {trust.sources.map((source) => (
                      <tr key={source} className="border-t border-border/60">
                        <td className="px-4 py-2.5">
                          <span className="block font-medium">{SOURCE_NAME[source] ?? source}</span>
                          <span className="mono text-[11px] text-dim">{source}</span>
                        </td>
                        {FIELDS.map((field) => {
                          const row = trust.cell(source, field)
                          return (
                            <td key={field} className="px-1.5 py-2.5 text-center">
                              {row ? <TrustCell weight={row.weight} learned={row.source_actor !== "seed"} /> : <span className="text-dim">—</span>}
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mt-2 text-xs text-muted-foreground">
                {trust.learned ? `${trust.learned} weights changed by your approvals (outlined). ` : "Every weight is still the starting table; approved trust changes show outlined. "}
                {trust.overrides.length ? `${trust.overrides.length} ecosystem-specific overrides.` : ""}
              </p>
            </Section>

            <div className="grid gap-8 lg:grid-cols-2">
              <Section title="Learned mappings" description="Product names in advisories that Sibyl now maps to your packages.">
                {memory.mappings.length === 0 ? (
                  <Quiet>None yet. When an advisory names a product Sibyl can't place, it proposes a mapping for you to approve.</Quiet>
                ) : (
                  <ul className="divide-y divide-border/60 rounded-xl border border-border bg-surface">
                    {memory.mappings.map((item) => (
                      <li key={item.product} className="flex flex-wrap items-center gap-2 px-4 py-3 text-sm">
                        <span>{item.product}</span>
                        <ArrowRight className="size-3.5 text-dim" aria-hidden="true" />
                        <span className="mono text-xs text-primary">{item.purl}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Section>

              <Section title="Human resolutions" description="Your answers to cases. A remembered answer decides the same case in later runs without asking again.">
                {resolutions.length === 0 ? (
                  <Quiet>None yet. Answer a case in <Link to="/queue" className="text-primary hover:underline">Needs you</Link> and it is kept here.</Quiet>
                ) : (
                  <ul className="divide-y divide-border/60 rounded-xl border border-border bg-surface">
                    {resolutions.map((item) => {
                      const parsed = parseCase(item.case_id)
                      return (
                        <li key={item.case_id} className="flex flex-col gap-1 px-4 py-3">
                          <div className="flex flex-wrap items-center gap-2 text-sm">
                            <Decision value={item.decision} />
                            <Link to={`/cases/${encodeURIComponent(item.case_id)}`} className="mono text-xs text-primary hover:underline">{parsed.vuln}</Link>
                            <span className="text-xs">{parsed.pkg}<span className="text-muted-foreground">@{parsed.version}</span></span>
                            <span className="rounded-md bg-raised px-1.5 py-0.5 text-[11px] text-muted-foreground">{parsed.service}</span>
                          </div>
                          {item.note ? <p className="text-xs leading-5 text-muted-foreground">“{item.note}”</p> : null}
                          <p className="text-[11px] text-dim">
                            {item.user || "someone"} · {item.at ? new Date(item.at).toLocaleDateString(undefined, { day: "numeric", month: "short" }) : ""}
                            {item.scope === "this_case" ? " · this case" : ` · ${item.scope.replaceAll("_", " ")}`}
                            {item.expiry ? ` · expires ${item.expiry.slice(0, 10)}` : ""}
                          </p>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </Section>
            </div>
          </>
        ) : null}
      </main>
    </div>
  )
}

function Stat({ icon, label, value, tone = "" }: { icon: ReactNode; label: string; value: number; tone?: string }) {
  return (
    <div className="rounded-xl border border-border bg-surface p-4">
      <span className="flex items-center gap-2 text-xs text-muted-foreground"><span className="text-dim" aria-hidden="true">{icon}</span>{label}</span>
      <span className={`num mt-1 block text-[28px] font-semibold leading-9 ${tone}`}>{value}</span>
    </div>
  )
}

function Section({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-base font-semibold">{title}</h2>
        <p className="mt-0.5 max-w-[720px] text-xs leading-5 text-muted-foreground">{description}</p>
      </div>
      {children}
    </section>
  )
}

function Quiet({ children }: { children: ReactNode }) {
  return <p className="rounded-xl border border-dashed border-border px-4 py-4 text-xs leading-5 text-muted-foreground">{children}</p>
}

function TrustCell({ weight, learned }: { weight: number; learned: boolean }) {
  // Opacity tracks trust so the strong sources read first.
  const alpha = Math.max(0.08, Math.min(0.55, (weight - 0.3) * 0.85))
  return (
    <span title={`${weight}${learned ? " (changed by an approval)" : ""}`} className={`num inline-flex min-w-12 justify-center rounded-md px-2 py-1 text-xs ${learned ? "ring-1 ring-primary" : ""}`} style={{ background: `color-mix(in srgb, var(--success) ${Math.round(alpha * 100)}%, transparent)` }}>
      {weight.toFixed(2)}
    </span>
  )
}

function Decision({ value }: { value: string }) {
  const style = value === "affected" ? "bg-high/15 text-high" : value === "not_affected" ? "bg-success/15 text-success" : "bg-primary/15 text-primary"
  return <span className={`rounded-md px-2 py-0.5 text-xs ${style}`}>{value.replaceAll("_", " ")}</span>
}

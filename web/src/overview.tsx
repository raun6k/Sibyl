import { useEffect, useMemo, useState } from "react"
import { Link } from "react-router"
import { AlertTriangle, ArrowRight, CheckCircle2, Globe, Lock, MessageSquare, Sparkles, XCircle } from "lucide-react"
import { api, type Report, type ReportCase, type RunState, type ServiceCard } from "@/api"
import { PageHeader } from "@/components/page-header"
import { ago, band, ecosystemLabel, isActive, BAND_GLYPH, BAND_LABEL, clock, duration, patchNow, serviceOf, SOURCE_LABEL, type Band } from "@/lib/format"
import { useWorkspace } from "@/workspace"

const BANDS: Band[] = ["critical", "high", "medium", "low"]

type ServiceRisk = {
  service: ServiceCard
  bands: Record<Band, number>
  packages: number
  exploited: number
  patchNow: number
  needsYou: number
  top: number
}

export function Overview() {
  const { runs, sources, openRunDialog, openAsk, workspace } = useWorkspace()
  const [services, setServices] = useState<ServiceCard[] | null>(null)
  const [packages, setPackages] = useState<number | null>(null)
  const [servicesError, setServicesError] = useState(false)
  const [report, setReport] = useState<Report | null>(null)

  const finished = useMemo(() => (runs ?? []).filter((run) => run.status === "DONE"), [runs])
  const lastDone = finished.length ? finished[finished.length - 1] : null
  const lastId = lastDone?.run_id
  const active = (runs ?? []).find(isActive) ?? null

  useEffect(() => {
    api
      .inventory()
      .then((body) => {
        setServices(body.services)
        setPackages(body.components)
      })
      .catch(() => setServicesError(true))
  }, [lastId])

  useEffect(() => {
    if (!lastId) return
    api.report(lastId).then(setReport).catch(() => setReport(null))
  }, [lastId])

  const risks = useMemo(() => (services ? rankServices(services, report) : null), [services, report])
  const ranked = report?.ranked ?? []
  const queue = report?.needs_human ?? []
  const urgent = ranked.filter(patchNow)
  const toUpgrade = new Set(ranked.map((card) => `${serviceOf(card.case_id)}|${card.package}@${card.version}`)).size
  const exploited = ranked.filter((card) => card.exploited).length
  const degraded = lastDone?.degraded_sources ?? []

  const meta = [
    services ? `${services.length} services` : null,
    packages != null ? `${packages} packages` : null,
    lastDone ? `last run ${ago(lastDone.started)}` : active ? "first triage running" : "no runs yet",
  ]
    .filter(Boolean)
    .join(" · ")

  return (
    <div>
      <PageHeader
        eyebrow={workspace.name}
        title="Overview"
        meta={meta}
        actions={
          <>
            <button type="button" onClick={openAsk} className="flex items-center gap-2 rounded-full border border-hairline px-4 py-2 text-sm hover:bg-raised">
              <MessageSquare className="size-4 text-primary" aria-hidden="true" />
              Ask Sibyl
            </button>
            {active ? (
              <Link to={`/runs/${active.run_id}`} className="btn-gold rounded-full px-5 py-2 text-sm font-medium no-underline">
                Watch the run
              </Link>
            ) : (
              <button type="button" onClick={openRunDialog} className="btn-gold rounded-full px-5 py-2 text-sm font-medium">
                Run triage
              </button>
            )}
          </>
        }
      />

      <div className="mx-auto flex max-w-[1200px] flex-col gap-10 px-6 py-8 sm:px-10">
        {runs == null ? (
          <BriefingSkeleton />
        ) : lastDone && report ? (
          <Briefing run={lastDone} report={report} urgent={urgent} toUpgrade={toUpgrade} degraded={degraded} />
        ) : lastDone ? (
          <BriefingSkeleton />
        ) : services && services.length === 0 && !workspace.is_demo ? (
          <NoServices />
        ) : (
          <Welcome onRun={openRunDialog} running={active?.run_id ?? null} />
        )}

        {report ? (
          <section aria-label="Summary" className="grid grid-cols-2 overflow-hidden rounded-2xl border border-hairline lg:grid-cols-4">
            <Stat to="/patches" label="Patch now" value={urgent.length} note={exploited ? `${exploited} exploited in the wild` : "nothing exploited"} tone={urgent.length ? "critical" : undefined} />
            <Stat to="/patches" label="Packages to upgrade" value={toUpgrade} note={`${ranked.length} vulnerabilities in all`} />
            <Stat to="/queue" label="Needs you" value={queue.length} note={queue.length ? "sources disagree" : "nothing waiting"} tone={queue.length ? "primary" : undefined} />
            <Stat
              to={lastDone ? `/runs/${lastDone.run_id}` : "/"}
              label="Last run"
              value={duration(lastDone?.elapsed_seconds)}
              note={degraded.length ? `${degraded.map((item) => SOURCE_LABEL[item] ?? item).join(", ")} off` : `${(sources ?? []).length || 7} sources answered`}
            />
          </section>
        ) : null}

        <div className="grid grid-cols-1 gap-10 xl:grid-cols-12">
          <section aria-labelledby="services-title" className="flex flex-col xl:col-span-8">
            <div className="mb-3 flex items-baseline justify-between gap-4">
              <h2 id="services-title" className="display text-[26px] leading-8">Services</h2>
              <span className="text-xs text-muted-foreground">{report ? "Riskiest first" : "Run a triage to rank them"}</span>
            </div>
            {servicesError ? (
              <p role="alert" className="rounded-xl border border-border px-4 py-6 text-sm text-muted-foreground">
                The services didn't load. Zetaris may be slow or down.{" "}
                <button type="button" className="text-primary" onClick={() => window.location.reload()}>Try again</button>
              </p>
            ) : risks == null ? (
              <ServicesSkeleton />
            ) : (
              <ul className="flex flex-col border-t border-hairline">
                {risks.map((risk) => (
                  <ServiceRow key={risk.service.service_id} risk={risk} triaged={Boolean(report)} />
                ))}
              </ul>
            )}
          </section>

          <section aria-labelledby="runs-title" className="flex flex-col xl:col-span-4">
            <div className="mb-3 flex items-baseline justify-between gap-4">
              <h2 id="runs-title" className="display text-[26px] leading-8">Past runs</h2>
              {lastDone ? <Link to={`/runs/${lastDone.run_id}`} className="text-xs text-primary">Latest trace →</Link> : null}
            </div>
            <RunLedger runs={runs} />
          </section>
        </div>
      </div>
    </div>
  )
}

function rankServices(services: ServiceCard[], report: Report | null): ServiceRisk[] {
  const risks = services.map((service) => {
    const cards = (report?.ranked ?? []).filter((card) => serviceOf(card.case_id) === service.service_id)
    const bands: Record<Band, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const card of cards) bands[band(card.score)] += 1
    return {
      service,
      bands,
      packages: new Set(cards.map((card) => `${card.package}@${card.version}`)).size,
      exploited: cards.filter((card) => card.exploited).length,
      patchNow: cards.filter(patchNow).length,
      needsYou: (report?.needs_human ?? []).filter((card) => serviceOf(card.case_id) === service.service_id).length,
      top: Math.max(0, ...cards.map((card) => card.score)),
    }
  })
  return risks.sort(
    (a, b) =>
      b.exploited - a.exploited ||
      b.patchNow - a.patchNow ||
      b.top - a.top ||
      Number(b.service.criticality) - Number(a.service.criticality),
  )
}

function Briefing({ run, report, urgent, toUpgrade, degraded }: { run: RunState; report: Report; urgent: ReportCase[]; toUpgrade: number; degraded: string[] }) {
  const top = report.ranked[0]
  const queue = report.needs_human.length
  return (
    <section aria-labelledby="briefing-title" className="relative overflow-hidden rounded-2xl border border-hairline bg-surface px-7 py-7 sm:px-9">
      <div className="mb-4 flex flex-wrap items-center gap-x-3 gap-y-1">
        <Sparkles className="size-4 text-primary" aria-hidden="true" />
        <h2 id="briefing-title" className="eyebrow text-primary">Sibyl's briefing</h2>
        <span className="text-xs text-muted-foreground">{clock(run.started)} · run of {report.ranked.length + report.closed.length + queue} cases</span>
      </div>
      <p className="display max-w-[880px] text-[26px] leading-[36px] sm:text-[28px] sm:leading-[38px]">
        {top ? (
          <>
            Patch <span className="mono text-[20px] text-primary">{top.package} {top.version}</span> in {serviceOf(top.case_id)} first:{" "}
            {top.exploited ? "it's on CISA's list of vulnerabilities exploited in the wild." : `it has the highest priority score, ${Math.round(top.score)}.`}{" "}
            {urgent.length > 1 ? `${urgent.length - 1} more need patching now, and ` : ""}
            {toUpgrade} package {toUpgrade === 1 ? "version has" : "versions have"} a known vulnerability across your services.
          </>
        ) : (
          <>None of your packages is affected by the advisories in this window.</>
        )}{" "}
        {queue ? `I couldn't settle ${queue} ${queue === 1 ? "case" : "cases"} where the sources disagree, and need your call.` : "Every case was settled from the sources."}
        {degraded.length ? ` ${degraded.map((item) => SOURCE_LABEL[item] ?? item).join(", ")} ${degraded.length === 1 ? "was" : "were"} off, so some answers are less certain.` : ""}
      </p>
      <div className="mt-6 flex flex-wrap gap-3">
        <Link to="/patches" className="btn-gold flex items-center gap-2 rounded-full px-5 py-2.5 text-sm font-medium no-underline">
          Review the patch list
          <ArrowRight className="size-4" aria-hidden="true" />
        </Link>
        {queue ? (
          <Link to="/queue" className="rounded-full border border-hairline px-5 py-2.5 text-sm text-foreground no-underline hover:bg-raised">
            Answer {queue} {queue === 1 ? "question" : "questions"}
          </Link>
        ) : null}
      </div>
    </section>
  )
}

function Welcome({ onRun, running }: { onRun: () => void; running: string | null }) {
  const steps = [
    ["Run a triage", "Sibyl checks every package your services use against seven public vulnerability sources."],
    ["Review the patch list", "Each affected package is ranked, with the source behind every fact."],
    ["Answer what it can't settle", "When sources disagree, Sibyl asks you instead of guessing."],
    ["It remembers", "Your answers and trust changes shape the next run."],
  ]
  return (
    <section aria-labelledby="welcome-title" className="rounded-2xl border border-hairline bg-surface px-7 py-8 sm:px-9">
      <span className="eyebrow text-primary">Welcome</span>
      <h2 id="welcome-title" className="display mt-2 text-[30px] leading-9">Find out which new vulnerabilities actually affect your services.</h2>
      <ol className="mt-6 grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {steps.map(([title, body], i) => (
          <li key={title} className="flex flex-col gap-1.5">
            <span className="display text-[22px] text-primary">{["I", "II", "III", "IV"][i]}</span>
            <span className="font-medium">{title}</span>
            <span className="text-sm text-muted-foreground">{body}</span>
          </li>
        ))}
      </ol>
      {running ? (
        <Link to={`/runs/${running}`} className="btn-gold mt-7 inline-flex items-center gap-2 rounded-full px-6 py-2.5 text-sm font-medium no-underline">
          Your first triage is running. Watch it
          <ArrowRight className="size-4" aria-hidden="true" />
        </Link>
      ) : (
        <button type="button" onClick={onRun} className="btn-gold mt-7 rounded-full px-6 py-2.5 text-sm font-medium">
          Run your first triage
        </button>
      )}
    </section>
  )
}

function NoServices() {
  return (
    <section aria-labelledby="empty-title" className="rounded-2xl border border-hairline bg-surface px-7 py-8 sm:px-9">
      <span className="eyebrow text-primary">No services yet</span>
      <h2 id="empty-title" className="display mt-2 text-[30px] leading-9">Connect a repository and Sibyl finds your services.</h2>
      <p className="mt-3 max-w-[640px] text-sm text-muted-foreground">
        It reads the manifests and lockfiles, builds an SBOM for each service, and asks you to confirm what it works out about each one.
      </p>
      <Link to="/repositories" className="btn-gold mt-6 inline-flex items-center gap-2 rounded-full px-6 py-2.5 text-sm font-medium no-underline">
        Connect a repository
        <ArrowRight className="size-4" aria-hidden="true" />
      </Link>
    </section>
  )
}

function Stat({ to, label, value, note, tone }: { to: string; label: string; value: number | string; note: string; tone?: "critical" | "primary" }) {
  return (
    <Link to={to} className="group flex flex-col gap-1 border-hairline px-6 py-5 text-foreground no-underline transition-colors duration-75 hover:bg-raised/50 [&:not(:last-child)]:border-r max-lg:[&:nth-child(2)]:border-r-0 max-lg:[&:nth-child(-n+2)]:border-b">
      <span className="eyebrow">{label}</span>
      <span className={`display num text-[40px] leading-[44px] ${tone === "critical" ? "text-critical" : tone === "primary" ? "text-primary" : ""}`}>{value}</span>
      <span className="text-xs text-muted-foreground">{note}</span>
    </Link>
  )
}

function ServiceRow({ risk, triaged }: { risk: ServiceRisk; triaged: boolean }) {
  const { service } = risk
  const facing = service.internet_facing === "true" || service.internet_facing === "t"
  const total = BANDS.reduce((sum, item) => sum + risk.bands[item], 0)
  const ecosystem = ecosystemLabel(service.ecosystems ?? { pypi: service.pypi, npm: service.npm })
  return (
    <li className="border-b border-hairline">
      <Link to={`/patches?service=${service.service_id}`} className="grid grid-cols-1 items-center gap-x-6 gap-y-3 px-2 py-5 text-foreground no-underline transition-colors duration-75 hover:bg-raised/40 sm:grid-cols-[minmax(0,1fr)_220px_auto]">
        <div className="flex min-w-0 flex-col gap-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="text-[16px] font-medium">{service.name}</span>
            {risk.exploited ? <span className="tint-critical rounded-full px-2 text-xs leading-5 text-critical">◆ {risk.exploited} exploited</span> : null}
            {risk.needsYou ? <span className="tint-primary rounded-full px-2 text-xs leading-5 text-primary">? {risk.needsYou} need{risk.needsYou === 1 ? "s" : ""} you</span> : null}
          </span>
          <span className="flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
            <span>{service.team}</span>
            <span aria-hidden="true">·</span>
            <span>{service.data_class} data</span>
            <span aria-hidden="true">·</span>
            <span className="flex items-center gap-1">
              {facing ? <Globe className="size-3.5" aria-hidden="true" /> : <Lock className="size-3.5" aria-hidden="true" />}
              {facing ? "internet-facing" : "internal"}
            </span>
            <span aria-hidden="true">·</span>
            <span>{ecosystem || "no packages"}</span>
          </span>
        </div>

        {triaged ? (
          <div className="flex flex-col gap-1.5" aria-label={BANDS.map((item) => `${risk.bands[item]} ${BAND_LABEL[item]}`).join(", ")}>
            <span className="flex h-1.5 overflow-hidden rounded-full bg-raised">
              {total
                ? BANDS.map((item) =>
                    risk.bands[item] ? <span key={item} className="h-full" style={{ width: `${(risk.bands[item] / total) * 100}%`, background: `var(--${item})` }} /> : null,
                  )
                : null}
            </span>
            <span className="flex gap-3 text-xs text-muted-foreground">
              {BANDS.map((item) => (
                <span key={item} className={risk.bands[item] ? "" : "text-dim"}>
                  <span style={{ color: risk.bands[item] ? `var(--${item})` : undefined }}>{BAND_GLYPH[item]}</span> <span className="num">{risk.bands[item]}</span>
                </span>
              ))}
            </span>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">Not triaged yet</span>
        )}

        {triaged ? (
          <span className="flex items-baseline gap-1.5 justify-self-start sm:justify-self-end">
            <span className="display num text-[28px] leading-8">{risk.packages}</span>
            <span className="text-xs text-muted-foreground">to fix</span>
          </span>
        ) : null}
      </Link>
    </li>
  )
}

function RunLedger({ runs }: { runs: RunState[] | null }) {
  if (runs == null) return <LedgerSkeleton />
  if (runs.length === 0) {
    return <p className="border-t border-hairline py-5 text-sm text-muted-foreground">No runs yet. Your first triage will appear here.</p>
  }
  const numbered = runs.map((run, i) => ({ run, number: i + 1, previous: runs.slice(0, i).filter((item) => item.status === "DONE").pop() }))
  const recent = numbered.slice(-3).reverse()
  return (
    <ul className="flex flex-col border-t border-hairline">
      {recent.map(({ run, number, previous }) => {
        const done = run.status === "DONE"
        const failed = run.status === "FAILED"
        const degraded = run.degraded_sources.length > 0
        return (
          <li key={run.run_id} className="border-b border-hairline">
            <Link to={`/runs/${run.run_id}`} className="grid grid-cols-[20px_minmax(0,1fr)_auto] items-start gap-3 px-1 py-4 text-foreground no-underline transition-colors duration-75 hover:bg-raised/40">
              <span className="pt-1">
                {failed ? (
                  <XCircle className="size-4 text-critical" aria-label="Failed" />
                ) : !done ? (
                  <span className="sib-pulse block size-2.5 translate-y-1 rounded-full bg-primary" aria-label="Running" />
                ) : degraded ? (
                  <AlertTriangle className="size-4 text-primary" aria-label="Degraded" />
                ) : (
                  <CheckCircle2 className="size-4 text-success" aria-label="Done" />
                )}
              </span>
              <span className="flex min-w-0 flex-col gap-0.5">
                <span className="display num text-[20px] leading-6">No. {number}</span>
                <span className="text-xs text-muted-foreground">
                  {ago(run.started)}
                  {degraded ? ` · ${run.degraded_sources.map((item) => SOURCE_LABEL[item] ?? item).join(", ")} off` : ""}
                  {failed ? " · failed" : ""}
                </span>
                {done ? (
                  <span className="mt-1 flex flex-wrap gap-x-3 text-xs">
                    <span>
                      <span className="num">{run.counts.ranked}</span> affected <Delta now={run.counts.ranked} before={previous?.counts.ranked} worseUp />
                    </span>
                    <span>
                      <span className="num">{run.counts.needs_human}</span> need you <Delta now={run.counts.needs_human} before={previous?.counts.needs_human} worseUp />
                    </span>
                  </span>
                ) : null}
              </span>
              <span className="mono num pt-1 text-xs text-muted-foreground">{done || failed ? duration(run.elapsed_seconds) : "running"}</span>
            </Link>
          </li>
        )
      })}
    </ul>
  )
}

function Delta({ now, before, worseUp }: { now: number; before?: number; worseUp?: boolean }) {
  if (before == null || before === now) return null
  const up = now > before
  const bad = worseUp ? up : !up
  return <span className={`num ${bad ? "text-critical" : "text-success"}`}>{up ? "+" : "−"}{Math.abs(now - before)}</span>
}

function BriefingSkeleton() {
  return (
    <section aria-busy="true" aria-label="Loading the briefing" className="rounded-2xl border border-hairline bg-surface px-7 py-7 sm:px-9">
      <span className="eyebrow text-primary">Sibyl's briefing</span>
      <div className="mt-5 flex flex-col gap-3">
        <span className="sib-pulse block h-6 w-11/12 rounded bg-raised" />
        <span className="sib-pulse block h-6 w-3/4 rounded bg-raised" />
      </div>
    </section>
  )
}

function ServicesSkeleton() {
  return (
    <ul aria-busy="true" aria-label="Loading services" className="flex flex-col border-t border-hairline">
      {[0, 1, 2, 3].map((i) => (
        <li key={i} className="flex items-center justify-between gap-6 border-b border-hairline px-2 py-6">
          <span className="flex flex-col gap-2">
            <span className="sib-pulse block h-4 w-40 rounded bg-raised" />
            <span className="sib-pulse block h-3 w-64 rounded bg-raised" />
          </span>
          <span className="sib-pulse block h-6 w-12 rounded bg-raised" />
        </li>
      ))}
    </ul>
  )
}

function LedgerSkeleton() {
  return (
    <ul aria-busy="true" aria-label="Loading runs" className="flex flex-col border-t border-hairline">
      {[0, 1].map((i) => (
        <li key={i} className="border-b border-hairline px-1 py-5">
          <span className="sib-pulse block h-4 w-24 rounded bg-raised" />
        </li>
      ))}
    </ul>
  )
}


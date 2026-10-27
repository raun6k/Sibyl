import { useEffect, useRef, useState, type FormEvent } from "react"
import { Link } from "react-router"
import { Check, ChevronDown, ExternalLink, Loader2, ShieldQuestion } from "lucide-react"
import { api, type ReportCase } from "@/api"
import { PageHeader } from "@/components/page-header"
import { Select } from "@/components/ui/select"
import { Empty, Loading, PanelError } from "@/states"

const DECISIONS = [
  { id: "affected", label: "Affected", explanation: "This package version is affected and needs remediation." },
  { id: "not_affected", label: "Not affected", explanation: "The evidence shows this package version is not affected." },
  { id: "accept_risk", label: "Accept risk", explanation: "Record an accepted risk. Risk acceptance expires after 90 days by default." },
]

export function Queue() {
  const [items, setItems] = useState<ReportCase[] | null>(null)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState<{ text: string; pending: boolean } | null>(null)
  const [openId, setOpenId] = useState<string | null>(null)
  const list = useRef<HTMLDivElement>(null)

  function load() {
    setError("")
    api.queue().then((body) => setItems(body.needs_human)).catch((exc: Error) => setError(exc.message))
  }
  useEffect(() => {
    let active = true
    api.queue().then((body) => { if (active) setItems(body.needs_human) }).catch((exc: Error) => { if (active) setError(exc.message) })
    return () => { active = false }
  }, [])

  function saved(item: ReportCase, pending: boolean) {
    if (!pending) setItems((current) => current?.filter((card) => card.case_id !== item.case_id) ?? null)
    setOpenId(null)
    setNotice({ text: pending ? `Trust change proposed for ${item.vuln_id}. The case still needs a resolution.` : `Resolution saved for ${item.package} · ${item.vuln_id}.`, pending })
    window.dispatchEvent(new Event("sibyl-queue"))
    window.dispatchEvent(new Event("sibyl-inbox"))
    requestAnimationFrame(() => {
      const target = list.current?.querySelector<HTMLButtonElement>("[data-review-toggle]")
      if (target) target.focus({ preventScroll: true })
      list.current?.scrollIntoView({ behavior: "instant", block: "start" })
    })
  }

  return (
    <div>
      <PageHeader title="Needs you" meta={items ? `${items.length} ${items.length === 1 ? "case needs" : "cases need"} your decision` : "Loading cases…"} />
      <main ref={list} tabIndex={-1} className="mx-auto flex max-w-[1200px] scroll-mt-32 flex-col gap-4 px-6 py-8 pb-24 sm:px-10">
        {notice ? <div role="status" className="flex flex-wrap items-center gap-2 rounded-xl bg-success/10 px-4 py-3 text-xs leading-5 text-success"><Check className="size-4 shrink-0" aria-hidden="true" />{notice.text}{notice.pending ? <Link to="/memory" className="font-medium underline underline-offset-4">Review in Memory</Link> : null}</div> : null}
        {error ? <PanelError message={error} onRetry={load} /> : null}
        {items == null && !error ? <Loading label="Cases needing review" /> : null}
        {items && items.length === 0 ? <div data-demo="review"><Empty title="No cases need your decision" action="Open patch list" href="/patches" /></div> : null}
        {items?.map((item) => <ReviewCard key={item.case_id} item={item} open={openId === item.case_id} onToggle={() => setOpenId((current) => current === item.case_id ? null : item.case_id)} onSaved={(pending) => saved(item, pending)} />)}
      </main>
    </div>
  )
}

function ReviewCard({ item, open, onToggle, onSaved }: { item: ReportCase; open: boolean; onToggle: () => void; onSaved: (pending: boolean) => void }) {
  const [decision, setDecision] = useState("")
  const [note, setNote] = useState("")
  const [remember, setRemember] = useState(true)
  const [scope, setScope] = useState("this_case")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const inFlight = useRef(false)
  const contentId = `review-${encodeURIComponent(item.case_id)}`

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!decision || inFlight.current) return
    inFlight.current = true
    setBusy(true)
    setError("")
    try {
      const result = await api.resolve(item.case_id, { decision, note, user: "you", remember, scope: remember ? scope : "this_case" })
      if (result.blocked || (!result.resolution && !result.pending)) throw new Error(result.blocked || "The resolution was not saved. Please try again.")
      onSaved(Boolean(result.pending))
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "The resolution could not be saved. Your choices are still here.")
    } finally {
      inFlight.current = false
      setBusy(false)
    }
  }

  return (
    <article data-demo="review" className="min-w-0 rounded-2xl border border-border bg-surface [overflow-wrap:anywhere]">
      <button type="button" data-review-toggle aria-expanded={open} aria-controls={open ? contentId : undefined} onClick={onToggle} className="flex w-full min-w-0 items-start gap-3 rounded-2xl px-5 py-4 text-left hover:bg-raised/40">
        <ShieldQuestion className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden="true" />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-3 gap-y-1"><span className="text-sm font-medium">{item.package}<span className="text-muted-foreground">@{item.version}</span></span><span className="mono text-xs text-primary">{item.vuln_id}</span></span>
          <span className="mt-1.5 block text-xs leading-5 text-muted-foreground">{item.question?.includes("?") ? item.question.slice(0, item.question.indexOf("?") + 1) : item.question || `Is this package version affected by ${item.vuln_id}?`}</span>
        </span>
        <ChevronDown className={`mt-0.5 size-4 shrink-0 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>
      <div id={contentId} hidden={!open} className="@container border-t border-border p-5">
        <div className="grid gap-6 @min-[740px]:grid-cols-[minmax(0,1fr)_340px]">
          <section className="min-w-0" aria-label={`Evidence for ${item.vuln_id}`}>
            <h3 className="text-sm font-medium">Source evidence</h3>
            <p className="mt-1 text-xs leading-5 text-muted-foreground">Review the source positions before choosing a resolution.</p>
            {item.question ? <details className="mt-3 text-xs leading-5 text-muted-foreground"><summary className="w-fit cursor-pointer">Review context</summary><p className="mt-2">{item.question}</p></details> : null}
            <ul className="mt-4 max-h-96 divide-y divide-border overflow-y-auto pr-2 [scrollbar-color:var(--input)_transparent] [scrollbar-width:thin]">
              {!item.positions.length ? <li className="py-2 text-xs text-muted-foreground">No source position was recorded.</li> : null}
              {item.positions.map((position, index) => <li key={`${position.source}-${index}`} className="py-3 first:pt-0">
                <div className="flex flex-wrap items-center justify-between gap-2 text-xs"><span className="font-medium">{position.source}</span><span className="rounded-md bg-raised px-2 py-1 capitalize">{position.verdict.replaceAll("_", " ")}</span></div>
                {position.status && position.status !== "active" ? <p className="mt-2 text-xs text-muted-foreground">Status: {position.status}</p> : null}
                {position.bound ? <p className="mt-2 text-xs text-muted-foreground">Affected range: <span className="mono text-foreground">{position.bound}</span></p> : null}
                {position.quote ? <blockquote className="mt-2 text-xs leading-5 text-muted-foreground">{position.quote}</blockquote> : null}
                {position.record_id ? <details className="mt-2 text-[11px] text-muted-foreground"><summary className="w-fit cursor-pointer">Source record</summary><p className="mono mt-2">{position.record_id}</p></details> : null}
              </li>)}
            </ul>
            <Link to={`/cases/${encodeURIComponent(item.case_id)}`} className="mt-3 inline-flex min-h-9 items-center gap-1.5 text-xs text-primary hover:underline">Open full case<ExternalLink className="size-3.5" aria-hidden="true" /></Link>
          </section>
          <form onSubmit={save} className="min-w-0 @min-[740px]:border-l @min-[740px]:border-border @min-[740px]:pl-6">
            <fieldset disabled={busy} className="min-w-0 border-0 p-0">
              <legend className="mb-3 text-sm font-medium">Your decision</legend>
              <div className="grid grid-cols-3 gap-1.5">
                {DECISIONS.map((choice) => <label key={choice.id} className="min-w-0 cursor-pointer">
                  <input className="peer sr-only" type="radio" name={`decision-${item.case_id}`} value={choice.id} checked={decision === choice.id} onChange={() => setDecision(choice.id)} />
                  <span className="flex min-h-11 items-center justify-center rounded-lg border border-border px-1 py-2 text-center text-xs text-muted-foreground peer-checked:border-primary peer-checked:bg-primary/15 peer-checked:text-primary peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ring">{choice.label}</span>
                </label>)}
              </div>
              <p className="mt-2 min-h-5 text-xs leading-5 text-muted-foreground">{DECISIONS.find((choice) => choice.id === decision)?.explanation || "Choose the outcome supported by the evidence."}</p>
              <label className="mt-4 flex flex-col gap-2 text-xs font-medium">Resolution note <span className="sr-only">for {item.vuln_id}</span><textarea value={note} onChange={(event) => setNote(event.target.value)} rows={2} placeholder="Explain your reasoning or add context…" className="input resize-y text-sm font-normal leading-5" /></label>
              <div className="mt-4 border-t border-border pt-4">
                <label className="flex cursor-pointer items-start gap-2.5 text-xs"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} className="mt-0.5 size-4 shrink-0 accent-primary" /><span><span className="block font-medium">Remember for future runs</span><span className="mt-1 block leading-5 text-muted-foreground">Let this decision inform later triages.</span></span></label>
                {remember ? <label className="mt-3 flex flex-col gap-2 text-xs">Apply to<Select value={scope} onValueChange={setScope} className="text-xs" aria-label={`Resolution scope for ${item.vuln_id}`}><option value="this_case">This case only</option><option value="adjust_trust">Propose a source-trust change</option></Select></label> : null}
                {remember && scope === "adjust_trust" ? <p className="mt-2 text-xs leading-5 text-muted-foreground">Trust changes need approval in Memory. This proposes a change; it does not resolve the case yet.</p> : null}
              </div>
            </fieldset>
            {error ? <p role="alert" className="mt-4 text-xs leading-5 text-critical">{error}</p> : null}
            <button type="submit" disabled={busy || !decision} className="mt-4 flex min-h-10 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary-strong disabled:cursor-not-allowed disabled:opacity-50">{busy ? <Loader2 className="size-4 animate-spin" aria-hidden="true" /> : <Check className="size-4" aria-hidden="true" />}{busy ? "Saving…" : remember && scope === "adjust_trust" ? "Submit trust change" : "Save resolution"}</button>
          </form>
        </div>
      </div>
    </article>
  )
}

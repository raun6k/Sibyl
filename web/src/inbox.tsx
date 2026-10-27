import { Select } from "@/components/ui/select"
import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import { Brain, Check, ChevronRight, Clock3, FileCode2, Pencil, ShieldQuestion, Trash2 } from "lucide-react"
import { api, DATA_CLASSES, type InboxBody, type Question } from "@/api"
import { PageHeader } from "@/components/page-header"
import { ago } from "@/lib/format"
import { useWorkspace } from "@/workspace"

const KIND = {
  service_fact: { label: "Confirm a fact", confirm: "Confirm", dismiss: "Not now" },
  fact_changed: { label: "Code changed", confirm: "Use the new value", dismiss: "Keep mine" },
  service_found: { label: "New service", confirm: "Keep it", dismiss: "Remove it" },
  service_gone: { label: "Service gone", confirm: "Remove it", dismiss: "Keep it" },
  data_quality: { label: "Data quality · Zetaris", confirm: "Got it", dismiss: "" },
} as Record<string, { label: string; confirm: string; dismiss: string }>

const CARD = "flex min-w-0 flex-col rounded-2xl border border-border bg-surface p-5 [overflow-wrap:anywhere]"
const GRID = "grid grid-cols-1 items-stretch gap-4 @min-[580px]:grid-cols-2 @min-[900px]:grid-cols-3"
const CONFIRM = "inline-flex min-h-9 min-w-0 flex-1 basis-0 items-center justify-center gap-1 rounded-lg bg-success/15 px-1.5 py-2 text-xs font-medium text-success hover:bg-success/25 disabled:opacity-50"
const CHANGE = "inline-flex min-h-9 min-w-0 flex-1 basis-0 items-center justify-center gap-1 rounded-lg bg-primary/15 px-1.5 py-2 text-xs font-medium text-primary hover:bg-primary/25 disabled:opacity-50"
const DEFER = "inline-flex min-h-9 min-w-0 flex-1 basis-0 items-center justify-center gap-1 rounded-lg bg-raised px-1.5 py-2 text-xs font-medium text-muted-foreground hover:text-foreground disabled:opacity-50"
const REMOVE = "inline-flex min-h-9 min-w-0 flex-1 basis-0 items-center justify-center gap-1 rounded-lg bg-critical/15 px-1.5 py-2 text-xs font-medium text-critical hover:bg-critical/25 disabled:opacity-50"

const ORDER = ["service_found", "service_gone", "fact_changed", "service_fact", "data_quality"]

// One inbox for everything the agents need from a person (D23: in-app only).
export function InboxScreen() {
  const { workspace, refreshInbox } = useWorkspace()
  const [body, setBody] = useState<InboxBody | null>(null)
  const [error, setError] = useState("")

  const load = useCallback(() => {
    api.inbox(workspace.workspace_id).then(setBody).catch((exc: Error) => setError(exc.message))
  }, [workspace.workspace_id])

  useEffect(load, [load])

  useEffect(() => {
    window.addEventListener("sibyl-inbox", load)
    return () => window.removeEventListener("sibyl-inbox", load)
  }, [load])

  const questions = [...(body?.questions ?? [])].sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind))
  const cases = body?.needs_human ?? []
  const approvals = body?.approvals ?? []
  const total = body?.counts.total ?? 0
  const done = () => {
    load()
    refreshInbox()
  }

  return (
    <div>
      <PageHeader
        title="Inbox"
        meta={
          body
            ? total
              ? `${body.counts.questions} questions · ${body.counts.needs_human} cases · ${body.counts.approvals} memory approvals`
              : "Nothing waiting on you"
            : "Loading…"
        }
      />
      <div className="@container mx-auto flex max-w-[1440px] flex-col gap-8 px-6 py-8 pb-24 sm:px-10">
        {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
        {body && total === 0 ? (
          <p className="text-sm text-muted-foreground">
            Everything the agents need from you lands here: facts Sibyl worked out from the code, new or removed services,
            data-quality checks, vulnerability cases it could not settle, and memory changes waiting for your approval.
          </p>
        ) : null}

        {approvals.length ? (
          <section aria-labelledby="inbox-approvals">
            <h2 id="inbox-approvals" className="mb-4 text-sm font-medium text-muted-foreground">Memory changes to approve</h2>
            <div className={GRID}>{approvals.map((item) => <ApprovalCard key={item.id} item={item} onDone={done} />)}</div>
          </section>
        ) : null}

        {cases.length ? (
          <section aria-labelledby="inbox-cases">
            <h2 id="inbox-cases" className="mb-4 text-sm font-medium text-muted-foreground">Cases that need your answer</h2>
            <div className={GRID}>
              {cases.map((card) => (
                <article key={card.case_id} className={CARD}>
                  <header className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="flex items-center gap-1.5 text-xs font-medium text-primary"><ShieldQuestion className="size-3.5" aria-hidden="true" />Needs you</span>
                    <span className="mono text-xs text-muted-foreground">{card.package}@{card.version} · {card.vuln_id}</span>
                  </header>
                  <p className="mt-2 text-[15px] leading-6">{card.question || `Is ${card.package}@${card.version} affected by ${card.vuln_id}?`}</p>
                  {card.positions?.length ? (
                    <p className="mt-1 text-sm text-muted-foreground">
                      {card.positions.map((position) => `${position.source}: ${position.verdict}${position.bound ? ` (${position.bound})` : ""}`).join(" · ")}
                    </p>
                  ) : null}
                  <div className="mt-auto pt-5">
                    <Link to={`/cases/${encodeURIComponent(card.case_id)}`} className="btn-gold rounded-full px-5 py-1.5 text-sm font-medium no-underline">
                      Open the case and answer
                    </Link>
                  </div>
                </article>
              ))}

            </div>
          </section>
        ) : null}
        {questions.length ? (
          <section aria-labelledby="inbox-questions">
            <h2 id="inbox-questions" className="mb-4 text-sm font-medium text-muted-foreground">Questions about your services</h2>
            <div className={GRID}>{questions.map((question) => <QuestionCard key={question.question_id} question={question} onAnswered={done} />)}</div>
          </section>
        ) : null}
      </div>
    </div>
  )
}

function ApprovalCard({ item, onDone }: { item: InboxBody["approvals"][number]; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  async function act(approve: boolean) {
    setBusy(true)
    setError("")
    try {
      const result = approve ? await api.approve(item.id) : await api.reject(item.id)
      if (!result.ok) throw new Error("H-MEM refused the change.")
      onDone()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "That didn't save.")
      setBusy(false)
    }
  }
  return (
    <article className={CARD}>
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="flex items-center gap-1.5 text-xs font-medium text-primary"><Brain className="size-3.5" aria-hidden="true" />{item.kind === "mapping" ? "Package mapping" : "Trust change"}</span>
        <span className="text-xs text-muted-foreground">{item.user || "Sibyl"}</span>
      </header>
      <p className="mt-2 text-[15px] leading-6">
        {item.kind === "mapping"
          ? `Map “${item.product}” to ${item.purl}.`
          : `Weigh ${item.source} at ${item.weight} (now ${item.previous}) for ${item.field} in ${item.ecosystem}.`}
      </p>
      {item.reason ? <p className="mt-1 text-sm text-muted-foreground">{item.reason}</p> : null}
      <p className="mt-1 text-xs text-muted-foreground">Nothing changes until you approve. The next triage re-decides every case this touches.</p>
      <div className="mt-auto flex gap-2 border-t border-border pt-4">
        <button type="button" disabled={busy} onClick={() => act(true)} className={CONFIRM}>Approve</button>
        <button type="button" disabled={busy} onClick={() => act(false)} className={REMOVE}>Reject</button>
      </div>
      {error ? <p role="alert" className="mt-2 text-sm text-critical">{error}</p> : null}
    </article>
  )
}

function QuestionCard({ question, onAnswered }: { question: Question; onAnswered: () => void }) {
  const kind = KIND[question.kind] ?? { label: question.kind, confirm: "Confirm", dismiss: "Dismiss" }
  const [changing, setChanging] = useState(false)
  const [value, setValue] = useState<string>(String(question.proposed ?? ""))
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const factual = question.kind === "service_fact" || question.kind === "fact_changed"
  const files = question.evidence.filter((item) => item.file || item.text)
  const notes = question.evidence.filter((item) => item.note)

  async function answer(action: "confirm" | "change" | "dismiss") {
    setBusy(true)
    setError("")
    try {
      await api.answer(question.question_id, { action, value: action === "change" ? coerce(question.field, value) : undefined })
      onAnswered()
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "That answer didn't save.")
      setBusy(false)
    }
  }

  return (
    <article className={CARD}>
      <header className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <span className="font-medium text-primary">{kind.label}</span>
        <time dateTime={question.created_at} className="text-muted-foreground">{ago(Date.parse(question.created_at) / 1000)}</time>
      </header>
      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
        {question.service_name ? <span className="font-medium text-foreground">{question.service_name}</span> : null}
        {question.confidence != null ? <span className="num">{Math.round(question.confidence * 100)}% confidence</span> : null}
      </div>
      <h3 className="mt-2 text-sm font-medium leading-6">{question.prompt}</h3>
      {notes.map((item, index) => (
        <p key={index} className="mt-3 text-xs leading-5 text-muted-foreground">{item.by === "model" ? "Model" : "Sibyl"}: {item.note}</p>
      ))}

      {files.length ? (
        <div className="mt-3">
          <button type="button" aria-expanded={open} onClick={() => setOpen((was) => !was)} className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
            <ChevronRight className={`size-4 transition-transform duration-150 ${open ? "rotate-90" : ""}`} aria-hidden="true" />
            View evidence · {files.length} {files.length === 1 ? "line" : "lines"}
          </button>
          {open ? (
            <ul className="mt-2 flex max-h-48 flex-col gap-1.5 overflow-y-auto">
              {files.map((item, index) => (
                <li key={`${item.file}-${item.line}-${index}`} className="rounded-md bg-raised px-3 py-2 text-xs">
                  {item.file ? (
                    <span className="mono flex items-start gap-1.5 text-muted-foreground [overflow-wrap:anywhere]">
                      <FileCode2 className="size-3.5" aria-hidden="true" />
                      {item.file}{item.line ? `:${item.line}` : ""}
                    </span>
                  ) : null}
                  <span className="mono block text-foreground">{item.text}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}

      <div className="mt-auto pt-5">
        {changing && factual ? (
          <div className="flex flex-wrap items-center gap-2 border-t border-border pt-4 [&>input]:w-full [&>button[role=combobox]]:w-full">
            <ValueInput field={question.field} value={value} onChange={setValue} />
            <button type="button" disabled={busy} onClick={() => answer("change")} className={CONFIRM}>Save</button>
            <button type="button" onClick={() => setChanging(false)} className={DEFER}>Cancel</button>
          </div>
        ) : (
          <div className="flex flex-wrap gap-2 border-t border-border pt-4">
            <button type="button" disabled={busy} onClick={() => answer("confirm")} className={kind.confirm === "Remove it" ? REMOVE : CONFIRM}>{kind.confirm === "Remove it" ? <Trash2 className="size-3.5 shrink-0" aria-hidden="true" /> : <Check className="size-3.5 shrink-0" aria-hidden="true" />}{kind.confirm}</button>
            {factual ? (
              <button type="button" disabled={busy} onClick={() => setChanging(true)} className={CHANGE}><Pencil className="size-3.5 shrink-0" aria-hidden="true" />Change</button>
            ) : null}
            {kind.dismiss ? (
              <button type="button" disabled={busy} onClick={() => answer("dismiss")} className={kind.dismiss === "Remove it" ? REMOVE : DEFER}>{kind.dismiss === "Not now" ? <Clock3 className="size-3.5 shrink-0" aria-hidden="true" /> : null}{kind.dismiss}</button>
            ) : null}
          </div>
        )}
        {error ? <p role="alert" className="mt-2 text-sm text-critical">{error}</p> : null}
      </div>
    </article>
  )
}

function ValueInput({ field, value, onChange }: { field: string; value: string; onChange: (value: string) => void }) {
  if (field === "internet_facing") {
    return (
      <Select value={value === "true" ? "true" : "false"} onValueChange={(value) => onChange(value)} className="w-auto text-sm" aria-label="Exposure">
        <option value="true">Internet-facing</option>
        <option value="false">Internal</option>
      </Select>
    )
  }
  if (field === "data_class") {
    return (
      <Select value={value} onValueChange={(value) => onChange(value)} className="w-auto text-sm" aria-label="Data class">
        {DATA_CLASSES.map((item) => (
          <option key={item} value={item}>{item}</option>
        ))}
      </Select>
    )
  }
  if (field === "criticality") {
    return <input type="number" min={0} max={1} step={0.1} value={value} onChange={(event) => onChange(event.target.value)} className="input num w-28 text-sm" aria-label="Criticality" />
  }
  return <input value={value} onChange={(event) => onChange(event.target.value)} className="input w-64 text-sm" aria-label="Team" />
}

function coerce(field: string, value: string): unknown {
  if (field === "internet_facing") return value === "true"
  if (field === "criticality") return Number(value)
  return value
}

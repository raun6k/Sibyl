import { useCallback, useEffect, useState } from "react"
import { Link } from "react-router"
import { ChevronRight, FileCode2 } from "lucide-react"
import { api, DATA_CLASSES, type Question } from "@/api"
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

const ORDER = ["service_found", "service_gone", "fact_changed", "service_fact", "data_quality"]

export function InboxScreen() {
  const { workspace, refreshInbox } = useWorkspace()
  const [questions, setQuestions] = useState<Question[] | null>(null)
  const [error, setError] = useState("")

  const load = useCallback(() => {
    api.questions(workspace.workspace_id).then((body) => setQuestions(body.questions)).catch((exc: Error) => setError(exc.message))
  }, [workspace.workspace_id])

  useEffect(load, [load])

  const sorted = [...(questions ?? [])].sort((a, b) => ORDER.indexOf(a.kind) - ORDER.indexOf(b.kind))

  return (
    <div>
      <PageHeader
        eyebrow={workspace.name}
        title="Inbox"
        meta={questions ? (questions.length ? `${questions.length} questions from the agents` : "Nothing waiting on you") : "Loading…"}
      />
      <div className="mx-auto flex max-w-[900px] flex-col gap-4 px-6 py-8 sm:px-10">
        {error ? <p role="alert" className="text-sm text-critical">{error}</p> : null}
        {questions && questions.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Questions about your services land here: what Sibyl worked out from the code and wants you to confirm, new or
            removed services, and data-quality checks. Vulnerability questions are in <Link to="/queue">Needs you</Link>.
          </p>
        ) : null}
        {sorted.map((question) => (
          <QuestionCard
            key={question.question_id}
            question={question}
            onAnswered={() => {
              load()
              refreshInbox()
            }}
          />
        ))}
      </div>
    </div>
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
    <article className="rounded-2xl border border-hairline bg-surface px-6 py-5">
      <header className="flex flex-wrap items-baseline justify-between gap-2">
        <span className="eyebrow text-primary">{kind.label}</span>
        <span className="text-xs text-muted-foreground">
          {question.service_name ? <span className="mr-2">{question.service_name}</span> : null}
          {question.confidence ? <span className="num mr-2">{Math.round(question.confidence * 100)}% sure</span> : null}
          {ago(Date.parse(question.created_at) / 1000)}
        </span>
      </header>
      <p className="mt-2 text-[15px] leading-6">{question.prompt}</p>
      {notes.map((item, index) => (
        <p key={index} className="mt-1 text-sm text-muted-foreground">{item.by === "model" ? "Model" : "Sibyl"}: {item.note}</p>
      ))}

      {files.length ? (
        <div className="mt-3">
          <button type="button" aria-expanded={open} onClick={() => setOpen((was) => !was)} className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground">
            <ChevronRight className={`size-4 transition-transform duration-150 ${open ? "rotate-90" : ""}`} aria-hidden="true" />
            {files.length} {files.length === 1 ? "line" : "lines"} it read
          </button>
          {open ? (
            <ul className="mt-2 flex flex-col gap-1.5">
              {files.map((item, index) => (
                <li key={`${item.file}-${item.line}-${index}`} className="rounded-md bg-raised px-3 py-2 text-xs">
                  {item.file ? (
                    <span className="mono flex items-center gap-1.5 text-muted-foreground">
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

      {changing && factual ? (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <ValueInput field={question.field} value={value} onChange={setValue} />
          <button type="button" disabled={busy} onClick={() => answer("change")} className="btn-gold rounded-full px-5 py-1.5 text-sm font-medium disabled:opacity-60">Save</button>
          <button type="button" onClick={() => setChanging(false)} className="rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">Cancel</button>
        </div>
      ) : (
        <div className="mt-4 flex flex-wrap gap-2">
          <button type="button" disabled={busy} onClick={() => answer("confirm")} className="btn-gold rounded-full px-5 py-1.5 text-sm font-medium disabled:opacity-60">{kind.confirm}</button>
          {factual ? (
            <button type="button" disabled={busy} onClick={() => setChanging(true)} className="rounded-full border border-hairline px-4 py-1.5 text-sm hover:bg-raised">Change</button>
          ) : null}
          {kind.dismiss ? (
            <button type="button" disabled={busy} onClick={() => answer("dismiss")} className="rounded-full border border-hairline px-4 py-1.5 text-sm text-muted-foreground hover:bg-raised">{kind.dismiss}</button>
          ) : null}
        </div>
      )}
      {error ? <p role="alert" className="mt-2 text-sm text-critical">{error}</p> : null}
    </article>
  )
}

function ValueInput({ field, value, onChange }: { field: string; value: string; onChange: (value: string) => void }) {
  if (field === "internet_facing") {
    return (
      <select value={value === "true" ? "true" : "false"} onChange={(event) => onChange(event.target.value)} className="input w-auto text-sm" aria-label="Exposure">
        <option value="true">Internet-facing</option>
        <option value="false">Internal</option>
      </select>
    )
  }
  if (field === "data_class") {
    return (
      <select value={value} onChange={(event) => onChange(event.target.value)} className="input w-auto text-sm" aria-label="Data class">
        {DATA_CLASSES.map((item) => (
          <option key={item} value={item}>{item}</option>
        ))}
      </select>
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

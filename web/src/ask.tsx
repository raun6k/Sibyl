import { useState } from "react"
import { Link } from "react-router"
import { api, type ReportCase } from "@/api"

export function AskDrawer({ onClose }: { onClose: () => void }) {
  const [question, setQuestion] = useState("Are we affected by CVE-2023-4863?")
  const [answer, setAnswer] = useState<{ intent: string; case: ReportCase | null } | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)

  async function send() {
    setBusy(true)
    setError("")
    try {
      const result = await api.ask(question)
      setAnswer({ intent: result.intent, case: result.case })
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Sibyl could not answer")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-black/40" role="presentation" onClick={onClose}>
      <aside role="dialog" aria-label="Ask Sibyl" className="flex h-full w-full max-w-[480px] flex-col gap-4 bg-surface p-4 shadow-xl" onClick={(event) => event.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold">Ask Sibyl</h2>
          <button type="button" onClick={onClose}>Close</button>
        </div>
        <label className="flex flex-col gap-1 text-sm">
          Question
          <input value={question} onChange={(event) => setQuestion(event.target.value)} className="h-10 rounded-md border border-input bg-background px-2" />
        </label>
        <button type="button" disabled={busy || !question.trim()} onClick={send} className="h-10 rounded-md bg-primary font-semibold text-primary-foreground">
          {busy ? "Asking…" : "Ask"}
        </button>
        {error ? <p role="alert">{error}</p> : null}
        {answer?.case ? (
          <article className="rounded-xl border border-border p-4">
            <p className="text-xs text-muted-foreground">Scout intent {answer.intent}</p>
            <h3 className="mono mt-1 font-semibold">{answer.case.vuln_id}</h3>
            <p>{answer.case.verdict}{answer.case.exploited ? " · exploited" : ""} · priority {answer.case.score}</p>
            <p className="text-sm text-muted-foreground">{answer.case.rationale}</p>
            <Link to={`/cases/${encodeURIComponent(answer.case.case_id)}`} onClick={onClose}>Open the case file →</Link>
          </article>
        ) : null}
      </aside>
    </div>
  )
}

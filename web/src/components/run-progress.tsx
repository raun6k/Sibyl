import { Check, Circle, Loader2, X } from "lucide-react"
import { STAGES, STAGE_LABEL, STAGE_PHRASE } from "@/lib/format"

export function RunProgress({ stage, status, compact = false }: { stage: string; status: string; compact?: boolean }) {
  const done = status === "DONE"
  const failed = status === "FAILED"
  const index = STAGES.indexOf(stage as (typeof STAGES)[number])
  const queued = status === "QUEUED"
  return (
    <div>
      {!compact ? <p className="mb-5 text-sm font-medium">{done ? "Run completed" : failed ? "Run stopped" : queued ? "Waiting to start" : STAGE_PHRASE[stage] || "Run in progress"}<span className="ml-2 text-xs font-normal text-muted-foreground">{done ? "All stages finished" : queued ? "Earlier workspace jobs finish first" : failed ? "Review the error and trace below" : "Progress by stage"}</span></p> : null}
      <ol aria-label="Run stages" className={`grid ${compact ? "grid-cols-7 gap-1.5" : "grid-cols-4 gap-x-2 gap-y-4 sm:grid-cols-7"}`}>
        {STAGES.map((name, i) => {
          const complete = done || (!queued && index >= 0 && i < index)
          const active = !done && !queued && i === index
          return <li key={name} aria-current={active ? "step" : undefined} className="min-w-0">
            {compact ? <div className={`mb-1.5 h-1 rounded-full ${complete || active ? "bg-primary" : "bg-raised"}`} /> : <div className="relative mb-2 flex justify-center">
              {i < STAGES.length - 1 ? <span aria-hidden="true" className={`absolute top-3 left-[calc(50%+16px)] hidden h-px w-[calc(100%-24px)] sm:block ${complete ? "bg-primary/50" : "bg-border"}`} /> : null}
              <span className={`relative flex size-6 items-center justify-center rounded-full ${complete ? "bg-primary/15 text-primary" : active ? failed ? "bg-critical/15 text-critical" : "bg-primary text-primary-foreground" : "bg-raised text-muted-foreground"}`}>
                {complete ? <Check className="size-3.5" aria-hidden="true" /> : active ? failed ? <X className="size-3.5" aria-hidden="true" /> : <Loader2 className="size-3.5 animate-spin" aria-hidden="true" /> : <Circle className="size-2" aria-hidden="true" />}
              </span>
            </div>}
            <span className={`block text-center text-[11px] ${complete || active ? "font-medium text-foreground" : "text-muted-foreground"}`}>{STAGE_LABEL[name]}</span>
            <span className="sr-only">{complete ? "Completed" : active ? failed ? "Failed" : "In progress" : "Pending"}</span>
          </li>
        })}
      </ol>
    </div>
  )
}

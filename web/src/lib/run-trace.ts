import type { TraceEvent } from "@/api"

export const TRACE_FILTERS = [
  { id: "all", label: "All events" },
  { id: "models", label: "Model calls" },
  { id: "queries", label: "Queries" },
  { id: "decisions", label: "Decisions" },
  { id: "stages", label: "Stages" },
  { id: "rechecks", label: "Rechecks" },
  { id: "other", label: "Other" },
] as const
export type TraceFilter = (typeof TRACE_FILTERS)[number]["id"]

export function traceCategory(event: TraceEvent): TraceFilter {
  if (event.type === "llm_call") return "models"
  if (event.type === "tool" || event.type === "tool_call") return "queries"
  if (event.type === "recheck" || event.payload.action === "recheck") return "rechecks"
  if (event.type === "decision" || event.type === "reuse") return "decisions"
  if (event.type === "state" || event.type === "agent_step") return "stages"
  return "other"
}

export function traceSummary(event: TraceEvent): string {
  const p = event.payload
  if (event.type === "llm_call") return `${p.lane || "Model call"} · ${p.routed_model || p.requested_model || "model not recorded"}${p.error_code ? ` · ${p.error_code}` : ""}`
  if (event.type === "tool" || event.type === "tool_call") return `Zetaris query · ${p.rows ?? "—"} rows · ${p.ms ?? "—"} ms`
  if (event.type === "state") return `${p.from ? `${p.from} → ` : ""}${p.to || "State update"}`
  if (event.type === "reuse") return `Reused ${p.verdict || "verdict"} · ${p.case_id || "case"}`
  return String(p.reason || p.step || p.action || p.case_id || event.type.replaceAll("_", " "))
}

export function filterTrace(events: TraceEvent[], category: TraceFilter, actor: string, query: string): TraceEvent[] {
  const term = query.trim().toLowerCase()
  return events.filter((event) => (category === "all" || traceCategory(event) === category)
    && (!actor || event.actor === actor)
    && (!term || `${event.actor} ${event.type} ${JSON.stringify(event.payload)}`.toLowerCase().includes(term)))
}

export function tracePage(events: TraceEvent[], page: number, pageSize = 20) {
  const pages = Math.max(1, Math.ceil(events.length / pageSize))
  const current = Math.max(0, Math.min(page, pages - 1))
  return { events: events.slice(current * pageSize, (current + 1) * pageSize), current, pages }
}

export type RunState = {
  run_id: string
  status: string
  stage: string
  dataset?: string
  window_days?: number
  elapsed_seconds?: number
  counts: { ranked: number; closed: number; needs_human: number }
  budget: { tokens: number; max_tokens: number; seconds: number; max_seconds: number }
  degraded_sources: string[]
  error?: string
}

export type ReportCase = {
  case_id: string
  package: string
  version: string
  vuln_id: string
  verdict: string
  score: number
  score_factors: Record<string, number>
  confidence: number
  confidence_factors: { name: string; value: number; note?: string }[]
  record_ids: string[]
  rationale: string
  rationale_source: string
  conflicts: { field?: string; values_by_source?: Record<string, string>; severity?: string }[]
  question: string
  accepted_under: string | null
  positions: { source: string; verdict: string; status?: string; bound?: string }[]
  method: string
  exploited: boolean
  resolution?: string
  low_trust_flags?: string[]
}

export type Report = {
  run_id: string
  state: string
  partial: boolean
  degraded: boolean
  ranked: ReportCase[]
  closed: ReportCase[]
  needs_human: ReportCase[]
  receipts: { zetaris: { sql: string; rows: number; ms: number; truncated?: boolean }[]; llm: Record<string, unknown>[] }
}

export type TraceEvent = {
  event_id: string
  ts?: string
  actor: string
  type: string
  payload: Record<string, unknown>
}

async function read<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || response.statusText)
  }
  return response.json() as Promise<T>
}

export const api = {
  inventory: () => read<{ services: ServiceCard[]; components: number; run_id?: string }>("/api/inventory"),
  sources: () => read<{ sources: { source: string; records: number; status: string }[] }>("/api/sources"),
  runs: () => read<{ runs: RunState[] }>("/api/runs"),
  run: (id: string) => read<RunState>(`/api/runs/${id}`),
  report: (id: string) => read<Report>(`/api/runs/${id}/report`),
  start: (body: { dataset: string; disable_sources: string[]; window_days: number }) =>
    read<{ run_id: string }>("/api/runs", { method: "POST", body: JSON.stringify(body) }),
  case: (id: string) => read<CaseFile>(`/api/cases/${encodeURIComponent(id)}`),
  queue: () => read<{ run_id: string; needs_human: ReportCase[] }>("/api/needs-human"),
  resolve: (id: string, body: { decision: string; note: string; user: string; remember: boolean; scope: string }) =>
    read<{ pending: { id: string } | null; resolution: unknown }>(`/api/cases/${encodeURIComponent(id)}/resolution`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  memory: () => read<MemorySnapshot>("/api/memory"),
  approve: (id: string) => read<{ ok: boolean }>(`/api/memory/pending/${id}/approve`, { method: "POST" }),
  reject: (id: string) => read<{ ok: boolean }>(`/api/memory/pending/${id}/reject`, { method: "POST" }),
  ask: (question: string) =>
    read<{ question: string; intent: string; cve_id: string | null; run_id: string; case: ReportCase | null }>("/api/ask", {
      method: "POST",
      body: JSON.stringify({ question }),
    }),
  baselines: (label: string) => read<{ rows: BaselineRow[] }>(`/api/baselines/${label}`),
}

export type ServiceCard = {
  service_id: string
  name: string
  team: string
  internet_facing: string
  criticality: string
  data_class: string
  components: number
  pypi: number
  npm: number
  affected: number
  needs_human: number
  sbom_at: string
}

export type CaseFile = {
  case: ReportCase
  run_id: string
  events: TraceEvent[]
  provenance: {
    records: { record_id: string; source: string; status: string; retrieved_at: string }[]
    matrix: { field: string; cells: Record<string, string> }[]
  }
}

export type MemorySnapshot = {
  unavailable?: boolean
  error?: string
  pending: {
    id: string
    kind: string
    source: string
    field: string
    ecosystem: string
    weight: number
    previous: number
    product: string
    purl: string
    reason: string
    case_id: string
    user: string
  }[]
  trust: { source: string; field: string; ecosystem: string; weight: number; superseded: boolean; source_actor: string }[]
  mappings: { product: string; purl: string }[]
  resolutions: { case_id: string; decision: string; note: string; user: string; at: string; expiry: string | null; scope: string }[]
}

export type BaselineRow = {
  service_id: string
  package: string
  version: string
  vuln_id: string
  prediction: string
}

export function streamRun(id: string, onEvent: (event: TraceEvent) => void, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const source = new EventSource(`/api/runs/${id}/events`)
    const stop = () => {
      source.close()
      resolve()
    }
    signal.addEventListener("abort", () => {
      source.close()
      reject(new DOMException("aborted", "AbortError"))
    })
    source.onmessage = (message) => {
      const event = JSON.parse(message.data) as TraceEvent
      onEvent(event)
      const to = event.payload?.to
      if (event.type === "state" && (to === "DONE" || to === "FAILED")) stop()
    }
    source.onerror = () => {
      source.close()
      reject(new Error("the event stream closed"))
    }
  })
}

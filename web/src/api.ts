export type RunState = {
  run_id: string
  workspace_id?: string
  status: string
  stage: string
  dataset?: string
  window_days?: number
  started?: number
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
  positions: { source: string; verdict: string; status?: string; bound?: string; record_id?: string; quote?: string }[]
  method: string
  exploited: boolean
  resolution?: string
  low_trust_flags?: string[]
  ecosystem?: string
  purl?: string
  cvss?: number
  cvss_source?: string
  cvss_version?: string
  epss_percentile?: number
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

// The workspace every scoped call reads. The shell sets it when you switch workspaces.
let currentWorkspace = ""

export function setApiWorkspace(id: string) {
  currentWorkspace = id
}

function scoped(path: string) {
  if (!currentWorkspace) return path
  return `${path}${path.includes("?") ? "&" : "?"}workspace=${encodeURIComponent(currentWorkspace)}`
}

async function read<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    const text = await response.text()
    let detail = text
    try {
      const parsed = JSON.parse(text) as { detail?: unknown }
      if (typeof parsed.detail === "string") detail = parsed.detail
    } catch {
      // Not JSON: show the text as it came.
    }
    throw new Error(detail || response.statusText)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  inventory: () => read<{ services: ServiceCard[]; components: number; run_id?: string }>(scoped("/api/inventory")),
  sources: () => read<{ sources: { source: string; records: number; status: string }[] }>("/api/sources"),
  runs: () => read<{ runs: RunState[] }>(scoped("/api/runs")),
  run: (id: string) => read<RunState>(`/api/runs/${id}`),
  report: (id: string) => read<Report>(`/api/runs/${id}/report`),
  start: (body: { dataset: string; disable_sources: string[]; window_days: number }) =>
    read<{ run_id: string }>("/api/runs", { method: "POST", body: JSON.stringify({ ...body, workspace_id: currentWorkspace }) }),
  case: (id: string) => read<CaseFile>(`/api/cases/${encodeURIComponent(id)}`),
  queue: () => read<{ run_id: string; needs_human: ReportCase[] }>(scoped("/api/needs-human")),
  resolve: (id: string, body: { decision: string; note: string; user: string; remember: boolean; scope: string }) =>
    read<{ pending: { id: string } | null; resolution: unknown }>(`/api/cases/${encodeURIComponent(id)}/resolution`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  memory: () => read<MemorySnapshot>(scoped("/api/memory")),
  approve: (id: string) => read<{ ok: boolean }>(scoped(`/api/memory/pending/${id}/approve`), { method: "POST" }),
  reject: (id: string) => read<{ ok: boolean }>(scoped(`/api/memory/pending/${id}/reject`), { method: "POST" }),
  ask: (question: string) =>
    read<{ question: string; intent: string; cve_id: string | null; run_id: string; case: ReportCase | null }>("/api/ask", {
      method: "POST",
      body: JSON.stringify({ question, workspace_id: currentWorkspace }),
    }),
  baselines: (label: string) => read<{ rows: BaselineRow[] }>(`/api/baselines/${label}`),

  workspaces: () => read<{ workspaces: WorkspaceInfo[] }>("/api/workspaces"),
  createWorkspace: (name: string) => read<WorkspaceInfo>("/api/workspaces", { method: "POST", body: JSON.stringify({ name }) }),
  loadDemo: () => read<WorkspaceInfo>("/api/workspaces/demo", { method: "POST" }),
  renameWorkspace: (id: string, name: string) =>
    read<WorkspaceInfo>(`/api/workspaces/${id}`, { method: "PATCH", body: JSON.stringify({ name }) }),
  deleteWorkspace: (id: string) => read<void>(`/api/workspaces/${id}`, { method: "DELETE" }),

  repositories: (workspace: string) => read<{ repositories: Repository[] }>(`/api/workspaces/${workspace}/repositories`),
  repository: (id: string) => read<RepositoryDetail>(`/api/repositories/${id}`),
  connect: (workspace: string, body: { location: string; branch: string; token_env: string; sync_interval_minutes: number }) =>
    read<Repository>(`/api/workspaces/${workspace}/repositories`, { method: "POST", body: JSON.stringify(body) }),
  updateRepository: (id: string, body: Partial<Pick<Repository, "branch" | "token_env" | "sync_interval_minutes">>) =>
    read<Repository>(`/api/repositories/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  disconnect: (id: string) => read<void>(`/api/repositories/${id}`, { method: "DELETE" }),
  sync: (id: string, full = false) => read<{ syncing: boolean }>(`/api/repositories/${id}/sync${full ? "?full=true" : ""}`, { method: "POST" }),
  syncs: (workspace: string) => read<{ syncs: SyncRecord[] }>(`/api/workspaces/${workspace}/syncs`),

  services: (workspace: string) => read<{ services: ServiceRow[] }>(`/api/workspaces/${workspace}/services`),
  addService: (workspace: string, body: ServiceInput & { sbom?: unknown }) =>
    read<ServiceRow>(`/api/workspaces/${workspace}/services`, { method: "POST", body: JSON.stringify(body) }),
  updateService: (id: string, body: Partial<ServiceInput> & { triage_policy?: string; triage_interval_minutes?: number; user?: string }) =>
    read<ServiceRow>(`/api/services/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  removeService: (id: string) => read<void>(`/api/services/${id}`, { method: "DELETE" }),

  questions: (workspace: string, status = "open") => read<{ questions: Question[] }>(`/api/workspaces/${workspace}/questions?status=${status}`),
  answer: (id: string, body: { action: "confirm" | "change" | "dismiss"; value?: unknown; user?: string }) =>
    read<Question>(`/api/questions/${id}/answer`, { method: "POST", body: JSON.stringify(body) }),
}

export type WorkspaceInfo = {
  workspace_id: string
  name: string
  is_demo: boolean
  created_at?: string
  services?: number
  repositories?: number
  open_questions?: number
}

export type Repository = {
  repo_id: string
  workspace_id: string
  kind: "git" | "local"
  location: string
  branch: string
  token_env: string
  sync_interval_minutes: number
  last_scanned_sha: string | null
  last_synced_at: string | null
  status: string
  error: string
  services?: number
  syncing?: boolean
}

export type SyncRecord = {
  sync_id: string
  repo_id: string
  started_at: string
  finished_at: string | null
  from_sha: string | null
  to_sha: string | null
  mode: string
  status: string
  error: string
  summary: {
    mode?: string
    new_services?: { service_id: string; path: string; components: number }[]
    services?: Record<string, { added: number; removed: number; changed: number; diff?: Record<string, string[]> }>
    questions?: number
    skipped?: string[]
    limits?: string[]
    not_covered?: Record<string, number>
    quality?: { rule: string; table?: string; meaning?: string; invalid: number; checked?: number; examples: string[]; error?: string }[]
    seconds?: number
  }
}

export type RepositoryDetail = Repository & { syncs: SyncRecord[]; services: ServiceRow[] }

export type ServiceInput = {
  name: string
  team: string
  internet_facing: boolean
  criticality: number
  data_class: string
}

export type ServiceRow = ServiceInput & {
  service_id: string
  workspace_id: string
  repo_id: string | null
  path: string
  status: string
  triage_policy: string
  triage_interval_minutes: number
  components?: number
  sbom_at?: string | null
  ecosystems?: Record<string, number>
}

export type Question = {
  question_id: string
  workspace_id: string
  service_id: string | null
  repo_id: string | null
  kind: string
  field: string
  prompt: string
  proposed: unknown
  evidence: { id?: string; file?: string; line?: number; signal?: string; text?: string; note?: string; by?: string }[]
  confidence: number
  status: string
  answer: unknown
  answered_by: string
  created_at: string
  service_name?: string | null
  service_path?: string | null
}

export const DATA_CLASSES = ["public", "internal", "employee", "customer", "merchant", "cardholder", "credentials", "health"] as const

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
  ecosystems?: Record<string, number>
  repo_id?: string
  path?: string
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

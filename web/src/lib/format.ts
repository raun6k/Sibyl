import type { ReportCase, RunState } from "@/api"

export type Band = "critical" | "high" | "medium" | "low"

// Priority bands from docs/project/ui.md: ≥80 Critical, 60–79 High, 40–59 Medium, <40 Low.
export function band(score: number): Band {
  if (score >= 80) return "critical"
  if (score >= 60) return "high"
  if (score >= 40) return "medium"
  return "low"
}

export const BAND_LABEL: Record<Band, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" }
export const BAND_GLYPH: Record<Band, string> = { critical: "◆", high: "▲", medium: "■", low: "▼" }

// A case id is `case:<service>:<purl>:<vuln>`.
export function serviceOf(caseId: string): string {
  return caseId.split(":")[1] ?? ""
}

// Patch now: exploited in the wild, or High priority and above.
export function patchNow(card: ReportCase): boolean {
  return card.exploited || card.score >= 60
}

export function ago(seconds?: number | null): string {
  if (!seconds) return "never"
  const diff = Math.max(0, Date.now() / 1000 - seconds)
  if (diff < 60) return "just now"
  if (diff < 3600) return `${Math.round(diff / 60)} min ago`
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`
  const days = Math.round(diff / 86400)
  return days === 1 ? "yesterday" : `${days} days ago`
}

export function clock(seconds?: number | null): string {
  if (!seconds) return ""
  return new Date(seconds * 1000).toLocaleString(undefined, { weekday: "short", hour: "2-digit", minute: "2-digit" })
}

export function duration(seconds?: number | null): string {
  if (seconds == null) return "—"
  const total = Math.round(seconds)
  const minutes = Math.floor(total / 60)
  const rest = String(total % 60).padStart(2, "0")
  return minutes ? `${minutes}m ${rest}s` : `${total}s`
}

export const STAGES = ["PLANNED", "COLLECTING", "MAPPING", "MATCHING", "CRITIQUE", "PRIORITISING", "REPORTING"] as const

export const STAGE_LABEL: Record<string, string> = {
  PLANNED: "Plan",
  COLLECTING: "Collect",
  MAPPING: "Map",
  MATCHING: "Match",
  CRITIQUE: "Critique",
  PRIORITISING: "Prioritise",
  REPORTING: "Report",
}

export const STAGE_PHRASE: Record<string, string> = {
  PLANNED: "Preparing the run",
  COLLECTING: "Gathering the sources",
  MAPPING: "Mapping advisories to packages",
  MATCHING: "Weighing the evidence",
  CRITIQUE: "Questioning the verdicts",
  PRIORITISING: "Ranking what matters",
  REPORTING: "Writing the report",
}

export function isActive(run: RunState): boolean {
  return run.status === "RUNNING"
}

export const SOURCE_LABEL: Record<string, string> = {
  osv: "OSV",
  ghsa: "GitHub",
  nvd: "NVD",
  cve_org: "CVE.org",
  kev: "CISA KEV",
  epss: "EPSS",
  euvd: "EUVD",
}

export const SOURCES = ["osv", "ghsa", "nvd", "cve_org", "kev", "epss", "euvd"]

/**
 * Sibyl's records on top of H-MEM.
 *
 * Trust weights, human resolutions, learned mappings, accepted false
 * positives, and run summaries are memories. A change that would alter a
 * later verdict (trust, mapping) stays in `pending` until a person approves
 * it. A `this_case` resolution is written straight into the store.
 */

import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

import { HMEM, type LedgerEntry, type Memory } from "./index.js";

export const DEFAULT_WEIGHTS: Record<string, number> = {
  osv: 0.95,
  ghsa: 0.9,
  cna: 0.8,
  "cisa-adp": 0.8,
  euvd: 0.75,
  "nvd-cpe": 0.7,
  nvd: 0.7,
  "llm-extracted": 0.5,
};

export const TRUST_FIELDS = [
  "affected_ranges",
  "fixed_version",
  "aliases",
  "severity",
  "exploited",
  "epss",
  "withdrawn",
];

export interface TrustBody {
  kind: "trust";
  source: string;
  field: string;
  ecosystem: string;
  weight: number;
}

export interface ResolutionBody {
  kind: "resolution";
  case_id: string;
  decision: string;
  note: string;
  user: string;
  scope: string;
  at: string;
  expiry: string | null;
}

export interface MappingBody {
  kind: "mapping";
  product: string;
  purl: string;
}

export interface FalsePositiveBody {
  kind: "false_positive";
  case_id: string;
  package: string;
  vuln_id: string;
  note: string;
}

export interface SummaryBody {
  kind: "run_summary";
  run_id: string;
  needs_human: number;
  ranked: number;
  closed: number;
}

export interface PendingChange {
  id: string;
  kind: "trust" | "mapping";
  source: string;
  field: string;
  ecosystem: string;
  weight: number;
  previous: number;
  product: string;
  purl: string;
  reason: string;
  case_id: string;
  user: string;
  created_at: string;
}

export interface ResolveInput {
  case_id: string;
  decision: string;
  note?: string;
  user?: string;
  remember?: boolean;
  scope?: string;
  source?: string;
  field?: string;
  ecosystem?: string;
  weight?: number;
  product?: string;
  purl?: string;
  package?: string;
  vuln_id?: string;
  expiry?: string | null;
}

interface Saved {
  memories: Memory[];
  ledger: LedgerEntry[];
  pending: PendingChange[];
}

export class SibylMemory {
  pending: PendingChange[] = [];
  private seq = 0;

  constructor(
    readonly hmem: HMEM,
    readonly dir: string,
  ) {}

  seed(): void {
    if (this.bodies("trust").length > 0) return;
    for (const [source, weight] of Object.entries(DEFAULT_WEIGHTS)) {
      for (const field of TRUST_FIELDS) {
        const body: TrustBody = { kind: "trust", source, field, ecosystem: "*", weight };
        this.hmem.add({
          content: JSON.stringify(body),
          source: "seed",
          type: "factual",
          layer: "long_term",
          confidence: 1,
          domain: "trust",
          tags: ["trust", `source:${source}`, `field:${field}`, "ecosystem:*"],
        });
      }
    }
  }

  trust(source: string, field = "affected_ranges", ecosystem = "*"): number | null {
    const wanted = source.trim().toLowerCase();
    const rows = this.bodies("trust")
      .map((memory) => ({ memory, body: JSON.parse(memory.content) as TrustBody }))
      .filter((item) => !item.memory.supersededBy && item.body.source === wanted);
    const exact = rows.find((item) => item.body.field === field && item.body.ecosystem === ecosystem);
    const starred = rows.find((item) => item.body.field === field && item.body.ecosystem === "*");
    const anyField = rows.find((item) => item.body.field === "*" && item.body.ecosystem === "*");
    const found = exact ?? starred ?? anyField;
    return found ? found.body.weight : null;
  }

  resolve(input: ResolveInput): { resolution: ResolutionBody | null; pending: PendingChange | null; blocked: string } {
    const scope = input.scope === "adjust_trust" ? "adjust_trust" : "this_case";
    const remember = input.remember !== false;
    if (scope === "adjust_trust" && remember) {
      const source = (input.source || "cna").trim().toLowerCase();
      const field = input.field || "affected_ranges";
      const ecosystem = input.ecosystem || "*";
      const previous = this.trust(source, field, ecosystem) ?? DEFAULT_WEIGHTS[source] ?? 0.5;
      const weight = input.weight ?? Math.min(1, Math.round((previous + 0.1) * 1000) / 1000);
      if (weight > previous && (DEFAULT_WEIGHTS[source] ?? 1) < previous && source !== "human") {
        return { resolution: null, pending: null, blocked: "low-trust cannot overwrite a higher-trust weight" };
      }
      const pending = this.queue({
        kind: "trust",
        source,
        field,
        ecosystem,
        weight,
        previous,
        product: "",
        purl: "",
        reason: input.note || "",
        case_id: input.case_id,
        user: input.user || "",
      });
      return { resolution: null, pending, blocked: "" };
    }
    const expiry = input.decision === "accept_risk" ? input.expiry ?? daysFromNow(90) : input.expiry ?? null;
    const body: ResolutionBody = {
      kind: "resolution",
      case_id: input.case_id,
      decision: input.decision,
      note: input.note || "",
      user: input.user || "",
      scope,
      at: new Date(this.hmem.clock()).toISOString(),
      expiry,
    };
    this.hmem.add({
      content: JSON.stringify(body),
      source: "human",
      type: "factual",
      layer: "long_term",
      confidence: 1,
      domain: "resolution",
      tags: ["resolution", `case:${input.case_id}`],
    });
    if (input.decision === "not_affected") {
      const fp: FalsePositiveBody = {
        kind: "false_positive",
        case_id: input.case_id,
        package: input.package || "",
        vuln_id: input.vuln_id || "",
        note: input.note || "",
      };
      this.hmem.add({
        content: JSON.stringify(fp),
        source: "human",
        type: "factual",
        layer: "long_term",
        confidence: 1,
        domain: "false_positive",
        tags: ["false_positive", `case:${input.case_id}`],
      });
    }
    return { resolution: body, pending: null, blocked: "" };
  }

  proposeMapping(product: string, purl: string, reason = ""): PendingChange {
    return this.queue({
      kind: "mapping",
      source: "",
      field: "",
      ecosystem: "",
      weight: 0,
      previous: 0,
      product,
      purl,
      reason,
      case_id: "",
      user: "",
    });
  }

  approve(id: string): { ok: boolean; error: string; pending: PendingChange | null } {
    const index = this.pending.findIndex((item) => item.id === id);
    if (index < 0) return { ok: false, error: "unknown pending change", pending: null };
    const change = this.pending[index];
    if (change.kind === "trust") {
      const current = this.currentTrust(change.source, change.field, change.ecosystem);
      if (current && current.confidence > 1) {
        return { ok: false, error: "low-trust cannot overwrite a higher-trust weight", pending: change };
      }
      const body: TrustBody = {
        kind: "trust",
        source: change.source,
        field: change.field,
        ecosystem: change.ecosystem,
        weight: change.weight,
      };
      const created = this.hmem.add({
        content: JSON.stringify(body),
        source: "human",
        type: "factual",
        layer: "long_term",
        confidence: 1,
        domain: "trust",
        tags: ["trust", `source:${change.source}`, `field:${change.field}`, `ecosystem:${change.ecosystem}`],
      });
      if (current) current.supersededBy = created.id;
    } else {
      const body: MappingBody = { kind: "mapping", product: change.product, purl: change.purl };
      this.hmem.add({
        content: JSON.stringify(body),
        source: "human",
        type: "factual",
        layer: "long_term",
        confidence: 1,
        domain: "mapping",
        tags: ["mapping", `product:${change.product}`],
      });
    }
    this.pending.splice(index, 1);
    return { ok: true, error: "", pending: change };
  }

  reject(id: string): { ok: boolean; error: string } {
    const index = this.pending.findIndex((item) => item.id === id);
    if (index < 0) return { ok: false, error: "unknown pending change" };
    this.pending.splice(index, 1);
    return { ok: true, error: "" };
  }

  resolutionFor(caseId: string): ResolutionBody | null {
    const now = this.hmem.clock();
    const found = this.bodies("resolution")
      .map((memory) => JSON.parse(memory.content) as ResolutionBody)
      .filter((body) => body.case_id === caseId && body.scope === "this_case")
      .reverse();
    for (const body of found) {
      if (body.expiry && Date.parse(body.expiry) <= now) continue;
      return body;
    }
    return null;
  }

  mappingFor(product: string): string | null {
    const wanted = product.trim().toLowerCase();
    const found = this.bodies("mapping")
      .map((memory) => JSON.parse(memory.content) as MappingBody)
      .reverse()
      .find((body) => body.product.trim().toLowerCase() === wanted);
    return found ? found.purl : null;
  }

  mappings(): MappingBody[] {
    return this.bodies("mapping").map((memory) => JSON.parse(memory.content) as MappingBody);
  }

  resolutions(): ResolutionBody[] {
    return this.bodies("resolution").map((memory) => JSON.parse(memory.content) as ResolutionBody);
  }

  ledger(): Array<TrustBody & { superseded: boolean; source_actor: string }> {
    return this.bodies("trust").map((memory) => {
      const body = JSON.parse(memory.content) as TrustBody;
      return { ...body, superseded: Boolean(memory.supersededBy), source_actor: memory.source };
    });
  }

  summaries(): SummaryBody[] {
    return this.bodies("run_summary").map((memory) => JSON.parse(memory.content) as SummaryBody);
  }

  falsePositives(): FalsePositiveBody[] {
    return this.bodies("false_positive").map((memory) => JSON.parse(memory.content) as FalsePositiveBody);
  }

  addSummary(body: Omit<SummaryBody, "kind">): void {
    const stored: SummaryBody = { kind: "run_summary", ...body };
    this.hmem.add({
      content: JSON.stringify(stored),
      source: "run",
      type: "general",
      layer: "working",
      confidence: 1,
      domain: "run",
      tags: ["run_summary", `run:${body.run_id}`],
    });
  }

  snapshot(): Record<string, unknown> {
    return {
      pending: this.pending,
      trust: this.ledger().filter((row) => !row.superseded),
      mappings: this.mappings(),
      resolutions: this.resolutions(),
      false_positives: this.falsePositives(),
      summaries: this.summaries(),
      unavailable: false,
    };
  }

  save(): void {
    mkdirSync(this.dir, { recursive: true });
    const saved: Saved = {
      memories: this.hmem.store.all(),
      ledger: this.hmem.ledger.all(),
      pending: this.pending,
    };
    writeFileSync(storeFile(this.dir), JSON.stringify(saved));
  }

  load(): void {
    const file = storeFile(this.dir);
    if (!existsSync(file)) return;
    const saved = JSON.parse(readFileSync(file, "utf8")) as Saved;
    this.hmem.store.replace(saved.memories ?? []);
    this.hmem.ledger.replace(saved.ledger ?? []);
    this.pending = saved.pending ?? [];
  }

  reset(): void {
    rmSync(this.dir, { recursive: true, force: true });
    mkdirSync(this.dir, { recursive: true });
    this.hmem.store.replace([]);
    this.hmem.ledger.replace([]);
    this.pending = [];
    this.seed();
    this.save();
  }

  private queue(change: Omit<PendingChange, "id" | "created_at">): PendingChange {
    const pending: PendingChange = {
      ...change,
      id: `pend_${(this.seq += 1).toString(36)}_${this.hmem.clock().toString(36)}`,
      created_at: new Date(this.hmem.clock()).toISOString(),
    };
    this.pending.push(pending);
    return pending;
  }

  private bodies(kind: string): Memory[] {
    return this.hmem.store.all().filter((memory) => {
      try {
        return JSON.parse(memory.content).kind === kind;
      } catch {
        return false;
      }
    });
  }

  private currentTrust(source: string, field: string, ecosystem: string): Memory | undefined {
    return this.bodies("trust").find((memory) => {
      if (memory.supersededBy) return false;
      const body = JSON.parse(memory.content) as TrustBody;
      return body.source === source && body.field === field && body.ecosystem === ecosystem;
    });
  }
}

function daysFromNow(days: number): string {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

export function storeFile(dir: string): string {
  return path.join(dir, "store.json");
}

export function openMemory(dir: string): SibylMemory {
  const memory = new SibylMemory(new HMEM({ clock: () => Date.now(), dir }), dir);
  memory.load();
  memory.seed();
  memory.save();
  return memory;
}

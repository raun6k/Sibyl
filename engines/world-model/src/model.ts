/**
 * Sibyl's World Model.
 *
 * Event-sourced, one writer at a time. This is not the Meterless
 * reference. The conformance runner is the contract: stable ids, merge
 * bands, provenance, idempotent ingest, bitemporal edges, and an ordered
 * audit log.
 *
 * State lives in memory. Every mutation that changes state is also put on
 * a write log (`drainLog`), which the host appends to durable storage;
 * `replay` rebuilds the same state from that log on the next start.
 */

import { canonicalJson, entityIdFromName, externalEntityId, sha16 } from "./ids.js";

export type SourceRef = { kind: string; at?: string; url?: string };

export type UpsertEntity = {
  type: string;
  name?: string;
  externalKey?: { system: string; id: string };
  attrs?: Record<string, unknown>;
  source?: SourceRef;
};

export type ObservationInput = {
  externalId: string;
  title: string;
  at: string;
  source: SourceRef;
  entities?: { type: string; name: string }[];
};

export type IngestReport = {
  changed: boolean;
  processed: number;
  clusters: number;
  skippedUnchanged: number;
};

export type RelateInput = {
  from: string;
  type: string;
  to: string;
  validFrom?: string;
  source?: SourceRef;
  /**
   * Edges with the same `from`, `type` and `slot` supersede each other. A
   * service uses many packages at once, so its `uses` edges are slotted by
   * package and a new version closes only that package's edge.
   */
  slot?: string;
};

export type UnrelateInput = { from: string; type: string; slot?: string; validTo: string; source?: SourceRef };

export type AuditEntry = { seq: number; action: string; target: string; at: string };

export type Neighbor = { id: string };

/** Write-log schema. A log written by a newer schema is refused on replay. */
export const LOG_SCHEMA_VERSION = 1;

export type LogEntry = {
  seq: number;
  v: number;
  op: "upsert" | "ingest" | "relate" | "unrelate" | "apply";
  at: string;
  input: Record<string, unknown>;
};

type EntityRecord = {
  id: string;
  type: string;
  name: string;
  attrs: Record<string, unknown>;
  source: SourceRef;
};

type ObservationRecord = {
  externalId: string;
  title: string;
  at: string;
  source: SourceRef;
  entityIds: string[];
  hash: string;
};

export type EdgeRecord = {
  id: string;
  from: string;
  type: string;
  to: string;
  validFrom: string | null;
  validTo: string | null;
  source: SourceRef;
  slot?: string;
};

export const MESSAGE_KINDS = [
  "Claim",
  "AliasLink",
  "SourceMap",
  "DraftVerdict",
  "Conflict",
  "RecheckRequest",
  "CriticDecision",
  "Verdict",
  "Priority",
  "Escalation",
  "RunOpened",
  "Placement",
  "RunClosed",
] as const;

export type MessageKind = (typeof MESSAGE_KINDS)[number];

export type ApplyResult = { changed: boolean; ids: string[] };

type DomainEvent = {
  id: string;
  kind: MessageKind;
  payload: Record<string, unknown>;
};

type Payload = Record<string, unknown>;

type RunRecord = { runId: string; order: number; opened: Payload | null; closed: Payload | null };

export class WorldModel {
  readonly schemaVersion = 1;
  readonly namespace: string;
  private readonly clock: () => Date;
  private readonly entities = new Map<string, EntityRecord>();
  private readonly observations = new Map<string, ObservationRecord>();
  private readonly edges = new Map<string, EdgeRecord>();
  private readonly events: DomainEvent[] = [];
  private readonly eventIds = new Set<string>();
  private readonly byCase = new Map<string, DomainEvent[]>();
  private readonly aliasEvents: DomainEvent[] = [];
  private readonly keyed = new Map<string, string>();
  private readonly runs = new Map<string, RunRecord>();
  private readonly auditLog: AuditEntry[] = [];
  private readonly pendingLog: LogEntry[] = [];
  private seq = 0;
  private logSeq = 0;
  private replayAt: string | null = null;
  private tail: Promise<void> = Promise.resolve();

  constructor(options: { storage: "memory"; namespace: string; clock?: () => Date }) {
    if (options.storage !== "memory") {
      throw new Error(`unsupported storage ${options.storage}`);
    }
    this.namespace = options.namespace;
    this.clock = options.clock ?? (() => new Date());
  }

  upsertEntity(input: UpsertEntity): Promise<{ id: string; changed: boolean }> {
    return this.enqueue(() => this.doUpsert(input));
  }

  ingest(observations: ObservationInput[]): Promise<IngestReport> {
    return this.enqueue(() => this.doIngest(observations));
  }

  relate(input: RelateInput): Promise<{ id: string; changed: boolean }> {
    return this.enqueue(() => this.doRelate(input));
  }

  /** Close the open edge in one slot, for a package a service no longer uses. */
  unrelate(input: UnrelateInput): Promise<{ id: string | null; changed: boolean }> {
    return this.enqueue(() => this.doUnrelate(input));
  }

  /**
   * Append one Sibyl message. The same canonical payload is an empty diff.
   * A claim is keyed by case, source, field and record: it changes only
   * when its value differs from the current one for that key. Stable ids
   * named by the payload (`case:`, `vuln:`, `source:`, …) are registered
   * the first time they appear.
   */
  apply(kind: MessageKind, payload: Record<string, unknown>): Promise<ApplyResult> {
    return this.enqueue(() => this.doApply(kind, payload));
  }

  /** Entries written since the last drain, oldest first. The host makes them durable. */
  drainLog(): LogEntry[] {
    return this.pendingLog.splice(0, this.pendingLog.length);
  }

  /** Rebuild state from a durable log. Replayed entries are not put on the write log again. */
  replay(entries: LogEntry[]): Promise<{ applied: number; seq: number }> {
    return this.enqueue(() => {
      let applied = 0;
      for (const entry of entries) {
        if (entry.v > LOG_SCHEMA_VERSION) {
          throw new Error(`log entry ${entry.seq} has schema ${entry.v}; this engine reads ${LOG_SCHEMA_VERSION}`);
        }
        if (entry.seq <= this.logSeq) continue;
        this.replayAt = entry.at;
        try {
          const input = entry.input;
          if (entry.op === "upsert") this.doUpsert(input as UpsertEntity, true);
          else if (entry.op === "ingest") this.doIngest(input.observations as ObservationInput[], true);
          else if (entry.op === "relate") this.doRelate(input as RelateInput, true);
          else if (entry.op === "unrelate") this.doUnrelate(input as UnrelateInput, true);
          else if (entry.op === "apply") this.doApply(input.kind as MessageKind, input.payload as Payload, true);
          else throw new Error(`unknown log op ${String(entry.op)}`);
        } finally {
          this.replayAt = null;
        }
        this.logSeq = entry.seq;
        applied += 1;
      }
      return { applied, seq: this.logSeq };
    });
  }

  view(name: string): { neighborsOf: (id: string, options?: { via?: string; at?: string }) => Neighbor[] } {
    if (name !== "graph") throw new Error(`unknown view ${name}`);
    return {
      neighborsOf: (id, options) => this.neighborsOf(id, options),
    };
  }

  /** Edges out of one entity, open now or at `at`. */
  edgesOf(from: string, options?: { via?: string; slot?: string; at?: string }): EdgeRecord[] {
    const found: EdgeRecord[] = [];
    for (const edge of this.edges.values()) {
      if (edge.from !== from) continue;
      if (options?.via && edge.type !== options.via) continue;
      if (options?.slot !== undefined && edge.slot !== options.slot) continue;
      if (!edgeActive(edge, options?.at)) continue;
      found.push({ ...edge });
    }
    return found.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  audit(): AuditEntry[] {
    return this.auditLog.map((entry) => ({ ...entry }));
  }

  stateShapeCanonical(): string {
    const entities = [...this.entities.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    const observations = [...this.observations.values()].sort((a, b) =>
      a.externalId < b.externalId ? -1 : a.externalId > b.externalId ? 1 : 0,
    );
    const edges = [...this.edges.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return canonicalJson({
      schemaVersion: this.schemaVersion,
      namespace: this.namespace,
      entities,
      observations,
      edges,
      clusters: this.clusterGroups(),
    });
  }

  /**
   * One case as the agents read it.
   *
   * `claims` are the current value per (source, field, record). Run-scoped
   * messages (drafts, conflicts, critic decisions, rechecks, verdict,
   * priority, escalations) are the ones of `runId`, or of the latest run
   * that touched the case. `history` holds what earlier runs decided,
   * newest first, and `prior` is the latest placement from an earlier run.
   */
  projectCase(caseId: string, options?: { runId?: string }): Record<string, unknown> {
    const events = this.byCase.get(caseId) ?? [];
    let current = options?.runId;
    if (current === undefined) {
      current = "";
      for (const event of events) {
        if (event.kind === "Claim" || event.kind === "SourceMap") continue;
        current = runOf(event.payload);
      }
    }
    const claims = new Map<string, Payload>();
    const draftVerdicts: Payload[] = [];
    const conflicts: Payload[] = [];
    const recheckRequests: Payload[] = [];
    const criticDecisions: Payload[] = [];
    const escalations: Payload[] = [];
    let sourceMap: Payload | null = null;
    let verdict: Payload | null = null;
    let priority: Payload | null = null;
    let placement: Payload | null = null;
    const earlier = new Map<string, { placement: Payload | null; rechecks: Payload[]; critic: Payload[]; verdict: Payload | null }>();
    for (const event of events) {
      const payload = event.payload;
      if (event.kind === "Claim") {
        claims.set(claimKey(payload), payload);
        continue;
      }
      if (event.kind === "SourceMap") {
        sourceMap = payload;
        continue;
      }
      const run = runOf(payload);
      if (run !== current) {
        const bucket = earlier.get(run) ?? { placement: null, rechecks: [], critic: [], verdict: null };
        earlier.set(run, bucket);
        if (event.kind === "Placement") bucket.placement = payload;
        else if (event.kind === "RecheckRequest") bucket.rechecks.push(payload);
        else if (event.kind === "CriticDecision") bucket.critic.push(payload);
        else if (event.kind === "Verdict") bucket.verdict = payload;
        continue;
      }
      if (event.kind === "DraftVerdict") draftVerdicts.push(payload);
      else if (event.kind === "Conflict") conflicts.push(payload);
      else if (event.kind === "RecheckRequest") recheckRequests.push(payload);
      else if (event.kind === "CriticDecision") criticDecisions.push(payload);
      else if (event.kind === "Verdict") verdict = payload;
      else if (event.kind === "Priority") priority = payload;
      else if (event.kind === "Escalation") escalations.push(payload);
      else if (event.kind === "Placement") placement = payload;
    }
    const history = [...earlier.entries()]
      .map(([runId, bucket]) => ({
        run_id: runId,
        order: this.runs.get(runId)?.order ?? -1,
        placement: bucket.placement?.placement ?? null,
        verdict: (bucket.verdict?.verdict as string | undefined) ?? (cardOf(bucket.placement)?.verdict as string | undefined) ?? null,
        resolution: (bucket.verdict?.resolution as string | undefined) ?? (cardOf(bucket.placement)?.resolution as string | undefined) ?? null,
        reused_from: bucket.placement?.reused_from ?? null,
        rechecks: bucket.rechecks.map((item) => ({ round: item.round, reason: item.reason, to: item.to })),
        critic: bucket.critic.map((item) => ({ round: item.round, decision: item.decision, reason: item.reason })),
        fingerprint: bucket.placement?.fingerprint ?? null,
      }))
      .filter((item) => item.placement !== null || item.verdict !== null || item.rechecks.length > 0)
      .sort((a, b) => b.order - a.order)
      .map(({ order: _order, ...rest }) => rest);
    let prior: Payload | null = null;
    let priorOrder = -Infinity;
    for (const [runId, bucket] of earlier.entries()) {
      if (bucket.placement === null) continue;
      const order = this.runs.get(runId)?.order ?? -1;
      if (order > priorOrder) {
        prior = bucket.placement;
        priorOrder = order;
      }
    }
    return {
      case_id: caseId,
      run_id: current,
      claims: [...claims.values()],
      alias_links: this.aliasEvents.filter((event) => aliasTouches(caseId, event.payload)).map((event) => event.payload),
      source_map: sourceMap,
      draft_verdicts: draftVerdicts,
      conflicts,
      recheck_requests: recheckRequests,
      critic_decisions: criticDecisions,
      verdict,
      priority,
      escalations,
      placement,
      prior,
      history,
    };
  }

  /** Runs, oldest first, with what opened and closed them. */
  listRuns(): { run_id: string; opened: Payload | null; closed: Payload | null }[] {
    return [...this.runs.values()]
      .sort((a, b) => a.order - b.order)
      .map((run) => ({ run_id: run.runId, opened: run.opened, closed: run.closed }));
  }

  /**
   * The report view: one run's placements as the report the API and the
   * exports serve. With no run id, the latest closed run.
   */
  report(runId?: string): Record<string, unknown> | null {
    let run: RunRecord | undefined;
    if (runId !== undefined && runId !== "") run = this.runs.get(runId);
    else {
      for (const candidate of this.runs.values()) {
        if (candidate.closed === null) continue;
        if (run === undefined || candidate.order > run.order) run = candidate;
      }
    }
    if (run === undefined) return null;
    const ranked: Payload[] = [];
    const closed: Payload[] = [];
    const needsHuman: Payload[] = [];
    const reused: string[] = [];
    for (const event of this.events) {
      if (event.kind !== "Placement" || runOf(event.payload) !== run.runId) continue;
      const card = { ...(cardOf(event.payload) ?? {}), reused_from: event.payload.reused_from ?? null };
      if (event.payload.reused_from) reused.push(String(event.payload.case_id));
      const where = event.payload.placement;
      if (where === "ranked") ranked.push(card);
      else if (where === "closed") closed.push(card);
      else needsHuman.push(card);
    }
    ranked.sort((a, b) => Number(b.score ?? 0) - Number(a.score ?? 0));
    const ending = run.closed ?? {};
    return {
      run_id: run.runId,
      state: ending.state ?? "RUNNING",
      partial: Boolean(ending.partial),
      degraded: Boolean(ending.degraded),
      unprocessed: ending.unprocessed ?? [],
      ranked,
      closed,
      needs_human: needsHuman,
      reused,
      receipts: ending.receipts ?? { zetaris: [], llm: [] },
      ingest: ending.ingest ?? null,
    };
  }

  /**
   * Current case state: each case's latest placement, kept only while the
   * latest run that covered its service still placed it. A run covers the
   * services in `RunOpened.services`, or every service when that is null.
   */
  currentCases(): Payload[] {
    const latestCover = new Map<string, number>();
    let latestAll = -1;
    for (const run of this.runs.values()) {
      if (run.closed === null || run.closed.state !== "DONE") continue;
      const services = run.opened?.services;
      if (Array.isArray(services)) {
        for (const name of services) latestCover.set(String(name), Math.max(latestCover.get(String(name)) ?? -1, run.order));
      } else latestAll = Math.max(latestAll, run.order);
    }
    const latest = new Map<string, { payload: Payload; order: number }>();
    for (const event of this.events) {
      if (event.kind !== "Placement") continue;
      const run = this.runs.get(runOf(event.payload));
      if (run === undefined || run.closed === null || run.closed.state !== "DONE") continue;
      const caseId = String(event.payload.case_id);
      const seen = latest.get(caseId);
      if (seen === undefined || run.order >= seen.order) latest.set(caseId, { payload: event.payload, order: run.order });
    }
    const found: Payload[] = [];
    for (const [caseId, item] of latest.entries()) {
      const service = serviceOf(caseId);
      const cover = Math.max(latestAll, latestCover.get(service) ?? -1);
      if (item.order < cover) continue;
      found.push({
        case_id: caseId,
        service_id: service,
        run_id: runOf(item.payload),
        placement: item.payload.placement,
        reused_from: item.payload.reused_from ?? null,
        card: cardOf(item.payload) ?? {},
      });
    }
    return found.sort((a, b) => (String(a.case_id) < String(b.case_id) ? -1 : 1));
  }

  private doUpsert(input: UpsertEntity, replaying = false): { id: string; changed: boolean } {
    if (!input.source?.kind) throw new Error("provenance required");
    if (!input.externalKey && !input.name) throw new Error("name or externalKey required");
    const id = input.externalKey
      ? externalEntityId(input.type, input.externalKey.system, input.externalKey.id)
      : entityIdFromName(input.type, input.name ?? "");
    const next: EntityRecord = {
      id,
      type: input.type,
      name: input.name ?? id,
      attrs: input.attrs ?? {},
      source: input.source,
    };
    const prev = this.entities.get(id);
    if (prev && canonicalJson(prev) === canonicalJson(next)) return { id, changed: false };
    this.entities.set(id, next);
    this.record("upsert", id, input.source.at);
    this.writeLog("upsert", input as Payload, replaying);
    return { id, changed: true };
  }

  private doIngest(observations: ObservationInput[], replaying = false): IngestReport {
    let changed = false;
    let skippedUnchanged = 0;
    const logged: ObservationInput[] = [];
    for (const raw of observations) {
      const mentions = raw.entities ?? [];
      const entityIds = mentions
        .map((entity) => {
          const id = entityIdFromName(entity.type, entity.name);
          if (!this.entities.has(id)) {
            this.entities.set(id, {
              id,
              type: entity.type,
              name: entity.name,
              attrs: {},
              source: raw.source,
            });
            this.record("upsert", id, raw.source?.at);
            changed = true;
          }
          return id;
        })
        .sort();
      const stored: ObservationRecord = {
        externalId: raw.externalId,
        title: raw.title,
        at: raw.at,
        source: raw.source,
        entityIds,
        hash: "",
      };
      stored.hash = sha16(
        canonicalJson({
          externalId: stored.externalId,
          title: stored.title,
          at: stored.at,
          source: stored.source,
          entityIds: stored.entityIds,
        }),
      );
      const previous = this.observations.get(raw.externalId);
      if (previous && previous.hash === stored.hash) {
        skippedUnchanged += 1;
        continue;
      }
      this.observations.set(raw.externalId, stored);
      this.record(previous ? "update" : "ingest", raw.externalId, raw.at);
      logged.push(raw);
      changed = true;
    }
    if (logged.length > 0) this.writeLog("ingest", { observations: logged }, replaying);
    return {
      changed,
      processed: observations.length,
      clusters: this.clusterCount(),
      skippedUnchanged,
    };
  }

  private doRelate(input: RelateInput, replaying = false): { id: string; changed: boolean } {
    if (!input.source?.kind) throw new Error("provenance required");
    const validFrom = input.validFrom ?? input.source.at ?? null;
    const id = `rel_${sha16(canonicalJson({ from: input.from, type: input.type, to: input.to, validFrom }))}`;
    if (this.edges.has(id)) return { id, changed: false };
    for (const edge of this.edges.values()) {
      // The same target already open in this slot: nothing changed.
      if (edge.from === input.from && edge.type === input.type && edge.slot === input.slot && edge.validTo === null && edge.to === input.to && input.slot !== undefined) {
        return { id: edge.id, changed: false };
      }
    }
    for (const edge of this.edges.values()) {
      if (edge.from === input.from && edge.type === input.type && edge.slot === input.slot && edge.validTo === null && edge.id !== id) {
        edge.validTo = validFrom;
      }
    }
    const edge: EdgeRecord = {
      id,
      from: input.from,
      type: input.type,
      to: input.to,
      validFrom,
      validTo: null,
      source: input.source,
    };
    if (input.slot !== undefined) edge.slot = input.slot;
    this.edges.set(id, edge);
    this.record("relate", id, input.source.at);
    this.writeLog("relate", input as Payload, replaying);
    return { id, changed: true };
  }

  private doUnrelate(input: UnrelateInput, replaying = false): { id: string | null; changed: boolean } {
    if (!input.source?.kind) throw new Error("provenance required");
    for (const edge of this.edges.values()) {
      if (edge.from === input.from && edge.type === input.type && edge.slot === input.slot && edge.validTo === null) {
        edge.validTo = input.validTo;
        this.record("unrelate", edge.id, input.source.at);
        this.writeLog("unrelate", input as Payload, replaying);
        return { id: edge.id, changed: true };
      }
    }
    return { id: null, changed: false };
  }

  private doApply(kind: MessageKind, payload: Payload, replaying = false): ApplyResult {
    let id = `evt_${sha16(canonicalJson({ kind, payload }))}`;
    const key = kind === "Claim" ? `claim|${claimKey(payload)}` : kind === "SourceMap" ? `map|${String(payload.case_id ?? "")}` : null;
    if (key !== null) {
      const now = canonicalJson(payload);
      if (this.keyed.get(key) === now) return { changed: false, ids: [] };
      // A value that comes back after a change is a new event, not a duplicate.
      if (this.eventIds.has(id)) id = `evt_${sha16(canonicalJson({ kind, payload, seq: this.seq + 1 }))}`;
      this.keyed.set(key, now);
    } else if (this.eventIds.has(id)) {
      return { changed: false, ids: [] };
    }
    const at = typeof payload.retrieved_at === "string" && payload.retrieved_at !== "" ? payload.retrieved_at : this.now();
    for (const entityId of entityIdsIn(payload)) {
      if (this.entities.has(entityId)) continue;
      const type = entityId.slice(0, entityId.indexOf(":")) || "entity";
      this.entities.set(entityId, {
        id: entityId,
        type,
        name: entityId,
        attrs: {},
        source: { kind: "sibyl", at },
      });
      this.record("ensure", entityId, at);
    }
    const event: DomainEvent = { id, kind, payload };
    this.events.push(event);
    this.eventIds.add(id);
    this.index(event);
    this.record(kind, id, at);
    this.writeLog("apply", { kind, payload }, replaying);
    return { changed: true, ids: [id] };
  }

  private index(event: DomainEvent): void {
    const payload = event.payload;
    if (event.kind === "AliasLink") {
      this.aliasEvents.push(event);
      return;
    }
    if (event.kind === "RunOpened" || event.kind === "RunClosed") {
      const runId = runOf(payload);
      const run = this.runs.get(runId) ?? { runId, order: this.runs.size, opened: null, closed: null };
      if (event.kind === "RunOpened") run.opened = payload;
      else run.closed = payload;
      this.runs.set(runId, run);
      return;
    }
    const runId = runOf(payload);
    if (runId !== "" && !this.runs.has(runId)) this.runs.set(runId, { runId, order: this.runs.size, opened: null, closed: null });
    const caseId = typeof payload.case_id === "string" ? payload.case_id : "";
    if (caseId === "") return;
    const list = this.byCase.get(caseId);
    if (list) list.push(event);
    else this.byCase.set(caseId, [event]);
  }

  private neighborsOf(id: string, options?: { via?: string; at?: string }): Neighbor[] {
    const found: Neighbor[] = [];
    for (const edge of this.edges.values()) {
      if (edge.from !== id) continue;
      if (options?.via && edge.type !== options.via) continue;
      if (!edgeActive(edge, options?.at)) continue;
      found.push({ id: edge.to });
    }
    return found;
  }

  private clusterCount(): number {
    return this.clusterGroups().length;
  }

  private clusterGroups(): string[][] {
    const ids = [...this.observations.keys()];
    const parent = new Map(ids.map((id) => [id, id]));
    const find = (value: string): string => {
      const current = parent.get(value);
      if (current === undefined || current === value) return value;
      const root = find(current);
      parent.set(value, root);
      return root;
    };
    const firstWith = new Map<string, string>();
    for (const observation of this.observations.values()) {
      for (const entityId of observation.entityIds) {
        const other = firstWith.get(entityId);
        if (other === undefined) firstWith.set(entityId, observation.externalId);
        else parent.set(find(observation.externalId), find(other));
      }
    }
    const groups = new Map<string, string[]>();
    for (const id of ids) {
      const root = find(id);
      const group = groups.get(root);
      if (group) group.push(id);
      else groups.set(root, [id]);
    }
    return [...groups.values()]
      .map((group) => group.sort())
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  }

  private enqueue<T>(fn: () => T): Promise<T> {
    const run = this.tail.then(() => fn());
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  private writeLog(op: LogEntry["op"], input: Payload, replaying: boolean): void {
    if (replaying) return;
    this.logSeq += 1;
    this.pendingLog.push({ seq: this.logSeq, v: LOG_SCHEMA_VERSION, op, at: this.now(), input });
  }

  private record(action: string, target: string, at?: string): void {
    this.seq += 1;
    this.auditLog.push({ seq: this.seq, action, target, at: at || this.now() });
  }

  private now(): string {
    return this.replayAt ?? this.clock().toISOString();
  }
}

function edgeActive(edge: EdgeRecord, at: string | undefined): boolean {
  if (at === undefined) return edge.validTo === null;
  if (edge.validFrom !== null && edge.validFrom > at) return false;
  if (edge.validTo !== null && edge.validTo <= at) return false;
  return true;
}

function claimKey(payload: Payload): string {
  return [payload.case_id, payload.source, payload.field, payload.raw_ref].map((part) => String(part ?? "")).join("|");
}

function runOf(payload: Payload): string {
  return typeof payload.run_id === "string" ? payload.run_id : "";
}

function cardOf(payload: Payload | null): Payload | null {
  if (payload === null) return null;
  const card = payload.card;
  return card !== null && typeof card === "object" ? (card as Payload) : null;
}

/** `case:<service>:<purl>:<vuln>` names its service second. */
function serviceOf(caseId: string): string {
  const parts = caseId.split(":");
  return parts.length > 1 ? parts[1] : "";
}

function entityIdsIn(payload: Record<string, unknown>): string[] {
  const ids = new Set<string>();
  for (const key of ["case_id", "vuln_id", "alias_id"]) {
    const value = payload[key];
    if (typeof value === "string" && value.includes(":")) ids.add(value);
  }
  const source = payload.source;
  if (typeof source === "string" && source !== "") {
    ids.add(source.startsWith("source:") ? source : `source:${source}`);
  }
  return [...ids];
}

function aliasTouches(caseId: string, payload: Record<string, unknown>): boolean {
  const vuln = typeof payload.vuln_id === "string" ? payload.vuln_id : "";
  const alias = typeof payload.alias_id === "string" ? payload.alias_id : "";
  return (vuln !== "" && caseId.includes(vuln)) || (alias !== "" && caseId.includes(alias));
}

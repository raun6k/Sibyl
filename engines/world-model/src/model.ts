/**
 * Sibyl's World Model.
 *
 * Event-sourced, in-memory, one writer at a time. This is not the
 * Meterless reference. The conformance runner is the contract: stable
 * ids, merge bands, provenance, idempotent ingest, bitemporal edges,
 * and an ordered audit log.
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
};

export type AuditEntry = { seq: number; action: string; target: string; at: string };

export type Neighbor = { id: string };

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

type EdgeRecord = {
  id: string;
  from: string;
  type: string;
  to: string;
  validFrom: string | null;
  validTo: string | null;
  source: SourceRef;
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
] as const;

export type MessageKind = (typeof MESSAGE_KINDS)[number];

export type ApplyResult = { changed: boolean; ids: string[] };

type DomainEvent = {
  id: string;
  kind: MessageKind;
  payload: Record<string, unknown>;
};

export class WorldModel {
  readonly schemaVersion = 1;
  readonly namespace: string;
  private readonly clock: () => Date;
  private readonly entities = new Map<string, EntityRecord>();
  private readonly observations = new Map<string, ObservationRecord>();
  private readonly edges = new Map<string, EdgeRecord>();
  private readonly events: DomainEvent[] = [];
  private readonly eventIds = new Set<string>();
  private readonly auditLog: AuditEntry[] = [];
  private seq = 0;
  private tail: Promise<void> = Promise.resolve();

  constructor(options: { storage: "memory"; namespace: string; clock?: () => Date }) {
    if (options.storage !== "memory") {
      throw new Error(`unsupported storage ${options.storage}`);
    }
    this.namespace = options.namespace;
    this.clock = options.clock ?? (() => new Date());
  }

  upsertEntity(input: UpsertEntity): Promise<{ id: string; changed: boolean }> {
    return this.enqueue(() => {
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
      return { id, changed: true };
    });
  }

  ingest(observations: ObservationInput[]): Promise<IngestReport> {
    return this.enqueue(() => {
      let changed = false;
      let skippedUnchanged = 0;
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
        changed = true;
      }
      return {
        changed,
        processed: observations.length,
        clusters: this.clusterCount(),
        skippedUnchanged,
      };
    });
  }

  relate(input: RelateInput): Promise<{ id: string; changed: boolean }> {
    return this.enqueue(() => {
      if (!input.source?.kind) throw new Error("provenance required");
      const validFrom = input.validFrom ?? input.source.at ?? null;
      const id = `rel_${sha16(canonicalJson({ from: input.from, type: input.type, to: input.to, validFrom }))}`;
      if (this.edges.has(id)) return { id, changed: false };
      for (const edge of this.edges.values()) {
        if (edge.from === input.from && edge.type === input.type && edge.validTo === null && edge.id !== id) {
          edge.validTo = validFrom;
        }
      }
      this.edges.set(id, {
        id,
        from: input.from,
        type: input.type,
        to: input.to,
        validFrom,
        validTo: null,
        source: input.source,
      });
      this.record("relate", id, input.source.at);
      return { id, changed: true };
    });
  }

  /**
   * Append one Sibyl message. The same canonical payload is an empty diff.
   * Stable ids named by the payload (`case:`, `vuln:`, `source:`, …) are
   * registered the first time they appear.
   */
  apply(kind: MessageKind, payload: Record<string, unknown>): Promise<ApplyResult> {
    return this.enqueue(() => {
      const id = `evt_${sha16(canonicalJson({ kind, payload }))}`;
      if (this.eventIds.has(id)) return { changed: false, ids: [] };
      const at = typeof payload.retrieved_at === "string" ? payload.retrieved_at : this.now();
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
      this.events.push({ id, kind, payload });
      this.eventIds.add(id);
      this.record(kind, id, at);
      return { changed: true, ids: [id] };
    });
  }

  view(name: string): { neighborsOf: (id: string, options?: { via?: string; at?: string }) => Neighbor[] } {
    if (name !== "graph") throw new Error(`unknown view ${name}`);
    return {
      neighborsOf: (id, options) => this.neighborsOf(id, options),
    };
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

  /** Current projection of one case. Lists keep every event; singletons keep the latest. */
  projectCase(caseId: string): Record<string, unknown> {
    const claims: Record<string, unknown>[] = [];
    const aliasLinks: Record<string, unknown>[] = [];
    const draftVerdicts: Record<string, unknown>[] = [];
    const conflicts: Record<string, unknown>[] = [];
    const recheckRequests: Record<string, unknown>[] = [];
    const criticDecisions: Record<string, unknown>[] = [];
    const escalations: Record<string, unknown>[] = [];
    let sourceMap: Record<string, unknown> | null = null;
    let verdict: Record<string, unknown> | null = null;
    let priority: Record<string, unknown> | null = null;
    for (const event of this.events) {
      const payload = event.payload;
      if (event.kind === "AliasLink") {
        if (aliasTouches(caseId, payload)) aliasLinks.push(payload);
        continue;
      }
      if (payload.case_id !== caseId) continue;
      if (event.kind === "Claim") claims.push(payload);
      else if (event.kind === "SourceMap") sourceMap = payload;
      else if (event.kind === "DraftVerdict") draftVerdicts.push(payload);
      else if (event.kind === "Conflict") conflicts.push(payload);
      else if (event.kind === "RecheckRequest") recheckRequests.push(payload);
      else if (event.kind === "CriticDecision") criticDecisions.push(payload);
      else if (event.kind === "Verdict") verdict = payload;
      else if (event.kind === "Priority") priority = payload;
      else if (event.kind === "Escalation") escalations.push(payload);
    }
    return {
      case_id: caseId,
      claims,
      alias_links: aliasLinks,
      source_map: sourceMap,
      draft_verdicts: draftVerdicts,
      conflicts,
      recheck_requests: recheckRequests,
      critic_decisions: criticDecisions,
      verdict,
      priority,
      escalations,
    };
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

  private record(action: string, target: string, at?: string): void {
    this.seq += 1;
    this.auditLog.push({ seq: this.seq, action, target, at: at || this.now() });
  }

  private now(): string {
    return this.clock().toISOString();
  }
}

function edgeActive(edge: EdgeRecord, at: string | undefined): boolean {
  if (at === undefined) return edge.validTo === null;
  if (edge.validFrom !== null && edge.validFrom > at) return false;
  if (edge.validTo !== null && edge.validTo <= at) return false;
  return true;
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

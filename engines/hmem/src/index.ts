/**
 * Sibyl H-MEM.
 *
 * Conformance target for HMEM_IMPL. The runner constructs `new HMEM({ clock })`
 * and writes `supersededBy` on the object `add()` returned, so the store keeps
 * that object. No runtime dependencies. This is not the Meterless reference.
 */

export type MemoryType = "personal" | "factual" | "preference" | "general";
export type MemoryLayer = "short_term" | "working" | "long_term";
export type FeedbackKind = "helpful" | "not_helpful" | "wrong";

export interface Provenance {
  origin: string;
  learnedAt: number;
  label: string;
}

export interface MemoryEntity {
  name: string;
  type: string;
}

export interface Memory {
  id: string;
  content: string;
  type: MemoryType;
  layer: MemoryLayer;
  timestamp: number;
  lastAccessed: number;
  accessCount: number;
  tags: string[];
  confidence: number;
  source: string;
  provenance: Provenance;
  embedding: number[];
  entities: MemoryEntity[];
  relatedTo: string[];
  supersedes?: string;
  supersededBy?: string;
  derivedFrom: string[];
  domain: string;
  namespace: string;
  score?: number;
}

export interface AddInput {
  content: string;
  source: string;
  confidence?: number;
  layer?: MemoryLayer;
  type?: MemoryType;
  tags?: string[];
  derivedFrom?: string[];
  domain?: string;
  entities?: MemoryEntity[];
}

export interface LedgerEntry {
  memoryId: string;
  action: string;
  actor: string;
  timestamp: number;
  previousState?: { confidence?: number } | null;
  newState?: { confidence?: number } | null;
  details?: Record<string, unknown>;
}

export interface SleepPreview {
  toConsolidate: string[];
  toArchive: string[];
  toSynthesize: string[];
}

export interface SleepReport {
  backupId: string;
  archived: number;
  consolidated: number;
  synthesized: number;
}

export interface ConflictRecord {
  id: string;
  a: string;
  b: string;
  reason: string;
  confidence: number;
}

export interface DreamProposal {
  id: string;
  kind: "insight" | "invariant" | "domain";
  content: string;
  sourceIds: string[];
}

const DAY = 24 * 60 * 60 * 1000;
const DIM = 32;
const OPPOSITES: ReadonlyArray<readonly [string, string]> = [
  ["always", "never"],
  ["enable", "disable"],
  ["enabled", "disabled"],
  ["allow", "forbid"],
  ["allow", "deny"],
];

function clamp01(value: number): number {
  const clamped = Math.min(1, Math.max(0, value));
  return Math.round(clamped * 1e10) / 1e10;
}

function tokens(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length > 0);
}

function embed(text: string): number[] {
  const vector = new Array<number>(DIM).fill(0);
  for (const token of tokens(text)) {
    let hash = 2166136261;
    for (let index = 0; index < token.length; index += 1) {
      hash = Math.imul(hash ^ token.charCodeAt(index), 16777619);
    }
    vector[Math.abs(hash) % DIM] += 1;
  }
  let norm = 0;
  for (const value of vector) norm += value * value;
  norm = Math.sqrt(norm);
  if (norm === 0) return vector;
  return vector.map((value) => value / norm);
}

function cosine(left: number[], right: number[]): number {
  let sum = 0;
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) sum += left[index] * right[index];
  return clamp01(sum);
}

function jaccard(left: string[], right: string[]): number {
  const a = new Set(left);
  const b = new Set(right);
  if (a.size === 0 && b.size === 0) return 0;
  let intersection = 0;
  for (const token of a) if (b.has(token)) intersection += 1;
  const union = a.size + b.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

function top8(words: string[]): string[] {
  return words.slice(0, 8);
}

function opposes(left: string, right: string): boolean {
  const a = new Set(tokens(left));
  const b = new Set(tokens(right));
  return OPPOSITES.some(([one, other]) => (a.has(one) && b.has(other)) || (a.has(other) && b.has(one)));
}

export class MemoryStoreService {
  private records = new Map<string, Memory>();

  put(memory: Memory): Memory {
    this.records.set(memory.id, memory);
    return memory;
  }

  get(id: string): Memory | undefined {
    return this.records.get(id);
  }

  all(): Memory[] {
    return [...this.records.values()];
  }

  delete(id: string): void {
    this.records.delete(id);
  }

  replace(records: Memory[]): void {
    this.records.clear();
    for (const memory of records) this.records.set(memory.id, memory);
  }
}

export class TrustLedgerService {
  private entries: LedgerEntry[] = [];

  append(entry: LedgerEntry): void {
    this.entries.push(entry);
  }

  history(memoryId: string): LedgerEntry[] {
    return this.entries.filter((entry) => entry.memoryId === memoryId);
  }

  all(): LedgerEntry[] {
    return [...this.entries];
  }

  replace(entries: LedgerEntry[]): void {
    this.entries = [...entries];
  }
}

export class HMEM {
  readonly store = new MemoryStoreService();
  readonly ledger = new TrustLedgerService();
  readonly sleep: SleepCycleService;
  readonly dreaming: DreamingService;
  readonly conflicts: ConflictDetectionService;
  readonly clock: () => number;
  private seq = 0;
  private dir: string | undefined;

  constructor(options: { clock?: () => number; dir?: string } = {}) {
    this.clock = options.clock ?? (() => Date.now());
    this.dir = options.dir;
    this.sleep = new SleepCycleService(this);
    this.dreaming = new DreamingService(this);
    this.conflicts = new ConflictDetectionService(this);
  }

  rememberDir(dir: string | undefined): void {
    this.dir = dir;
  }

  storageDir(): string | undefined {
    return this.dir;
  }

  add(input: AddInput): Memory {
    const source = typeof input.source === "string" ? input.source.trim() : "";
    if (!source) throw new Error("a record with no source is rejected");
    const content = typeof input.content === "string" ? input.content : "";
    if (!content.trim()) throw new Error("a record with no content is rejected");
    const now = this.clock();
    const memory: Memory = {
      id: `mem_${(this.seq += 1).toString(36)}_${Math.abs(now).toString(36)}`,
      content,
      type: input.type ?? "general",
      layer: input.layer ?? "working",
      timestamp: now,
      lastAccessed: now,
      accessCount: 0,
      tags: [...(input.tags ?? [])],
      confidence: clamp01(input.confidence ?? 0.7),
      source,
      provenance: { origin: "direct", learnedAt: now, label: source },
      embedding: embed(content),
      entities: [...(input.entities ?? [])].slice(0, 10),
      relatedTo: [],
      derivedFrom: [...(input.derivedFrom ?? [])],
      domain: input.domain ?? domainOf(content, input.tags ?? [], input.type ?? "general"),
      namespace: "sibyl/memory",
    };
    this.store.put(memory);
    this.ledger.append({
      memoryId: memory.id,
      action: "create",
      actor: source,
      timestamp: now,
      previousState: null,
      newState: { confidence: memory.confidence },
    });
    return memory;
  }

  feedback(id: string, kind: FeedbackKind): Memory {
    const memory = this.store.get(id);
    if (!memory) throw new Error(`unknown memory ${id}`);
    const previous = memory.confidence;
    if (kind === "helpful") {
      memory.accessCount += 1;
      memory.confidence = clamp01(memory.confidence + 0.05);
    } else if (kind === "not_helpful") {
      memory.confidence = clamp01(memory.confidence - 0.03);
    } else if (kind === "wrong") {
      memory.confidence = clamp01(memory.confidence - 0.2);
      if (!memory.tags.includes("review")) memory.tags.push("review");
    } else {
      throw new Error(`unknown feedback ${kind}`);
    }
    memory.lastAccessed = this.clock();
    this.ledger.append({
      memoryId: memory.id,
      action: "feedback",
      actor: "user",
      timestamp: this.clock(),
      previousState: { confidence: previous },
      newState: { confidence: memory.confidence },
      details: { kind },
    });
    return memory;
  }

  query(text: string, options: { threshold?: number; topN?: number } = {}): { memories: { memory: Memory; score: number }[]; strategy: string } {
    const threshold = options.threshold ?? 0.35;
    const topN = options.topN ?? 5;
    const now = this.clock();
    const queryEmbedding = embed(text);
    const queryTokens = tokens(text);
    const ranked = this.store
      .all()
      .map((memory) => ({ memory, score: rank(memory, text, queryEmbedding, queryTokens, now) }))
      .filter((item) => item.score >= threshold)
      .sort((left, right) => right.score - left.score || (left.memory.timestamp - right.memory.timestamp));
    return { memories: ranked.slice(0, topN), strategy: "comprehensive" };
  }
}

function domainOf(content: string, tags: string[], type: string): string {
  const tagged = tags.find((tag) => tag.startsWith("domain:"));
  if (tagged) return tagged.slice("domain:".length);
  if (type === "preference" || type === "personal") return "preference";
  if (/\b(deploy|docker|api)\b/i.test(content)) return "engineering";
  return "general";
}

function rank(memory: Memory, query: string, queryEmbedding: number[], queryTokens: string[], now: number): number {
  const semantic = cosine(memory.embedding, queryEmbedding);
  const keyword = jaccard(top8(queryTokens), tokens(memory.content));
  const tag = jaccard(queryTokens, memory.tags.map((tag) => tag.toLowerCase()));
  const domain = domainOf(query, [], "general") === memory.domain ? 1 : 0;
  const entityNames = memory.entities.map((entity) => entity.name.toLowerCase());
  const entity = jaccard(queryTokens, entityNames);
  const layer = memory.layer === "long_term" ? 1 : memory.layer === "working" ? 0.8 : 0.6;
  const age = Math.max(0, now - memory.lastAccessed);
  const recency = Math.exp(-age / (14 * DAY));
  const superseded = memory.supersededBy ? 1 : 0;
  const raw =
    0.35 * semantic +
    0.2 * keyword +
    0.1 * tag +
    0.1 * domain +
    0.15 * entity +
    0.05 * layer +
    0.05 * recency -
    0.2 * superseded;
  const score = clamp01(raw) * memory.confidence;
  memory.score = score;
  return score;
}

export class SleepCycleService {
  private backups = new Map<string, Memory[]>();

  constructor(private readonly hmem: HMEM) {}

  preview(): SleepPreview {
    const now = this.hmem.clock();
    const records = this.hmem.store.all();
    const protectedIds = guardrailIds(records);
    const toArchive: string[] = [];
    const toConsolidate: string[] = [];
    for (const memory of records) {
      const ageDays = (now - memory.timestamp) / DAY;
      const stale = now - memory.lastAccessed >= 7 * DAY;
      if (memory.layer === "short_term" && stale && !protectedIds.has(memory.id)) toConsolidate.push(memory.id);
      if (protectedIds.has(memory.id)) continue;
      if (ageDays >= 30 && memory.accessCount <= 2) toArchive.push(memory.id);
    }
    return { toConsolidate, toArchive, toSynthesize: [] };
  }

  execute(preview: SleepPreview): SleepReport {
    const backupId = `bak_${this.hmem.clock().toString(36)}_${(this.backups.size + 1).toString(36)}`;
    this.backups.set(
      backupId,
      this.hmem.store.all().map((memory) => ({ ...memory, tags: [...memory.tags], derivedFrom: [...memory.derivedFrom] })),
    );
    const protectedIds = guardrailIds(this.hmem.store.all());
    let archived = 0;
    for (const id of preview.toArchive) {
      if (protectedIds.has(id)) continue;
      if (!this.hmem.store.get(id)) continue;
      this.hmem.store.delete(id);
      archived += 1;
      this.hmem.ledger.append({
        memoryId: id,
        action: "sleep_archive",
        actor: "sleep",
        timestamp: this.hmem.clock(),
      });
    }
    let consolidated = 0;
    for (const id of preview.toConsolidate) {
      const memory = this.hmem.store.get(id);
      if (!memory || memory.layer !== "short_term") continue;
      memory.layer = "long_term";
      consolidated += 1;
      this.hmem.ledger.append({
        memoryId: id,
        action: "sleep_consolidate",
        actor: "sleep",
        timestamp: this.hmem.clock(),
      });
    }
    return { backupId, archived, consolidated, synthesized: 0 };
  }
}

function guardrailIds(records: Memory[]): Set<string> {
  const protectedIds = new Set<string>();
  const referenced = new Set<string>();
  for (const memory of records) {
    if ((memory.derivedFrom ?? []).length > 0 || memory.source === "dreaming") protectedIds.add(memory.id);
    if (memory.supersedes) protectedIds.add(memory.id);
    if (memory.relatedTo.length >= 3) protectedIds.add(memory.id);
    for (const id of memory.relatedTo) referenced.add(id);
    for (const id of memory.derivedFrom) referenced.add(id);
    if (memory.supersedes) referenced.add(memory.supersedes);
  }
  for (const id of referenced) protectedIds.add(id);
  return protectedIds;
}

export class ConflictDetectionService {
  constructor(private readonly hmem: HMEM) {}

  scan(): ConflictRecord[] {
    const records = this.hmem.store.all();
    const found: ConflictRecord[] = [];
    for (let left = 0; left < records.length; left += 1) {
      for (let right = left + 1; right < records.length; right += 1) {
        const a = records[left];
        const b = records[right];
        if (a.supersededBy || b.supersededBy) continue;
        if (a.supersedes === b.id || b.supersedes === a.id) continue;
        if (!opposes(a.content, b.content)) continue;
        if (jaccard(tokens(a.content), tokens(b.content)) < 0.35) continue;
        const gap = Math.abs(a.confidence - b.confidence);
        found.push({
          id: `conf_${a.id}_${b.id}`,
          a: a.id,
          b: b.id,
          reason: "opposing phrase pair",
          confidence: clamp01(gap + 0.25),
        });
      }
    }
    return found;
  }

  autoResolve(conflict: ConflictRecord): "resolved" | "queued" {
    const a = this.hmem.store.get(conflict.a);
    const b = this.hmem.store.get(conflict.b);
    if (!a || !b) return "queued";
    this.hmem.ledger.append({
      memoryId: a.id,
      action: "conflict_detected",
      actor: "conflicts",
      timestamp: this.hmem.clock(),
      details: { other: b.id },
    });
    if (conflict.confidence < 0.7) return "queued";
    const winner = a.confidence >= b.confidence ? a : b;
    const loser = winner === a ? b : a;
    if (loser.confidence > winner.confidence) return "queued";
    loser.supersededBy = winner.id;
    this.hmem.ledger.append({
      memoryId: loser.id,
      action: "conflict_resolved",
      actor: "conflicts",
      timestamp: this.hmem.clock(),
      previousState: { confidence: loser.confidence },
      newState: { confidence: loser.confidence },
      details: { supersededBy: winner.id, kept: winner.id },
    });
    return "resolved";
  }
}

export class DreamingService {
  private proposals: DreamProposal[] = [];

  constructor(private readonly hmem: HMEM) {}

  dream(): DreamProposal[] {
    const groups = new Map<string, Memory[]>();
    for (const memory of this.hmem.store.all()) {
      const bucket = groups.get(memory.type) ?? [];
      bucket.push(memory);
      groups.set(memory.type, bucket);
    }
    const proposals: DreamProposal[] = [];
    for (const [type, members] of groups) {
      if (members.length < 2) continue;
      const related = members.filter((memory, index) => index === 0 || relatedTo(members[0], memory));
      if (related.length < 2) continue;
      const kind = type === "preference" || type === "personal" ? "invariant" : "insight";
      proposals.push({
        id: `dream_${kind}_${members[0].id}`,
        kind,
        content: related.map((memory) => memory.content).join("; "),
        sourceIds: related.map((memory) => memory.id),
      });
    }
    this.proposals = proposals;
    for (const proposal of proposals) {
      this.hmem.ledger.append({
        memoryId: proposal.sourceIds[0] ?? "dream",
        action: "dream_proposed",
        actor: "dreaming",
        timestamp: this.hmem.clock(),
        details: { proposalId: proposal.id },
      });
    }
    return proposals;
  }

  approve(id: string): Memory | null {
    const proposal = this.proposals.find((item) => item.id === id);
    if (!proposal) return null;
    const created = this.hmem.add({
      content: proposal.content,
      type: proposal.kind === "invariant" ? "preference" : "factual",
      layer: "long_term",
      source: "dreaming",
      confidence: 0.8,
      derivedFrom: proposal.sourceIds,
      tags: ["dream"],
    });
    this.hmem.ledger.append({
      memoryId: created.id,
      action: "dream_approved",
      actor: "human",
      timestamp: this.hmem.clock(),
      newState: { confidence: created.confidence },
      details: { proposalId: proposal.id },
    });
    return created;
  }
}

function relatedTo(left: Memory, right: Memory): boolean {
  if (left.type === right.type && (left.type === "preference" || left.type === "personal")) return true;
  return jaccard(tokens(left.content), tokens(right.content)) >= 0.35;
}

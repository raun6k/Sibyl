/**
 * One long-lived World Model process per workspace. JSON objects, one per line, on stdin.
 * Replies on stdout. Writes are applied in arrival order.
 *
 * Every reply that changed state carries `log`: the write-log entries the
 * host must append to `world.events` before the next start. `replay` takes
 * those entries back, oldest first.
 */

import { writeSync } from "node:fs";
import { createInterface } from "node:readline";

import { MESSAGE_KINDS, WorldModel, type LogEntry, type MessageKind } from "./index.js";

// One process per workspace; WM_NAMESPACE names it.
const world = new WorldModel({ storage: "memory", namespace: process.env.WM_NAMESPACE || "sibyl" });
const kinds = new Set<string>(MESSAGE_KINDS);

type Request = { id?: string; method?: string; payload?: Record<string, unknown> };

function reply(message: Record<string, unknown>): void {
  const log = world.drainLog();
  if (log.length > 0) message.log = log;
  writeSync(1, `${JSON.stringify(message)}\n`);
}

async function handle(line: string): Promise<void> {
  let request: Request;
  try {
    request = JSON.parse(line) as Request;
  } catch {
    reply({ id: null, ok: false, error: "request was not JSON" });
    return;
  }
  const id = request.id ?? null;
  try {
    const result = await dispatch(request.method ?? "", request.payload ?? {});
    reply({ id, ok: true, result });
    if (request.method === "close") process.exit(0);
  } catch (err) {
    const error = err instanceof Error ? err.message : "world model error";
    reply({ id, ok: false, error });
  }
}

async function dispatch(method: string, payload: Record<string, unknown>): Promise<unknown> {
  if (method === "close") return { closed: true };
  if (method === "batch") {
    // Several writes in one round trip. A failing item fails the batch after the items before it.
    const items = payload.items;
    if (!Array.isArray(items)) throw new Error("items required");
    const results: unknown[] = [];
    for (const item of items as Request[]) {
      if (item.method === "batch" || item.method === "close" || item.method === "replay") throw new Error(`${item.method} cannot be batched`);
      results.push(await dispatch(item.method ?? "", item.payload ?? {}));
    }
    return results;
  }
  if (method === "replay") {
    const entries = payload.entries;
    if (!Array.isArray(entries)) throw new Error("entries required");
    return world.replay(entries as LogEntry[]);
  }
  if (method === "case") {
    const caseId = payload.case_id;
    if (typeof caseId !== "string" || caseId === "") throw new Error("case_id required");
    const runId = typeof payload.run_id === "string" ? payload.run_id : undefined;
    return world.projectCase(caseId, { runId });
  }
  if (method === "cases") {
    const ids = payload.case_ids;
    if (!Array.isArray(ids)) throw new Error("case_ids required");
    const runId = typeof payload.run_id === "string" ? payload.run_id : undefined;
    return ids.map((caseId) => world.projectCase(String(caseId), { runId }));
  }
  if (method === "ingest") {
    const observations = payload.observations;
    if (!Array.isArray(observations)) throw new Error("observations required");
    return world.ingest(observations as Parameters<WorldModel["ingest"]>[0]);
  }
  if (method === "relate") return world.relate(payload as Parameters<WorldModel["relate"]>[0]);
  if (method === "unrelate") return world.unrelate(payload as Parameters<WorldModel["unrelate"]>[0]);
  if (method === "edges") {
    const from = payload.from;
    if (typeof from !== "string" || from === "") throw new Error("from required");
    return world.edgesOf(from, {
      via: typeof payload.via === "string" ? payload.via : undefined,
      slot: typeof payload.slot === "string" ? payload.slot : undefined,
      at: typeof payload.at === "string" ? payload.at : undefined,
    });
  }
  if (method === "report") return world.report(typeof payload.run_id === "string" ? payload.run_id : undefined);
  if (method === "runs") return world.listRuns();
  if (method === "current_cases") return world.currentCases();
  const kind = methodToKind(method);
  if (!kind) throw new Error(`unknown method ${method}`);
  return world.apply(kind, payload);
}

function methodToKind(method: string): MessageKind | null {
  const named = method
    .split("_")
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : ""))
    .join("");
  return kinds.has(named) ? (named as MessageKind) : null;
}

let tail: Promise<void> = Promise.resolve();
const lines = createInterface({ input: process.stdin });
lines.on("line", (line) => {
  tail = tail.then(() => handle(line)).then(
    () => undefined,
    () => undefined,
  );
});

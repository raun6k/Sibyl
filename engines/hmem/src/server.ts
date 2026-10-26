/**
 * One long-lived H-MEM process. JSON objects, one per line, on stdin.
 * The store is `var/hmem/` (or HMEM_DIR) so it survives restarts.
 */

import { writeSync } from "node:fs";
import { createInterface } from "node:readline";
import path from "node:path";

import { openMemory, type FactInput, type ResolveInput, type SibylMemory } from "./sibyl.js";

const dir = process.env.HMEM_DIR
  ? path.resolve(process.env.HMEM_DIR)
  : path.resolve(process.cwd(), "var", "hmem");
const memory: SibylMemory = openMemory(dir);

type Request = { id?: string; method?: string; payload?: Record<string, unknown> };

function reply(message: unknown): void {
  writeSync(1, `${JSON.stringify(message)}\n`);
}

function handle(line: string): void {
  let request: Request;
  try {
    request = JSON.parse(line) as Request;
  } catch {
    reply({ id: null, ok: false, error: "request was not JSON" });
    return;
  }
  const id = request.id ?? null;
  try {
    const result = dispatch(request.method ?? "", request.payload ?? {});
    memory.save();
    reply({ id, ok: true, result });
    if (request.method === "close") process.exit(0);
  } catch (err) {
    const error = err instanceof Error ? err.message : "hmem error";
    reply({ id, ok: false, error });
  }
}

function dispatch(method: string, payload: Record<string, unknown>): unknown {
  if (method === "close") return { closed: true };
  if (method === "ping") return { ok: true, dir };
  if (method === "trust") {
    const source = String(payload.source ?? "");
    const field = String(payload.field ?? "affected_ranges");
    const ecosystem = String(payload.ecosystem ?? "*");
    return { weight: memory.trust(source, field, ecosystem) };
  }
  if (method === "resolve") return memory.resolve(payload as unknown as ResolveInput);
  if (method === "approve") return memory.approve(String(payload.id ?? ""));
  if (method === "reject") return memory.reject(String(payload.id ?? ""));
  if (method === "resolution_for") return { resolution: memory.resolutionFor(String(payload.case_id ?? "")) };
  if (method === "mapping_for") return { purl: memory.mappingFor(String(payload.product ?? "")) };
  if (method === "propose_mapping") {
    return {
      pending: memory.proposeMapping(String(payload.product ?? ""), String(payload.purl ?? ""), String(payload.reason ?? "")),
    };
  }
  if (method === "summary") {
    memory.addSummary({
      run_id: String(payload.run_id ?? ""),
      needs_human: Number(payload.needs_human ?? 0),
      ranked: Number(payload.ranked ?? 0),
      closed: Number(payload.closed ?? 0),
    });
    return { ok: true };
  }
  if (method === "fact") return memory.recordFact(payload as unknown as FactInput);
  if (method === "fact_for") {
    return { fact: memory.factFor(String(payload.service_id ?? ""), String(payload.field ?? "")) };
  }
  if (method === "facts") return { facts: memory.facts(String(payload.service_id ?? "")) };
  if (method === "forget_service") return { forgotten: memory.forgetService(String(payload.service_id ?? "")) };
  if (method === "snapshot") return memory.snapshot();
  if (method === "reset") {
    memory.reset();
    return { ok: true };
  }
  throw new Error(`unknown method ${method}`);
}

const lines = createInterface({ input: process.stdin });
lines.on("line", (line) => {
  if (line.trim()) handle(line);
});

/**
 * One long-lived World Model process. JSON objects, one per line, on stdin.
 * Replies on stdout. Writes are applied in arrival order.
 */

import { writeSync } from "node:fs";
import { createInterface } from "node:readline";

import { MESSAGE_KINDS, WorldModel, type MessageKind } from "./index.js";

const world = new WorldModel({ storage: "memory", namespace: "sibyl" });
const kinds = new Set<string>(MESSAGE_KINDS);

type Request = { id?: string; method?: string; payload?: Record<string, unknown> };

function reply(message: unknown): void {
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
  if (method === "case") {
    const caseId = payload.case_id;
    if (typeof caseId !== "string" || caseId === "") throw new Error("case_id required");
    return world.projectCase(caseId);
  }
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

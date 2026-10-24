/**
 * Stable ids and merge bands from the World Model contract.
 *
 * Name-keyed ids are `ent_` plus the first 16 hex chars of
 * sha256(`${type}:${normalizeName(name)}`). Normalization is
 * lowercase, NFKD, strip combining marks, collapse whitespace, trim.
 */

import { createHash } from "node:crypto";

export function normalizeName(name: string): string {
  const stripped = name.toLowerCase().normalize("NFKD").replace(/\p{M}/gu, "");
  return stripped.replace(/\s+/gu, " ").trim();
}

export function entityIdFromName(type: string, name: string): string {
  return `ent_${sha16(`${type}:${normalizeName(name)}`)}`;
}

export function externalEntityId(type: string, system: string, externalId: string): string {
  return `${type}:${system}:${externalId}`;
}

/** Similarity bands the conformance runner fixes: 0.85 auto, 0.82 review. */
export function decide(similarity: number): "auto-merge" | "review" | "new" {
  if (similarity >= 0.85) return "auto-merge";
  if (similarity >= 0.82) return "review";
  return "new";
}

export function sha16(text: string): string {
  return createHash("sha256").update(text).digest("hex").slice(0, 16);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) sorted[key] = sortValue(source[key]);
    return sorted;
  }
  return value;
}

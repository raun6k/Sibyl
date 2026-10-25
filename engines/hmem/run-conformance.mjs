/**
 * One command for the H-MEM conformance suite.
 *
 *   node engines/hmem/run-conformance.mjs
 *
 * Uses the typescript already installed under engines/. Does not install tsx.
 * Meterless is the sibling checkout ../Meterless, or $METERLESS_REPO.
 */

import { register } from "node:module";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..");
const meterless = process.env.METERLESS_REPO
  ? path.resolve(process.env.METERLESS_REPO)
  : path.resolve(repo, "..", "Meterless");
const runner = path.join(meterless, "engines", "hmem", "conformance", "runner.ts");
const impl = process.env.HMEM_IMPL
  ? path.resolve(process.env.HMEM_IMPL)
  : path.join(here, "src", "index.ts");

process.env.HMEM_IMPL = impl;
register(pathToFileURL(path.join(here, "..", "world-model", "hooks.mjs")));
await import(pathToFileURL(runner).href);

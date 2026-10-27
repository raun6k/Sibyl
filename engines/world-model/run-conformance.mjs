/**
 * One command for the World Model conformance suite.
 *
 *   node engines/world-model/run-conformance.mjs
 *
 * Uses the typescript already installed under engines/. Does not install tsx.
 * Uses the bundled upstream runner; $METERLESS_REPO optionally selects another checkout.
 */

import { register } from "node:module";
import path from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, "..", "..");
const runner = process.env.METERLESS_REPO
  ? path.resolve(process.env.METERLESS_REPO, "engines", "world-model", "conformance", "runner.ts")
  : path.join(repo, "engines", "conformance", "meterless", "world-model", "runner.ts");
const impl = process.env.WORLD_MODEL_IMPL
  ? path.resolve(process.env.WORLD_MODEL_IMPL)
  : path.join(here, "src", "index.ts");

process.env.WORLD_MODEL_IMPL = impl;
register(pathToFileURL(path.join(here, "hooks.mjs")));
await import(pathToFileURL(runner).href);

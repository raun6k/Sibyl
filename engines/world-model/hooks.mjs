import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.join(here, "..", "package.json"));
const ts = require("typescript");

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith("file:") && specifier.split("?")[0].endsWith(".ts")) {
    return { url: specifier.split("?")[0], shortCircuit: true };
  }
  if (specifier.startsWith("node:") || (!specifier.startsWith(".") && !specifier.endsWith(".ts"))) {
    return nextResolve(specifier, context);
  }
  const parent = context.parentURL;
  if (!parent) return nextResolve(specifier, context);
  if (specifier.endsWith(".ts")) {
    return { url: new URL(specifier, parent).href, shortCircuit: true };
  }
  if (specifier.endsWith(".js")) {
    const tsUrl = new URL(specifier.replace(/\.js$/, ".ts"), parent);
    const jsUrl = new URL(specifier, parent);
    if (existsSync(fileURLToPath(tsUrl)) && !existsSync(fileURLToPath(jsUrl))) {
      return { url: tsUrl.href, shortCircuit: true };
    }
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  const clean = url.split("?")[0];
  if (!clean.endsWith(".ts")) return nextLoad(url, context);
  const source = await readFile(fileURLToPath(clean), "utf8");
  const output = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    fileName: clean,
  }).outputText;
  return { format: "module", source: output, shortCircuit: true };
}

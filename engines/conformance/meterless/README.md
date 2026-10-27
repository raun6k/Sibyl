# Bundled Meterless conformance suites

These upstream files are included so a fresh Sibyl clone can run the same
conformance checks without cloning Meterless or downloading a test runner.

- Source: https://github.com/Meterless/Meterless
- Revision: `1742dec56a66e58eef9dda2d2b865823758ca8cd`
- Copyright 2026 Meterless
- License: Apache-2.0; see [LICENSE](LICENSE).

The files are copied without modification:

| Local file | Upstream path |
|---|---|
| `world-model/runner.ts` | `engines/world-model/conformance/runner.ts` |
| `hmem/runner.ts` | `engines/hmem/conformance/runner.ts` |
| `hmem/vectors/vectors.json` | `engines/hmem/conformance/vectors/vectors.json` |

From the Sibyl repository root, after `npm --prefix engines install`:

```sh
node engines/world-model/run-conformance.mjs
node engines/hmem/run-conformance.mjs
```

The entrypoints select Sibyl's implementations and load these runners using
the installed TypeScript compiler. They need no database, sponsor credentials,
separate Meterless checkout, or network access.

To check against another upstream revision, explicitly set `METERLESS_REPO`
to that checkout's path. `WORLD_MODEL_IMPL` and `HMEM_IMPL` may also select
alternative implementations. To update the bundled suites, copy all three
files together from a pinned upstream revision, retain the license and
attribution, update this revision, and run both scorecards.

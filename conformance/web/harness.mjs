// The in-browser conformance harness: drives every case of both transpiled
// conformance suites against jco-impl/webcrypto.js running in *this*
// browser, reporting each result as it completes. Shared between the page's
// Web Worker (worker.mjs) and the main-thread fallback (app.mjs), so both
// paths run identically.
//
// The module paths are resolved relative to this file, so they work from
// any base path (the local server's repo root, or a GitHub Pages project
// subpath); the transpiled guests resolve their own relative imports of
// jco-impl/webcrypto.js the same way, so the serving tree must mirror the
// repository layout (see serve.mjs and the `conformance-web-site` recipe).

export const SUITES = [
  {
    suite: "shared",
    module: new URL(
      "../adapters/jco/generated/conformance-guest.js",
      import.meta.url,
    ).href,
  },
  {
    suite: "signing",
    module: new URL(
      "../adapters/jco/generated-signing/conformance-signing-guest.js",
      import.meta.url,
    ).href,
  },
];

/**
 * Run both suites with the given missing-features declaration, invoking
 * `report` with `{ kind: "start", suite, total }` before each suite and
 * `{ kind: "result", suite, index, name, features, outcome, detail }` per
 * case (`index` is the case's position in the suite, letting consumers of
 * a sharded run restore suite order).
 *
 * `shard` selects a stripe of each suite (case `i` belongs to shard
 * `i % count`), letting several workers — each with its own instances of
 * the guests — run disjoint slices concurrently. Striping balances load
 * better than contiguous chunks: expensive cases cluster by algorithm. The
 * default runs everything.
 * @param {string[]} missing
 * @param {(message: object) => void} report
 * @param {{ index: number, count: number }} [shard]
 */
export async function runAll(missing, report, shard = { index: 0, count: 1 }) {
  for (const { suite, module } of SUITES) {
    const { tests } = await import(module);
    const mine = [];
    tests.all(missing).forEach((testCase, index) => {
      if (index % shard.count === shard.index) mine.push([index, testCase]);
    });
    report({ kind: "start", suite, total: mine.length });
    for (const [index, testCase] of mine) {
      const name = String(testCase.name());
      const features = Array.from(testCase.features(), String);
      report({ kind: "result", suite, index, name, features, ...(await runCase(testCase)) });
    }
  }
}

/**
 * Run one case to its `{ outcome, detail }` row. `run` never traps by
 * construction (the conformance WIT: a mismatch is a `fail` outcome), so a
 * throw here is the guest being aborted — a host error the implementation
 * failed to lift into the WIT taxonomy. Record it as this case's failure:
 * one unliftable host error must not end the run and discard every
 * remaining case's verdict.
 *
 * Exported so the Node adapter's loop (adapters/jco/src/report.mjs) shares
 * this rule; this module stays browser-safe, so it is the lower layer.
 * @param {{ run: () => Promise<{ tag: string, val?: unknown }> }} testCase
 */
export async function runCase(testCase) {
  try {
    const { tag, val } = await testCase.run();
    return { outcome: String(tag), detail: String(val ?? "") };
  } catch (err) {
    return { outcome: "fail", detail: `the guest trapped: ${err}` };
  }
}

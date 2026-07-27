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
      const { tag, val } = await testCase.run();
      report({
        kind: "result",
        suite,
        index,
        name,
        features,
        outcome: String(tag),
        detail: String(val ?? ""),
      });
    }
  }
}

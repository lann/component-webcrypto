// The in-browser conformance harness: drives every case of both transpiled
// conformance guests against jco-impl/webcrypto.js running in *this*
// browser, reporting each result as it completes. Shared between the page's
// Web Worker (worker.mjs) and the main-thread fallback (app.mjs), so both
// paths run identically.
//
// The module paths are absolute: the repo root is the server root (see
// serve.mjs), which also lets the transpiled guests resolve their relative
// imports of jco-impl/webcrypto.js.

export const CORPORA = [
  {
    corpus: "shared",
    module: "/conformance/adapters/jco/generated/conformance-guest.js",
  },
  {
    corpus: "signing",
    module: "/conformance/adapters/jco/generated-signing/conformance-signing-guest.js",
  },
];

/**
 * Run both corpora with the given missing-features declaration, invoking
 * `report` with `{ kind: "start", corpus, total }` before each corpus and
 * `{ kind: "result", corpus, name, features, outcome, detail }` per case.
 * @param {string[]} missing
 * @param {(message: object) => void} report
 */
export async function runAll(missing, report) {
  for (const { corpus, module } of CORPORA) {
    const { tests } = await import(module);
    const cases = tests.all(missing);
    report({ kind: "start", corpus, total: cases.length });
    for (const testCase of cases) {
      const name = String(testCase.name());
      const features = Array.from(testCase.features(), String);
      const { tag, val } = await testCase.run();
      report({
        kind: "result",
        corpus,
        name,
        features,
        outcome: String(tag),
        detail: String(val ?? ""),
      });
    }
  }
}

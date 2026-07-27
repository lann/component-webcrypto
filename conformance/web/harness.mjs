// The in-browser conformance harness: drives every case of both transpiled
// conformance guests against jco-impl/webcrypto.js running in *this*
// browser, reporting each result as it completes. Shared between the page's
// Web Worker (worker.mjs) and the main-thread fallback (app.mjs), so both
// paths run identically.
//
// The module paths are resolved relative to this file, so they work from
// any base path (the local server's repo root, or a GitHub Pages project
// subpath); the transpiled guests resolve their own relative imports of
// jco-impl/webcrypto.js the same way, so the serving tree must mirror the
// repository layout (see serve.mjs and the `conformance-web-site` recipe).

export const CORPORA = [
  {
    corpus: "shared",
    module: new URL(
      "../adapters/jco/generated/conformance-guest.js",
      import.meta.url,
    ).href,
  },
  {
    corpus: "signing",
    module: new URL(
      "../adapters/jco/generated-signing/conformance-signing-guest.js",
      import.meta.url,
    ).href,
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

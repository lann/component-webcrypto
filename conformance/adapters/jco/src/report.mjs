// Shared helper for the jco conformance adapters (Node + browser): writes the
// per-target results document the conformance runner consumes
// (`conformance/results/<target>.json`) and prints the one-line summary.
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ADAPTER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_ROOT = resolve(ADAPTER_DIR, "..", "..", "..");
export const RESULTS_DIR = join(REPO_ROOT, "conformance", "results");

// The features the jco host (jco-impl/webcrypto.js) is missing, passed to
// every guest's `all` and recorded in the results for the runner to
// cross-check against conformance/targets.toml:
// - chacha20-poly1305: browser WebCrypto implements no ChaCha20-Poly1305
//   (the WICG proposal is unimplemented); minting declines `unsupported`.
// - deterministic-ecdsa: WebCrypto signs ECDSA with a randomized k, so
//   RFC 6979 deterministic known answers are unobservable.
export const MISSING = ["chacha20-poly1305", "deterministic-ecdsa"];

/**
 * Drive every materialized case of a guest's `tests` export, returning the
 * results rows the runner consumes. `only` (a substring) selects a corpus
 * subset for bisection.
 * @param {{ all: (missing: string[]) => any[] }} tests
 * @param {string | undefined} only
 */
export async function runCases(tests, only) {
  const results = [];
  for (const testCase of tests.all(MISSING)) {
    const name = String(testCase.name());
    if (only !== undefined && !name.includes(only)) continue;
    const features = Array.from(testCase.features(), String);
    const { tag, val } = await testCase.run();
    results.push({ name, features, outcome: String(tag), detail: String(val ?? "") });
  }
  return results;
}

/**
 * Write `conformance/results/<basename ?? target>.json` for `results` and
 * print the summary line. `basename` lets several guests report for the
 * same target (one results file per corpus).
 */
export async function writeReport(target, corpus, results, basename) {
  const report = { target, corpus, missing: MISSING, results };
  await mkdir(RESULTS_DIR, { recursive: true });
  const outPath = join(RESULTS_DIR, `${basename ?? target}.json`);
  await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);

  const failed = report.results.filter((r) => r.outcome === "fail").length;
  const skipped = report.results.filter((r) => r.outcome === "skipped").length;
  console.log(
    `${target}: ${report.results.length} cases, ${failed} failed, ${skipped} skipped (wrote ${outPath})`,
  );
  for (const r of report.results) {
    if (r.outcome === "fail") console.error(`  FAIL ${r.name}: ${r.detail}`);
  }
}

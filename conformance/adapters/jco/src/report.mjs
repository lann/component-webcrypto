// Shared helper for the jco conformance adapters (Node + browser): writes the
// per-target results document the conformance runner consumes
// (`conformance/results/<target>.json`) and prints the one-line summary.
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ADAPTER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_ROOT = resolve(ADAPTER_DIR, "..", "..", "..");
export const RESULTS_DIR = join(REPO_ROOT, "conformance", "results");

/**
 * Normalize one jco-lifted `test-result` (camelCase fields are already the
 * WIT names here) into the exact JSON shape the runner expects.
 */
function toJson({ id, passed, detail }) {
  return { id: String(id), passed: Boolean(passed), detail: String(detail ?? "") };
}

/**
 * Write `conformance/results/<target>.json` for `results` (the array returned
 * by the guest's `tests.run-all`) and print the pass/total summary line.
 */
export async function writeReport(target, results) {
  const report = { target, results: results.map(toJson) };
  await mkdir(RESULTS_DIR, { recursive: true });
  const outPath = join(RESULTS_DIR, `${target}.json`);
  await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);

  const passed = report.results.filter((r) => r.passed).length;
  console.log(`${target}: ${passed}/${report.results.length} tests passed (wrote ${outPath})`);
  for (const r of report.results) {
    if (!r.passed) console.error(`  FAIL ${r.id}: ${r.detail}`);
  }
}

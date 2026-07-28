// Shared helper for the jco conformance adapters (Node + browser): resolves
// each target's missing-features declaration from conformance/targets.toml
// (the single source of target facts — the runner cross-checks results
// against the same table), drives a guest's cases, and writes the
// per-target results document the conformance runner consumes
// (`conformance/results/<target>.json`).
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "smol-toml";

// The per-case guard is shared with the in-browser harness (that module is
// browser-safe, so it is the lower layer of the two drivers).
import { runCase } from "../../../web/harness.mjs";

export const ADAPTER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REPO_ROOT = resolve(ADAPTER_DIR, "..", "..", "..");
export const RESULTS_DIR = join(REPO_ROOT, "conformance", "results");

/**
 * The `missing-features` declaration for `target`, read from
 * conformance/targets.toml.
 * @param {string} target
 * @returns {Promise<string[]>}
 */
export async function missingFeatures(target) {
  const text = await readFile(join(REPO_ROOT, "conformance", "targets.toml"), "utf8");
  const entry = parse(text).targets?.[target];
  if (!entry) throw new Error(`target ${target} is not declared in conformance/targets.toml`);
  return Array.from(entry["missing-features"], String);
}

/**
 * Drive every materialized case of a guest's `tests` export, returning the
 * results rows the runner consumes. `only` (a substring) selects a
 * subset of the cases for bisection.
 * @param {{ all: (missingFeatures: string[]) => any[] }} tests
 * @param {string[]} missing
 * @param {string | undefined} only
 */
export async function runCases(tests, missing, only) {
  const results = [];
  for (const testCase of tests.all(missing)) {
    const name = String(testCase.name());
    if (only !== undefined && !name.includes(only)) continue;
    const features = Array.from(testCase.features(), String);
    results.push({ name, features, ...(await runCase(testCase)) });
  }
  return results;
}

/**
 * Write `conformance/results/<basename ?? target>.json` for `results` and
 * print the summary line. `basename` lets several guests report for the
 * same target (one results file per suite).
 */
export async function writeReport(target, suite, missing, results, basename) {
  const report = { target, suite, "missing-features": missing, results };
  await mkdir(RESULTS_DIR, { recursive: true });
  const outPath = join(RESULTS_DIR, `${basename ?? target}.json`);
  await writeFile(outPath, `${JSON.stringify(report, null, 2)}\n`);

  const failed = report.results.filter((r) => r.outcome === "fail").length;
  const skipped = report.results.filter((r) => r.outcome === "skipped").length;
  console.log(
    `${target}/${suite}: ${report.results.length} cases, ${failed} failed, ${skipped} skipped (wrote ${outPath})`,
  );
  for (const r of report.results) {
    if (r.outcome === "fail") console.error(`  FAIL ${r.name}: ${r.detail}`);
  }
}

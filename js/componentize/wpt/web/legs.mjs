// The two parity legs, browser-side: shared by the page's Web Worker
// (worker.mjs) and the main-thread fallback (app.mjs), so both paths run
// identically. The baseline leg is the shared group loop in
// ../parity-helpers.js (which installs ../harness.js's WPT harness
// globals in the current scope when the leg starts), run with a
// paint-yield between groups; the round-trip leg imports the web
// transpile of the parity runner (../parity/generated-web/, every import
// a relative path, so it loads in a worker) and collects the records the
// runner streams through its `wpt:parity/reporter` import.

import { checkStreamedCount, runBaselineGroups, unwrapResult } from "../parity-helpers.js";
import { setSink } from "../reporter.js";

const RUNNER_URL = new URL("../parity/generated-web/parity-runner.js", import.meta.url).href;
// Records per round-trip progress batch.
const BATCH = 100;

/**
 * The baseline leg: run every group, reporting each as it completes.
 * @param {(group: string, results: { name: string, status: string, message?: string }[]) => void} onGroup
 */
export function runBaselineLeg(onGroup) {
  return runBaselineGroups(onGroup, { yieldBetweenGroups: true });
}

/**
 * The round-trip leg: one call into the transpiled parity runner, its
 * records delivered in batches as the run executes (the runner reports
 * each settled test through ../reporter.js — the same module instance the
 * generated code imports). Resolves to the total record count, verified
 * against the count the runner's `run` resolves to. Imported on demand so
 * an environment without JSPI never fetches the component.
 * @param {(records: { group: string, name: string, status: string, message?: string }[]) => void} onRecords
 */
export async function runRoundtripLeg(onRecords) {
  let pending = [];
  let count = 0;
  const flush = () => {
    if (pending.length > 0) {
      onRecords(pending);
      pending = [];
    }
  };
  setSink((record) => {
    count += 1;
    pending.push(JSON.parse(record));
    if (pending.length >= BATCH) flush();
  });
  try {
    const { demo } = await import(RUNNER_URL);
    const output = await unwrapResult(() => demo.run());
    flush();
    return checkStreamedCount(output, count);
  } finally {
    setSink(null);
  }
}

// The two parity legs, browser-side: shared by the page's Web Worker
// (worker.mjs) and the main-thread fallback (app.mjs), so both paths run
// identically. The baseline leg imports the suite modules beside ../build/
// and runs them against this environment's own crypto; the round-trip leg
// imports the web transpile of the parity runner (../parity/generated-web/,
// every import a relative path, so it loads in a worker) and collects the
// records the runner streams through its `wpt:parity/reporter` import.
//
// Importing this module installs ../harness.js's WPT harness globals in
// the current scope.

import { GROUPS } from "../groups.js";
import { drain, takeResults } from "../harness.js";
import { setSink } from "../reporter.js";

const RUNNER_URL = new URL("../parity/generated-web/parity-runner.js", import.meta.url).href;
// Records per round-trip progress batch.
const BATCH = 100;

/**
 * The baseline leg: run every group, reporting each as it completes. The
 * explicit macrotask lets a main-thread run paint between groups (the
 * harness's own awaits may settle as microtasks for pure-JS tests).
 * @param {(group: string, results: { name: string, status: string, message?: string }[]) => void} onGroup
 */
export async function runBaselineLeg(onGroup) {
  for (const { name: group, module, start } of GROUPS) {
    await new Promise((resolve) => setTimeout(resolve));
    start(await import(new URL(`../build/${module}`, import.meta.url).href));
    await drain();
    onGroup(group, takeResults());
  }
}

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned
 * by an exported function — a convention, not documented API (validated
 * against jco-transpile 0.5.x; see examples/jco-demo/src/run.mjs, where
 * the same convention is anchored).
 * @param {() => Promise<unknown>} call
 */
async function unwrapResult(call) {
  let value;
  try {
    value = await call();
  } catch (err) {
    throw new Error(`returned err: ${err?.payload ?? err?.val ?? err}`);
  }
  if (typeof value === "object" && value !== null && "tag" in value) {
    if (value.tag !== "ok") {
      throw new Error(`returned err: ${value.val}`);
    }
    value = value.val;
  }
  return value;
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
    const marker = "WPT-PARITY-STREAMED ";
    if (typeof output !== "string" || !output.startsWith(marker)) {
      throw new Error(`parity runner returned an unexpected shape: ${String(output).slice(0, 200)}`);
    }
    const reported = Number(output.slice(marker.length));
    if (reported !== count) {
      throw new Error(`parity runner reported ${reported} records; received ${count}`);
    }
    return count;
  } finally {
    setSink(null);
  }
}

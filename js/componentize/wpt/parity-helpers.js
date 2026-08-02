// The run-and-parse helpers shared by the WPT parity legs: the Node gate
// (parity/baseline.mjs, parity/roundtrip.mjs) and the browser legs the
// parity page and the headless-engine adapter run (web/legs.mjs). Like
// groups.js and reporter.js, this module serves every environment the
// legs run in, so it is dependency-free and browser-loadable: importing
// it has no side effects — `runBaselineGroups` loads ./groups.js and
// ./harness.js (which installs the WPT harness globals) when first
// called, so a round-trip-only consumer never installs them.

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned
 * by an exported function — a convention, not documented API, so it is
 * isolated here and version-anchored: validated against jco-transpile
 * 0.5.x; revalidate when bumping jco-transpile (the standalone jco demo
 * carries its own copy in examples/jco-demo/src/run.mjs). The ok value is
 * returned; the err case thrown.
 * @param {() => Promise<unknown>} call
 */
export async function unwrapResult(call) {
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

const STREAMED_MARKER = "WPT-PARITY-STREAMED ";

/**
 * Parse the `WPT-PARITY-STREAMED <count>` summary the parity runner's
 * `run` resolves to (see ../parity-runner.js) and cross-check it against
 * the number of records the embedder received through the reporter
 * import; returns the count. A mismatch or an unexpected shape throws —
 * a record lost between the runner and the sink must fail the run.
 * @param {unknown} output
 * @param {number} received
 */
export function checkStreamedCount(output, received) {
  if (typeof output !== "string" || !output.startsWith(STREAMED_MARKER)) {
    throw new Error(`parity runner returned an unexpected shape: ${String(output).slice(0, 200)}`);
  }
  const count = Number(output.slice(STREAMED_MARKER.length));
  if (count !== received) {
    throw new Error(`parity runner reported ${count} records; received ${received}`);
  }
  return count;
}

/**
 * The baseline leg's group loop: run every vendored group in ./groups.js
 * against this environment's own crypto, reporting each as it completes.
 * The first call installs ./harness.js's WPT harness globals in the
 * current scope; each group's suite module is resolved against ./build/
 * and imported dynamically.
 *
 * With `yieldBetweenGroups`, an explicit macrotask precedes each group,
 * letting a browser main-thread run paint between groups (the harness's
 * own awaits may settle as microtasks for pure-JS tests).
 * @param {(group: string, results: { name: string, status: string, message?: string }[]) => void} onGroup
 * @param {{ yieldBetweenGroups?: boolean }} [options]
 */
export async function runBaselineGroups(onGroup, { yieldBetweenGroups = false } = {}) {
  const [{ GROUPS }, { drain, takeResults }] = await Promise.all([
    import("./groups.js"),
    import("./harness.js"),
  ]);
  for (const { name: group, module, start } of GROUPS) {
    if (yieldBetweenGroups) {
      await new Promise((resolve) => setTimeout(resolve));
    }
    start(await import(new URL(`./build/${module}`, import.meta.url).href));
    await drain();
    onGroup(group, takeResults());
  }
}

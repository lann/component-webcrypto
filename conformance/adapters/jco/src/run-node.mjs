// The jco Node conformance adapter: runs a conformance guest against the
// browser-first host (`js/jco/webcrypto.js`, wired in at transpile time
// via `--map`) under Node and writes its results file under
// `conformance/results/`.
//
// The cases are striped across a pool of worker threads (worker-node.mjs),
// each with its own instances of the guest and the host module — the Node
// counterpart of the browser adapter's Web Worker pool
// (conformance/web/harness.mjs, `runInWorkers`). Within a worker the cases
// run strictly sequentially, so no host instance ever sees two operations
// in flight. Workers interleave, so the rows are re-sorted into suite
// order before reporting.
//
// jco's async ABI needs JavaScript Promise Integration (JSPI), so this must
// run under Node 24+ with `--experimental-wasm-jspi` (the npm scripts and
// the `just conformance-jco-node` recipe supply both; the workers inherit
// the flag through `process.execArgv`).
//
// Usage: run-node.mjs [--signing] [--only <substring>]
//   default    the shared conformance guest -> jco-node.json
//   --signing  the host-only signing guest  -> jco-node-signing.json
//   --only     run only cases whose name contains the substring (a
//              bisection aid; the runner will reject the pruned results
//              file, so use it for debugging, not gating)
import { availableParallelism } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

import { ADAPTER_DIR, missingFeatures, writeReport } from "./report.mjs";

/** The worker-pool size for this machine (the browser pool's cap). */
const workerCount = () => Math.min(availableParallelism(), 8);

/**
 * Run the guest module's cases striped across the worker pool, returning
 * the results rows in suite order. Any worker failing fails the run: the
 * enclosing process exit tears the remaining workers down.
 * @param {string} module
 * @param {string[]} missing
 * @param {string | undefined} only
 */
async function runCasesInWorkers(module, missing, only) {
  const count = workerCount();
  const rows = [];
  await Promise.all(
    Array.from(
      { length: count },
      (_, index) =>
        new Promise((resolve, reject) => {
          const worker = new Worker(new URL("./worker-node.mjs", import.meta.url), {
            workerData: { module, missing, only, shard: { index, count } },
          });
          worker.on("message", (row) => rows.push(row));
          worker.on("error", reject);
          worker.on("exit", (code) => {
            if (code === 0) resolve();
            else reject(new Error(`conformance worker ${index} exited with code ${code}`));
          });
        }),
    ),
  );
  rows.sort((a, b) => a.index - b.index);
  return rows.map(({ index, ...row }) => row);
}

async function main() {
  const signing = process.argv.includes("--signing");
  const onlyIndex = process.argv.indexOf("--only");
  const only = onlyIndex >= 0 ? process.argv[onlyIndex + 1] : undefined;
  const generated = signing ? "generated-signing" : "generated";
  const name = signing ? "conformance-signing-guest" : "conformance-guest";
  const url = pathToFileURL(join(ADAPTER_DIR, generated, `${name}.js`));
  const missing = await missingFeatures("jco-node");
  const results = await runCasesInWorkers(url.href, missing, only);
  await writeReport(
    "jco-node",
    signing ? "signing" : "shared",
    missing,
    results,
    signing ? "jco-node-signing" : undefined,
  );
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("jco-node adapter failed:", err);
    process.exit(1);
  },
);

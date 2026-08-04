// jco-node driver for the ported conformance suite: reads the static
// tag inventory from the transpiled core wasm, applies the target
// manifest (--missing), runs applicable cases, and reports. The cases
// are striped across a pool of worker threads (worker-node.mjs), each
// with its own instance of the transpiled suite, so no instance ever
// sees two operations in flight — the incumbent adapter's topology,
// and the Node counterpart of the browser driver's Web Worker pool
// (run-browser.mjs). Workers interleave, so the rows are re-sorted
// into suite order before emission. The inventory parsing and per-case
// loop live in harness.mjs, shared with the browser driver.
import { availableParallelism } from "node:os";
import { parseArgs } from "node:util";
import { Worker } from "node:worker_threads";
import { envelope, mergeCounts, workerCount } from "./harness.mjs";

const { values } = parseArgs({
  options: {
    missing: { type: "string", default: "" },
    only: { type: "string" },
    jsonl: { type: "boolean", default: false },
    target: { type: "string", default: "jco-node" },
    suite: { type: "string", default: "conformance-guest-ct" },
    jobs: { type: "string" },
  },
});
const suite = values.suite;
const missing = values.missing.split(",").filter(Boolean);
const jsonl = values.jsonl;
const jobs = values.jobs ? Number(values.jobs) : workerCount(availableParallelism());

// Run the shards. Any worker failing fails the run (exit 2 below tears
// the rest down): a thrown inventory drift or a wedged instance is
// unsoundness, not a failing case.
const rows = [];
const parts = await Promise.all(
  Array.from({ length: jobs }, (_, index) =>
    new Promise((resolve, reject) => {
      const worker = new Worker(new URL("./worker-node.mjs", import.meta.url), {
        workerData: { suite, missing, only: values.only, shard: { index, count: jobs } },
      });
      let counts;
      worker.on("message", (msg) => {
        if (msg.kind === "event") rows.push(msg);
        else if (msg.kind === "counts") counts = msg.counts;
      });
      worker.on("error", reject);
      worker.on("exit", (code) => {
        if (code === 0 && counts) resolve(counts);
        else reject(new Error(`conformance worker ${index} exited with code ${code}`));
      });
    })
  )
).catch((e) => {
  console.error(String(e?.message ?? e));
  process.exit(2);
});

rows.sort((a, b) => a.index - b.index);
if (jsonl) {
  const lines = [JSON.stringify(envelope(values.target, suite))];
  for (const { event } of rows) lines.push(JSON.stringify(event));
  lines.push('{"segment-end":true}');
  console.log(lines.join("\n"));
}

const { passed, failed, skipped, na, total, failures } = mergeCounts(parts);
if (!jsonl) for (const f of failures.slice(0, 20)) {
  console.log(`FAIL: ${f.name}: ${f.detail}`);
  for (const d of f.diags) console.log(`    diag: ${d}`);
}
if (failures.length > 20) console.log(`... and ${failures.length - 20} more failures`);
if (!jsonl)
  console.log(
    `\nresult: ${passed} passed, ${failed} failed, ${skipped} skipped, ${na} not applicable, ${total} total`
  );
process.exit(failed === 0 ? 0 : 1);

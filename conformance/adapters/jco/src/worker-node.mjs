// The worker-thread half of the jco Node conformance adapter
// (run-node.mjs): materializes the guest's cases in this thread — its own
// instances of the transpiled guest and the host module — runs the
// `index % shard.count === shard.index` stripe, and streams one row per
// case back through `parentPort`. Striping balances load better than
// contiguous chunks: expensive cases cluster by algorithm.
//
// A top-level throw (a guest that fails to instantiate, a broken module
// path) rejects the module's evaluation, which surfaces as the parent's
// `error` event; Node's default unhandled-rejection behavior (throw) routes
// stray rejections the same way.
import { parentPort, workerData } from "node:worker_threads";

// The per-case guard is shared with the in-browser harness (that module is
// browser-safe, so it is the lower layer of the two drivers).
import { runCase } from "../../../web/harness.mjs";

const { module, missing, only, shard } = workerData;

const { tests } = await import(module);
const mine = [];
tests.all(missing).forEach((testCase, index) => {
  if (index % shard.count !== shard.index) return;
  if (only !== undefined && !String(testCase.name()).includes(only)) return;
  mine.push([index, testCase]);
});
for (const [index, testCase] of mine) {
  const name = String(testCase.name());
  const features = Array.from(testCase.features(), String);
  parentPort.postMessage({ index, name, features, ...(await runCase(testCase)) });
}

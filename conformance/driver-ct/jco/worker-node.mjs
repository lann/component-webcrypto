// The worker-thread half of the jco-node driver (runner.mjs): its own
// instance of the transpiled suite (and host modules) runs one shard of
// the case loop, streaming each results-JSONL event — tagged with its
// suite-order index so the parent can restore suite order — back through
// `parentPort`, then reporting the shard's counts. Workers inherit the
// parent's execArgv, so `--experimental-wasm-jspi` carries over.
import { readFile } from "node:fs/promises";
import { parentPort, workerData } from "node:worker_threads";
import { Context } from "../context.js";
import { inventoryLookup, runCases } from "./ct-harness.mjs";

const { suite, missing, only, shard } = workerData;

const coreModules = [];
for (const core of [`${suite}.core.wasm`, `${suite}.core2.wasm`]) {
  try {
    coreModules.push(new Uint8Array(await readFile(new URL(`./generated/${core}`, import.meta.url))));
  } catch {
    continue;
  }
}
const tagsOf = inventoryLookup(coreModules);
const { tests } = await import(`./generated/${suite}.js`);

const counts = await runCases({
  cases: await tests.all(),
  Context,
  tagsOf,
  missing,
  only,
  shard,
  emit: (event, index) => parentPort.postMessage({ kind: "event", index, event }),
});
parentPort.postMessage({ kind: "counts", counts });

// The worker-thread half of the jco-node driver (runner.mjs): its own
// instance of the transpiled suite (and host modules) runs one shard of
// the case loop, streaming each results-JSONL event — tagged with its
// suite-order index so the parent can restore suite order — back through
// `parentPort`, then reporting the shard's counts. Workers inherit the
// parent's execArgv, so `--experimental-wasm-jspi` carries over.
import { fileURLToPath } from "node:url";
import { parentPort, workerData } from "node:worker_threads";
import { cli, clocks, io, random, filesystem } from "@bytecodealliance/preview2-shim";
import { inventoryLookup, runCases } from "@polymorph/component-test-js/harness";
import { loadCoreModules } from "@polymorph/component-test-js/node-runner";
import { Context } from "../context.js";
import { instantiateSuite } from "./host-imports.mjs";

const { suite, missing, only, shard } = workerData;

const { modules, coreBytes } = await loadCoreModules(
  fileURLToPath(new URL("./generated/", import.meta.url)),
  suite,
);
const tagsOf = inventoryLookup(coreBytes);
const { instantiate } = await import(`./generated/${suite}.js`);
const tests = await instantiateSuite({
  instantiate,
  modules,
  wasi: { cli, clocks, io, random, filesystem },
});

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

// The worker-thread half of the jco-node driver (runner.mjs): its own
// instance of the transpiled suite (and host modules) runs one shard of
// the case loop, streaming each results-JSONL event — tagged with its
// suite-order index so the parent can restore suite order — back through
// `parentPort`, then reporting the shard's counts. Workers inherit the
// parent's execArgv, so `--experimental-wasm-jspi` carries over.
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parentPort, workerData } from "node:worker_threads";
import { cli, clocks, io, random, filesystem } from "@bytecodealliance/preview2-shim";
import { inventoryLookup, runCases } from "@polymorph/component-test-js/harness";
import { Context } from "../context.js";
import { instantiateSuite } from "./host-imports.mjs";

const { suite, missing, only, shard } = workerData;

const generatedDir = new URL("./generated/", import.meta.url);
const coreBytes = [];
const modules = new Map();
for (const name of (await readdir(fileURLToPath(generatedDir))).sort()) {
  if (!name.startsWith(`${suite}.core`) || !name.endsWith(".wasm")) continue;
  const bytes = new Uint8Array(await readFile(new URL(`./generated/${name}`, import.meta.url)));
  coreBytes.push(bytes);
  modules.set(name, await WebAssembly.compile(bytes));
}
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

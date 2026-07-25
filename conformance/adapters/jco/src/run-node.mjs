// The jco Node conformance adapter: runs the shared conformance guest against
// the browser-first host (`jco-impl/webcrypto.js`, wired in at transpile time
// via `--map`) under Node and writes `conformance/results/jco-node.json`.
//
// jco's async ABI needs JavaScript Promise Integration (JSPI), so this must
// run under Node 24+ with `--experimental-wasm-jspi` (the `run:node` script
// and the `just conformance-jco-node` recipe supply both).
//
// KNOWN BLOCKER: jco's component-model-async runtime currently corrupts the
// guest heap under this corpus's async-operation patterns (the guest binary
// runs the identical corpus clean under Wasmtime), so this target is not yet
// part of the gating `just conformance` run. The diagnosis and upstream next
// steps are written up in the jco checkout (GUEST-HEAP-CORRUPTION-DEBUG.md);
// once the fix lands upstream, verify with `just conformance-jco-node` and
// add the jco targets back to the `conformance` recipe.
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { ADAPTER_DIR, writeReport } from "./report.mjs";

async function main() {
  const url = pathToFileURL(join(ADAPTER_DIR, "generated", "conformance-guest.js"));
  const { tests } = await import(url.href);
  const results = await tests.runAll();
  await writeReport("jco-node", results);
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("jco-node adapter failed:", err);
    process.exit(1);
  },
);

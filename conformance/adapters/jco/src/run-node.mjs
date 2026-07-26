// The jco Node conformance adapter: runs a conformance guest against the
// browser-first host (`jco-impl/webcrypto.js`, wired in at transpile time
// via `--map`) under Node and writes its results file under
// `conformance/results/`.
//
// jco's async ABI needs JavaScript Promise Integration (JSPI), so this must
// run under Node 24+ with `--experimental-wasm-jspi` (the npm scripts and
// the `just conformance-jco-node` recipe supply both).
//
// Usage: run-node.mjs [--signing]
//   default    the shared conformance guest -> jco-node.json
//   --signing  the host-only signing guest  -> jco-node-signing.json
//              (same `jco-node` target; the runner merges the files)
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { ADAPTER_DIR, writeReport } from "./report.mjs";

async function main() {
  const signing = process.argv.includes("--signing");
  const generated = signing ? "generated-signing" : "generated";
  const name = signing ? "conformance-signing-guest" : "conformance-guest";
  const url = pathToFileURL(join(ADAPTER_DIR, generated, `${name}.js`));
  const { tests } = await import(url.href);
  const results = await tests.runAll();
  await writeReport("jco-node", results, signing ? "jco-node-signing" : undefined);
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error("jco-node adapter failed:", err);
    process.exit(1);
  },
);

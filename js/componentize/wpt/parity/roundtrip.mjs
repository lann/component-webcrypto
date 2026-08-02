// The round-trip leg of the WPT parity gate: the same vendored WPT suites,
// but through the full carrier stack — shim, WIT, component ABI, jco,
// webcrypto-jco — terminating in the same platform `crypto.subtle` the baseline
// leg measured. Any test the baseline passes and this leg does not is a
// loss introduced by that stack.
//
// Imports the jco transpile of parity-runner.component.wasm (see
// `npm run transpile`), collects the records the runner streams through
// its `wpt:parity/reporter` import (../reporter.js — the same module
// instance the generated code maps the import to), cross-checks the count
// `run` resolves to, and emits the records as JSON on stdout, matching
// baseline.mjs.

import { setSink } from "../reporter.js";
import { demo } from "./generated/parity-runner.js";

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned
 * by an exported function — a convention, not documented API (validated
 * against jco-transpile 0.5.x; see examples/jco-demo/src/run.mjs, where the
 * same convention is anchored). The ok value is returned; the err case thrown.
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

const records = [];
setSink((record) => records.push(JSON.parse(record)));
const output = await unwrapResult(() => demo.run());
const marker = "WPT-PARITY-STREAMED ";
if (typeof output !== "string" || !output.startsWith(marker)) {
  throw new Error(`parity runner returned an unexpected shape: ${String(output).slice(0, 200)}`);
}
const count = Number(output.slice(marker.length));
if (count !== records.length) {
  throw new Error(`parity runner reported ${count} records; received ${records.length}`);
}
process.stdout.write(JSON.stringify(records));

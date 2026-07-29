// The round-trip leg of the WPT parity gate: the same vendored WPT suites,
// but through the full carrier stack — shim, WIT, component ABI, jco,
// jco-impl — terminating in the same platform `crypto.subtle` the baseline
// leg measured. Any test the baseline passes and this leg does not is a
// loss introduced by that stack.
//
// Imports the jco transpile of parity-runner.component.wasm (see
// `npm run transpile`), invokes its async `run` export, and re-emits the
// guest's records as JSON on stdout, matching baseline.mjs.

import { demo } from "./generated/parity-runner.js";

/**
 * Unwrap jco's representation of a WIT `result<string, string>` returned
 * by an exported function — a convention, not documented API (validated
 * against jco 1.26.x; see examples/jco-demo/src/run.mjs, where the same
 * convention is anchored). The ok value is returned; the err case thrown.
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

const output = await unwrapResult(() => demo.run());
const marker = "WPT-PARITY-RESULTS\n";
if (typeof output !== "string" || !output.startsWith(marker)) {
  throw new Error(`parity runner returned an unexpected shape: ${String(output).slice(0, 200)}`);
}
process.stdout.write(output.slice(marker.length));

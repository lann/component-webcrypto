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
// `run` resolves to (../parity-helpers.js), and emits the records as JSON
// on stdout, matching baseline.mjs.

import { checkStreamedCount, unwrapResult } from "../parity-helpers.js";
import { setSink } from "../reporter.js";
import { demo } from "./generated/parity-runner.js";

const records = [];
setSink((record) => records.push(JSON.parse(record)));
const output = await unwrapResult(() => demo.run());
checkStreamedCount(output, records.length);
process.stdout.write(JSON.stringify(records));

// The baseline leg of the WPT parity gate: run the vendored WPT suites
// directly against this platform's own `crypto.subtle`, with no shim, no
// WIT, and no wasm in the path. The comparator holds the round trip to
// this leg's pass set, so whatever this platform does not implement falls
// out of scope without an exclusion list.
//
// Emits the same `{ group, name, status, message? }` records as
// parity-runner.js, as JSON on stdout. Both read the shared group table in
// ../groups.js, so a vendored group cannot reach one leg and miss the
// other; this leg resolves each group's suite module against ../build/ and
// imports it dynamically.

import { GROUPS } from "../groups.js";
import { drain, takeResults } from "../harness.js";

const records = [];
for (const { name: group, module, start } of GROUPS) {
  start(await import(new URL(`../build/${module}`, import.meta.url)));
  await drain();
  for (const { name, status, message } of takeResults()) {
    records.push(message === undefined ? { group, name, status } : { group, name, status, message });
  }
}
process.stdout.write(JSON.stringify(records));

// The baseline leg of the WPT parity gate: run the vendored WPT suites
// directly against this platform's own `crypto.subtle`, with no shim, no
// WIT, and no wasm in the path. The comparator holds the round trip to
// this leg's pass set, so whatever this platform does not implement falls
// out of scope without an exclusion list.
//
// Emits the same `{ group, name, status, message? }` records as
// parity-runner.js, as JSON on stdout. The group loop is the shared
// baseline helper in ../parity-helpers.js, which runs ../groups.js's
// group table — the same table the round trip's runner compiles in, so a
// vendored group cannot reach one leg and miss the other.

import { runBaselineGroups } from "../parity-helpers.js";

const records = [];
await runBaselineGroups((group, results) => {
  for (const { name, status, message } of results) {
    records.push(message === undefined ? { group, name, status } : { group, name, status, message });
  }
});
process.stdout.write(JSON.stringify(records));

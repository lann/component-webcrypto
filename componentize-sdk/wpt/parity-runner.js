// The WPT parity runner guest: the measuring half of the parity gate (see
// parity/README.md). It runs the same vendored WPT groups as runner.js
// against the same `componentize-sdk/webcrypto.js` shim, but asserts
// nothing in-guest: every result is reported, and the judgment — which
// losses relative to the platform baseline are known, which are new — is
// the host-side comparator's. The gating runner's subset and census checks
// are calibrated on the composed target and deliberately do not run here.
//
// Importing runner.js installs the shim as the `crypto`/`CryptoKey`
// globals (a module side effect there) and shares its GROUPS table, so a
// vendored group cannot reach one runner and miss the other.
//
// The exported `run` resolves to the marker line `WPT-PARITY-RESULTS`
// followed by a JSON array of `{ group, name, status, message? }` records.
// Module specifiers resolve against componentize-js's base directory, the
// repository root.

import { GROUPS } from "./componentize-sdk/wpt/runner.js";
import { drain, takeResults } from "./componentize-sdk/wpt/harness.js";

export const demoWebcryptoDemoDemo010 = {
  run: async function () {
    const records = [];
    for (const [group, start] of GROUPS) {
      start();
      await drain();
      for (const { name, status, message } of takeResults()) {
        records.push(message === undefined ? { group, name, status } : { group, name, status, message });
      }
    }
    return `WPT-PARITY-RESULTS\n${JSON.stringify(records)}`;
  },
};

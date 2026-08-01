// The WPT parity runner guest: the measuring half of the parity gate
// (see ../README.md, "The parity gate"). It runs the same vendored WPT
// groups as runner.js
// against the same `js/componentize/webcrypto.js` shim, but asserts
// nothing in-guest: every result is reported, and the judgment — which
// losses relative to the platform baseline are known, which are new — is
// the host-side comparator's. The gating runner's subset and census checks
// are calibrated on the composed target and deliberately do not run here.
//
// Importing runner.js installs the shim as the `crypto`/`CryptoKey`
// globals (a module side effect there) and shares its GROUPS table, so a
// vendored group cannot reach one runner and miss the other.
//
// Records stream out through the world's `wpt:parity/reporter` import as
// each test settles — one `report` call per record, the JSON encoding of
// `{ group, name, status, message? }` — so a live embedder (the browser
// parity page) shows progress mid-run and a batch one (the Node round-trip
// leg) collects. `run` resolves after the last record, to
// `WPT-PARITY-STREAMED <count>` for the embedder to cross-check against
// what it received.
//
// Module specifiers resolve against componentize-js's base directory, the
// repository root.

import { report } from "wpt:parity/reporter@0.1.0";
import { GROUPS } from "./js/componentize/wpt/runner.js";
import { drain, setOnResult, takeResults } from "./js/componentize/wpt/harness.js";

export const demoWebcryptoDemoDemo010 = {
  run: async function () {
    let currentGroup = "";
    let count = 0;
    setOnResult(({ name, status, message }) => {
      count += 1;
      report(
        JSON.stringify(
          message === undefined
            ? { group: currentGroup, name, status }
            : { group: currentGroup, name, status, message },
        ),
      );
    });
    for (const [group, start] of GROUPS) {
      currentGroup = group;
      start();
      await drain();
      takeResults();
    }
    return `WPT-PARITY-STREAMED ${count}`;
  },
};

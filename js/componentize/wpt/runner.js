// The WPT runner guest: runs the vendored WPT WebCryptoAPI tests (see
// vendor/) against the WebCrypto-subset library in
// `js/componentize/webcrypto.js`, inside a componentize-js component. It
// exports the same `demo:webcrypto-demo/demo@0.1.0` entry point as the demo
// guests, so the existing `crypto-demo-driver` drives it through the same
// composed pipeline.
//
// The vendored files run unmodified: the justfile recipe concatenates each
// test group (helpers + vectors + test script) into a module under build/
// with an appended `export` of its entry point, and this runner supplies the
// testharness surface (harness.js) plus the `crypto`/`CryptoKey` globals.
//
// WPT sweeps parameters the library deliberately does not serve. Each
// result is classified by its test name: *in-subset* tests — those whose
// parameters the library documents as served — must all pass;
// *out-of-subset* tests are reported by count and expected to fail with
// the library's documented fail-closed errors. The group table and the
// classifiers defining the subset live in groups.js, shared with every
// other environment that runs these suites; this module binds the table
// to its static imports of the suite modules.
//
// Module specifiers resolve against componentize-js's `--base-directory`,
// which the justfile recipe sets to the repository root.

import "./js/componentize/wpt/install-shim-globals.js";
import { EXPECTED } from "./js/componentize/wpt/expected.js";
import { GROUPS as GROUP_TABLE } from "./js/componentize/wpt/groups.js";
import { drain, takeResults } from "./js/componentize/wpt/harness.js";
import * as groupHmac from "./js/componentize/wpt/build/group-hmac.js";
import * as groupAesGcm from "./js/componentize/wpt/build/group-aes-gcm.js";
import * as groupAesGcm256Iv from "./js/componentize/wpt/build/group-aes-gcm-256-iv.js";
import * as groupAesCbc from "./js/componentize/wpt/build/group-aes-cbc.js";
import * as groupAesCtr from "./js/componentize/wpt/build/group-aes-ctr.js";
import * as groupImportKey from "./js/componentize/wpt/build/group-import-key.js";
import * as groupGenerateKey from "./js/componentize/wpt/build/group-generate-key.js";
import * as groupGenerateKeyFailures from "./js/componentize/wpt/build/group-generate-key-failures.js";
import * as groupCfrgBits from "./js/componentize/wpt/build/group-cfrg-bits.js";
import * as groupCfrgKeys from "./js/componentize/wpt/build/group-cfrg-keys.js";
import * as groupOkpImportKey from "./js/componentize/wpt/build/group-okp-import-key.js";
import * as groupOkpImportKeyFailures from "./js/componentize/wpt/build/group-okp-import-key-failures.js";
import * as groupDigest from "./js/componentize/wpt/build/group-digest.js";
import * as groupEddsa from "./js/componentize/wpt/build/group-eddsa.js";
import * as groupEddsaSmallOrder from "./js/componentize/wpt/build/group-eddsa-small-order.js";
import * as groupEcdsa from "./js/componentize/wpt/build/group-ecdsa.js";
import * as groupEcImportKey from "./js/componentize/wpt/build/group-ec-import-key.js";
import * as groupEcImportKeyFailures from "./js/componentize/wpt/build/group-ec-import-key-failures.js";
import * as groupGetRandomValues from "./js/componentize/wpt/build/group-get-random-values.js";
import * as groupRandomUuid from "./js/componentize/wpt/build/group-random-uuid.js";
import * as groupHkdfDerive from "./js/componentize/wpt/build/group-hkdf-derive.js";
import * as groupPbkdf2Derive from "./js/componentize/wpt/build/group-pbkdf2-derive.js";
import * as groupDerivedBitsLength from "./js/componentize/wpt/build/group-derived-bits-length.js";

/** The statically imported suite modules, keyed as groups.js names them. */
const MODULES = {
  "group-hmac.js": groupHmac,
  "group-aes-gcm.js": groupAesGcm,
  "group-aes-gcm-256-iv.js": groupAesGcm256Iv,
  "group-aes-cbc.js": groupAesCbc,
  "group-aes-ctr.js": groupAesCtr,
  "group-import-key.js": groupImportKey,
  "group-generate-key.js": groupGenerateKey,
  "group-generate-key-failures.js": groupGenerateKeyFailures,
  "group-cfrg-bits.js": groupCfrgBits,
  "group-cfrg-keys.js": groupCfrgKeys,
  "group-okp-import-key.js": groupOkpImportKey,
  "group-okp-import-key-failures.js": groupOkpImportKeyFailures,
  "group-digest.js": groupDigest,
  "group-eddsa.js": groupEddsa,
  "group-eddsa-small-order.js": groupEddsaSmallOrder,
  "group-ecdsa.js": groupEcdsa,
  "group-ec-import-key.js": groupEcImportKey,
  "group-ec-import-key-failures.js": groupEcImportKeyFailures,
  "group-get-random-values.js": groupGetRandomValues,
  "group-random-uuid.js": groupRandomUuid,
  "group-hkdf-derive.js": groupHkdfDerive,
  "group-pbkdf2-derive.js": groupPbkdf2Derive,
  "group-derived-bits-length.js": groupDerivedBitsLength,
};

// --- runner -----------------------------------------------------------------------

// The shared table bound to the static imports above, as
// `[name, start, inSubset]` tuples. Exported for the parity runner
// (parity-runner.js), which runs the same groups without the subset gating.
export const GROUPS = GROUP_TABLE.map(({ name, module, start, inSubset }) => {
  const ns = MODULES[module];
  if (ns === undefined) {
    throw new Error(`groups.js names ${module}, which runner.js does not import`);
  }
  return [name, () => start(ns), inSubset];
});

export const demoWebcryptoDemoDemo010 = {
  run: async function () {
    const lines = [];
    const failures = [];
    const census = {};
    let totalIn = 0;
    let totalInPassed = 0;

    for (const [groupName, start, inSubset] of GROUPS) {
      start();
      await drain();
      const results = takeResults();

      let inPassed = 0;
      let inFailed = 0;
      let outPassed = 0;
      let outFailed = 0;
      for (const result of results) {
        if (inSubset(result.name)) {
          if (result.status === "PASS") {
            inPassed += 1;
          } else {
            inFailed += 1;
            failures.push(`${groupName} :: ${result.name}: ${result.message}`);
          }
        } else if (result.status === "PASS") {
          outPassed += 1;
        } else {
          outFailed += 1;
        }
      }
      census[groupName] = { inPassed, inFailed, outPassed, outFailed };
      totalIn += inPassed + inFailed;
      totalInPassed += inPassed;
      lines.push(
        `${groupName}: in-subset ${inPassed}/${inPassed + inFailed} passed; ` +
          `out-of-subset ${outFailed} failed as designed, ${outPassed} passed`,
      );
    }

    // Emitted on every run, pass or fail, so `just update-wpt-expectations`
    // can record it mechanically.
    const censusLine = `WPT-CENSUS ${JSON.stringify(census)}`;

    if (failures.length > 0) {
      throw new ComponentError(
        `${failures.length} in-subset WPT failures:\n` +
          failures.join("\n") +
          `\n${censusLine}`,
      );
    }

    // Counting the results is not the same as asserting them. Membership of
    // the subset is decided by matching WPT test *names*, so an upstream
    // rename can move a test from "must pass" to "expected to fail" with no
    // signal, and a suite that registers nothing at all yields 0/0 — which
    // passes every check above. Pin the whole census: any test appearing,
    // vanishing, or crossing the boundary in either direction is then a
    // failure with a reviewable diff, including an out-of-subset test that
    // starts passing (the sign the subset definition has drifted from what
    // the library actually serves).
    const drift = censusDrift(EXPECTED, census);
    if (drift.length > 0) {
      throw new ComponentError(
        `WPT census does not match js/componentize/wpt/expected.js:\n` +
          drift.join("\n") +
          `\nRe-record with \`just update-wpt-expectations\` once the change is understood.` +
          `\n${censusLine}`,
      );
    }

    return (
      `WPT WebCryptoAPI subset: ${totalInPassed}/${totalIn} in-subset tests passed\n` +
      lines.join("\n") +
      `\n${censusLine}`
    );
  },
};

/** Human-readable differences between the recorded and observed censuses. */
function censusDrift(expected, observed) {
  const drift = [];
  const groups = new Set([...Object.keys(expected), ...Object.keys(observed)]);
  for (const group of [...groups].sort()) {
    const want = expected[group];
    const got = observed[group];
    if (!want) {
      drift.push(`  + ${group}: not recorded (observed ${JSON.stringify(got)})`);
      continue;
    }
    if (!got) {
      drift.push(`  - ${group}: recorded but never ran (expected ${JSON.stringify(want)})`);
      continue;
    }
    for (const key of ["inPassed", "inFailed", "outPassed", "outFailed"]) {
      if (want[key] !== got[key]) {
        drift.push(`  ~ ${group}.${key}: expected ${want[key]}, observed ${got[key]}`);
      }
    }
  }
  return drift;
}

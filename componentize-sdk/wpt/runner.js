// The WPT runner guest: runs the vendored WPT WebCryptoAPI tests (see
// vendor/) against the WebCrypto-subset library in
// `componentize-sdk/webcrypto.js`, inside a componentize-js component. It
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
// the library's documented fail-closed errors. The classifiers below are
// the machine-readable definition of "the portion of WPT this library
// implements"; their doc comments enumerate each group's boundary.
//
// Module specifiers resolve against componentize-js's `--base-directory`,
// which the justfile recipe sets to the repository root.

import "./componentize-sdk/wpt/install-shim-globals.js";
import { EXPECTED } from "./componentize-sdk/wpt/expected.js";
import { drain, takeResults } from "./componentize-sdk/wpt/harness.js";
import { run_test as runHmac } from "./componentize-sdk/wpt/build/group-hmac.js";
import { run_test as runAesGcm } from "./componentize-sdk/wpt/build/group-aes-gcm.js";
import { runTests as runImportKey } from "./componentize-sdk/wpt/build/group-import-key.js";
import { run_test as runGenerateKey } from "./componentize-sdk/wpt/build/group-generate-key.js";
import { define_tests_25519 as defineCfrgBits } from "./componentize-sdk/wpt/build/group-cfrg-bits.js";
import { define_tests_25519 as defineCfrgKeys } from "./componentize-sdk/wpt/build/group-cfrg-keys.js";
import { runTests as runOkpImportKey } from "./componentize-sdk/wpt/build/group-okp-import-key.js";
import { run_test as runOkpImportKeyFailures } from "./componentize-sdk/wpt/build/group-okp-import-key-failures.js";

// --- the subset definition, one classifier per group ---------------------------

/** sign_verify/hmac: SHA-256 vectors; the wrong-algorithm tests need ECDSA. */
function hmacInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return name.includes("SHA-256") && !/wrong algorithm|generate wrong key/.test(name);
}

/**
 * encrypt_decrypt/aes_gcm (96-bit iv): 256-bit keys at every legal tag
 * length (per-call `tag-size` carries them all), plus the illegal-tag-length
 * rejections; other key sizes are out, as is the mismatched-key test (it
 * needs AES-CBC normalization to succeed before the key check).
 */
function gcmInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return name.includes("256-bit key") && !name.includes("mismatched key and algorithm");
}

/**
 * import_export/symmetric_importKey: the "raw" and "jwk" formats;
 * HMAC-SHA-256 at any key size, AES-GCM at 256 bits. Empty-usages tests
 * are in for any parameters (usages are validated before key material
 * either way).
 */
function importKeyInSubset(name) {
  if (!name.includes("(raw, ") && !name.includes("(jwk, ")) {
    return false;
  }
  if (name.startsWith("Empty Usages:")) {
    return true;
  }
  if (name.includes("{hash: SHA-256, name: HMAC}")) {
    return true;
  }
  if (name.includes("{name: AES-GCM}")) {
    return name.includes(" 256 bits ");
  }
  return false;
}

/**
 * generateKey/successes: HMAC-SHA-256 (default or explicit length) and
 * AES-GCM at 256 bits, extractable or not (extractable cases export raw
 * and JWK), at every legal usage combination (wrap/unwrap usages are key
 * metadata). Algorithm-name case variants are in (names are
 * case-insensitive).
 */
function generateKeyInSubset(name) {
  if (/name: hmac/i.test(name)) {
    return name.includes("hash: SHA-256");
  }
  if (/name: aes-gcm/i.test(name)) {
    return name.includes("length: 256");
  }
  return false;
}

/**
 * The X25519 groups (derive_bits_keys/cfrg_curves_*, import_export/okp_*,
 * generateKey/successes_X25519): the library serves no X25519 at all —
 * the WIT carries it (`lann:webcrypto/x25519` and `key-agreement`), but
 * `deriveBits`/`deriveKey` and OKP key formats are unserved shim surface
 * (see the header's deviations list) — so the subset is empty and every
 * test is an out-of-subset expected failure until the shim grows.
 */
function x25519InSubset() {
  return false;
}

// --- runner -----------------------------------------------------------------------

// Exported for the parity runner (parity-runner.js), which runs the same
// groups without the subset gating. The baseline leg (parity/baseline.mjs)
// cannot import this module — the shim's `lann:webcrypto` specifiers only
// resolve under componentize-js — so it carries its own copy of this table;
// the parity comparator fails on any drift between the two.
export const GROUPS = [
  ["sign_verify/hmac", () => runHmac(), hmacInSubset],
  ["encrypt_decrypt/aes_gcm (96-bit iv)", () => runAesGcm(), gcmInSubset],
  [
    "import_export/symmetric_importKey (HMAC, AES-GCM)",
    () => {
      runImportKey("HMAC");
      runImportKey("AES-GCM");
    },
    importKeyInSubset,
  ],
  [
    "generateKey/successes (HMAC, AES-GCM)",
    () => runGenerateKey(["HMAC", "AES-GCM"]),
    generateKeyInSubset,
  ],
  [
    "derive_bits_keys/cfrg_curves_bits (X25519)",
    () => promise_test(defineCfrgBits, "setup - define tests"),
    x25519InSubset,
  ],
  [
    "derive_bits_keys/cfrg_curves_keys (X25519)",
    () => promise_test(defineCfrgKeys, "setup - define tests"),
    x25519InSubset,
  ],
  ["import_export/okp_importKey (X25519)", () => runOkpImportKey("X25519"), x25519InSubset],
  [
    "import_export/okp_importKey_failures (X25519)",
    () => runOkpImportKeyFailures(["X25519"]),
    x25519InSubset,
  ],
  ["generateKey/successes (X25519)", () => runGenerateKey(["X25519"]), x25519InSubset],
];

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
        `WPT census does not match componentize-sdk/wpt/expected.js:\n` +
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

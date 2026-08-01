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
import { run_digest_tests as runDigest } from "./componentize-sdk/wpt/build/group-digest.js";
import { run_test as runEddsa } from "./componentize-sdk/wpt/build/group-eddsa.js";
import { run_test as runEddsaSmallOrder } from "./componentize-sdk/wpt/build/group-eddsa-small-order.js";
import { run_test as runEcdsa } from "./componentize-sdk/wpt/build/group-ecdsa.js";
import { run_ec_import_tests as runEcImportKey } from "./componentize-sdk/wpt/build/group-ec-import-key.js";
import { run_test as runEcImportKeyFailures } from "./componentize-sdk/wpt/build/group-ec-import-key-failures.js";
import { define_tests as defineHkdf } from "./componentize-sdk/wpt/build/group-hkdf-derive.js";
import { define_tests as definePbkdf2 } from "./componentize-sdk/wpt/build/group-pbkdf2-derive.js";

// --- the subset definition, one classifier per group ---------------------------

/**
 * sign_verify/hmac: the served SHA-2 family; SHA-1 rows are unserved, and
 * the wrong-algorithm tests need ECDSA.
 */
function hmacInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return /SHA-(256|384|512)/.test(name) && !/wrong algorithm|generate wrong key/.test(name);
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
  if (/\{hash: SHA-(256|384|512), name: HMAC\}/.test(name)) {
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
    return /hash: SHA-(256|384|512)/.test(name);
  }
  if (/name: aes-gcm/i.test(name)) {
    return name.includes("length: 256");
  }
  return false;
}

/**
 * The groups whose every test crosses unserved formats: the cfrg derive
 * and the eddsa/ecdsa sign_verify suites import all their keys as
 * pkcs8/spki (formats the WIT defers by the format-admission ruling), and
 * each generateKey success test exports its pair as spki + private JWK
 * (the private export is WIT-forced; see the shim header). Their subsets
 * are therefore empty: the algorithms' behavioral assertions live in the
 * conformance suites (and the demo guest covers the shim's own sign
 * path), and these groups meter the remaining format gap.
 */
function formatGatedInSubset() {
  return false;
}

/**
 * import_export/okp_importKey (Ed25519): raw public imports are served;
 * private OKP JWKs are not — Ed25519 signing keys are generate-only
 * (WIT-forced; see the shim header) — and public JWKs and pkcs8/spki are
 * unserved, as for X25519.
 * @param {string} name
 */
function okpEd25519ImportInSubset(name) {
  return name.includes("(raw, buffer(32)");
}

/**
 * import_export/okp_importKey_failures (Ed25519): the raw-format
 * rejections are served; every JWK form is out (no private import at
 * all, unlike X25519).
 * @param {string} name
 */
function okpEd25519FailuresInSubset(name) {
  return name.includes("(raw") || name.startsWith("Missing algorithm name");
}

/**
 * derive_bits_keys/{hkdf,pbkdf2}: the served subset is SHA-256/384/512
 * derivations over importable base secrets, with derived-key targets the
 * WIT's `derive-key` mints span (AES-GCM 256, HMAC-SHA-256).
 *
 * Excluded, in match order: subtests needing an ECDH key (`generateKey`
 * does not serve ECDH, so the fixture is null); the empty HKDF base key
 * (WIT-forced — `import-ikm` rejects empty material by ruling); unserved
 * derived-key targets; then SHA-1 rows — except the subtests whose
 * checks precede the hash (bad hash names, missing usages), which are
 * hash-independent and served for every row.
 *
 * The exclusions are whole-row, so the census pins a large `outPassed`
 * for these groups: an unserved-target row's bad-hash and missing-usage
 * subtests often expect the same `DOMException` name the unserved-target
 * refusal carries, and pass for that wrong reason. Claiming a
 * coincidence would let it silently break when the target is served, so
 * they stay out-of-subset, visible in the pinned census.
 * @param {string} name
 */
function kdfDeriveInSubset(name) {
  if (name === "setup - define tests") {
    return true;
  }
  if (name.includes("wrong (ECDH) key")) {
    return false;
  }
  if (name.includes("empty derivedKey")) {
    return false;
  }
  if (name.startsWith("Derived key of type")) {
    const served =
      name.startsWith("Derived key of type name: AES-GCM length: 256") ||
      /^Derived key of type name: HMAC hash: SHA-(256|384|512)/.test(name);
    if (!served) {
      return false;
    }
  }
  if (/bad hash name|missing deriveBits usage|missing deriveKey usage/.test(name)) {
    return true;
  }
  return !name.includes(", SHA-1, ");
}

/**
 * import_export/ec_importKey: raw uncompressed ECDSA P-256/P-384 public
 * imports are served (65- and 97-byte points); ECDH is not an algorithm
 * here at all, P-521 is declared by the WIT and served by nothing, and
 * the spki/pkcs8/jwk EC forms are unserved.
 * @param {string} name
 */
function ecImportInSubset(name) {
  return name.includes("name: ECDSA") && /\(raw, buffer\((65|97)\)/.test(name);
}

/**
 * import_export/ec_importKey_failures (ECDSA): raw-format rejections are
 * served — for P-521 only the usage rejections, whose check precedes the
 * curve's — plus the missing-algorithm-name rows, whose `TypeError`
 * precedes every format and curve consideration.
 * @param {string} name
 */
function ecImportFailuresInSubset(name) {
  if (name.startsWith("Missing algorithm name")) {
    return true;
  }
  if (!name.includes("(raw")) {
    return false;
  }
  return name.startsWith("Bad usages") || !name.includes("P-521");
}

/**
 * digest/digest: the served SHA-2 family (SHA-256/384/512, any name
 * casing), the bad-algorithm-name rejections, and the missing-name
 * `TypeError`s; SHA-1 rows are unserved (the WIT carries no SHA-1
 * anywhere).
 * @param {string} name
 */
function digestInSubset(name) {
  return !/^sha-1 /i.test(name);
}

/**
 * import_export/okp_importKey (X25519): raw public imports and
 * non-extractable private JWK imports are served. Extractable private
 * imports are excluded — each such test also exports the key, and private
 * export is WIT-forced (the shim header's registry); public JWKs and the
 * pkcs8/spki formats are unserved.
 * @param {string} name
 */
function okpImportInSubset(name) {
  if (name.includes("(raw, buffer(32)")) {
    return true;
  }
  return name.includes("object(crv, d, x, kty)") && name.includes("false, [");
}

/**
 * import_export/okp_importKey_failures (X25519): every raw-format and
 * private-JWK rejection is served; the public JWK form and pkcs8/spki are
 * unserved, so their expected errors are not this library's.
 * @param {string} name
 */
function okpImportFailuresInSubset(name) {
  return (
    name.includes("(raw") ||
    name.includes("jwk(private)") ||
    name.startsWith("Missing algorithm name")
  );
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
    formatGatedInSubset,
  ],
  [
    "derive_bits_keys/cfrg_curves_keys (X25519)",
    () => promise_test(defineCfrgKeys, "setup - define tests"),
    formatGatedInSubset,
  ],
  ["import_export/okp_importKey (X25519)", () => runOkpImportKey("X25519"), okpImportInSubset],
  [
    "import_export/okp_importKey_failures (X25519)",
    () => runOkpImportKeyFailures(["X25519"]),
    okpImportFailuresInSubset,
  ],
  ["generateKey/successes (X25519)", () => runGenerateKey(["X25519"]), formatGatedInSubset],
  [
    "derive_bits_keys/hkdf",
    () => promise_test(defineHkdf, "setup - define tests"),
    kdfDeriveInSubset,
  ],
  [
    "derive_bits_keys/pbkdf2",
    () => promise_test(definePbkdf2, "setup - define tests"),
    kdfDeriveInSubset,
  ],
  ["digest/digest", () => runDigest(), digestInSubset],
  ["sign_verify/eddsa (Ed25519)", () => runEddsa("Ed25519"), formatGatedInSubset],
  ["sign_verify/eddsa_small_order_points", () => runEddsaSmallOrder(), formatGatedInSubset],
  ["sign_verify/ecdsa", () => runEcdsa(), formatGatedInSubset],
  ["import_export/okp_importKey (Ed25519)", () => runOkpImportKey("Ed25519"), okpEd25519ImportInSubset],
  [
    "import_export/okp_importKey_failures (Ed25519)",
    () => runOkpImportKeyFailures(["Ed25519"]),
    okpEd25519FailuresInSubset,
  ],
  ["generateKey/successes (Ed25519)", () => runGenerateKey(["Ed25519"]), formatGatedInSubset],
  ["import_export/ec_importKey", () => runEcImportKey(), ecImportInSubset],
  [
    "import_export/ec_importKey_failures (ECDSA)",
    () => runEcImportKeyFailures(["ECDSA"]),
    ecImportFailuresInSubset,
  ],
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

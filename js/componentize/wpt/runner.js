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
// the library's documented fail-closed errors. The classifiers below are
// the machine-readable definition of "the portion of WPT this library
// implements"; their doc comments enumerate each group's boundary.
//
// Module specifiers resolve against componentize-js's `--base-directory`,
// which the justfile recipe sets to the repository root.

import "./js/componentize/wpt/install-shim-globals.js";
import { EXPECTED } from "./js/componentize/wpt/expected.js";
import { drain, takeResults } from "./js/componentize/wpt/harness.js";
import { run_test as runHmac } from "./js/componentize/wpt/build/group-hmac.js";
import { run_test as runAesGcm } from "./js/componentize/wpt/build/group-aes-gcm.js";
import { run_test as runAesCbc } from "./js/componentize/wpt/build/group-aes-cbc.js";
import { run_test as runAesCtr } from "./js/componentize/wpt/build/group-aes-ctr.js";
import { runTests as runImportKey } from "./js/componentize/wpt/build/group-import-key.js";
import { run_test as runGenerateKey } from "./js/componentize/wpt/build/group-generate-key.js";
import { define_tests_25519 as defineCfrgBits } from "./js/componentize/wpt/build/group-cfrg-bits.js";
import { define_tests_25519 as defineCfrgKeys } from "./js/componentize/wpt/build/group-cfrg-keys.js";
import { runTests as runOkpImportKey } from "./js/componentize/wpt/build/group-okp-import-key.js";
import { run_test as runOkpImportKeyFailures } from "./js/componentize/wpt/build/group-okp-import-key-failures.js";
import { run_digest_tests as runDigest } from "./js/componentize/wpt/build/group-digest.js";
import { run_test as runEddsa } from "./js/componentize/wpt/build/group-eddsa.js";
import { run_test as runEddsaSmallOrder } from "./js/componentize/wpt/build/group-eddsa-small-order.js";
import { run_test as runEcdsa } from "./js/componentize/wpt/build/group-ecdsa.js";
import { run_ec_import_tests as runEcImportKey } from "./js/componentize/wpt/build/group-ec-import-key.js";
import { run_test as runEcImportKeyFailures } from "./js/componentize/wpt/build/group-ec-import-key-failures.js";
import { run_get_random_values_tests as runGetRandomValues } from "./js/componentize/wpt/build/group-get-random-values.js";
import { define_tests as defineHkdf } from "./js/componentize/wpt/build/group-hkdf-derive.js";
import { define_tests as definePbkdf2 } from "./js/componentize/wpt/build/group-pbkdf2-derive.js";

// --- the subset definition, one classifier per group ---------------------------

/**
 * sign_verify/hmac: the served hashes (SHA-1 through the package's
 * `hmac-sha1` interface, and the SHA-2 family); the wrong-algorithm tests
 * need ECDSA generation (class D).
 */
function hmacInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return /SHA-(1|256|384|512)\b/.test(name) && !/wrong algorithm|generate wrong key/.test(name);
}

/**
 * encrypt_decrypt/aes_gcm (96-bit iv): 128- and 256-bit keys at every
 * legal tag length (per-call `tag-size` carries them all), plus the
 * illegal-tag-length rejections and the mismatched-key tests (their
 * AES-CBC fixture is served); AES-192 is declined package-wide.
 */
function gcmInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return /(128|256)-bit key/.test(name);
}

/**
 * encrypt_decrypt/{aes_cbc,aes_ctr}: 128- and 256-bit keys; AES-192 is
 * declined package-wide, and the mismatched-key test needs the *other*
 * unauthenticated mode's fixture to import (it does — both are served —
 * so it is in).
 * @param {string} name
 */
function cipherInSubset(name) {
  return name === "setup" || /(128|256)-bit key/.test(name);
}

/**
 * import_export/symmetric_importKey: the "raw" and "jwk" formats;
 * HMAC-SHA-256 at any key size, the AES family at 128/256 bits.
 * Empty-usages tests are in for any parameters (usages are validated
 * before key material either way).
 */
function importKeyInSubset(name) {
  if (!name.includes("(raw, ") && !name.includes("(jwk, ")) {
    return false;
  }
  if (name.startsWith("Empty Usages:")) {
    return true;
  }
  if (/\{hash: SHA-(1|256|384|512), name: HMAC\}/.test(name)) {
    return true;
  }
  if (/\{name: AES-(GCM|CBC|CTR)\}/.test(name)) {
    return / (128|256) bits /.test(name);
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
    return /hash: SHA-(1|256|384|512)\b/.test(name);
  }
  if (/name: aes-(gcm|cbc|ctr)/i.test(name)) {
    return /length: (128|256)/.test(name);
  }
  return false;
}

/**
 * sign_verify/ecdsa: every test needs ECDSA signing or a generated pair —
 * `ecdsa-sign` is class D, withheld by the in-guest provider this shim
 * composes with (see the shim header) — so the subset stays empty and the
 * group meters that gap. The verify path's behavioral assertions live in
 * the conformance suites.
 */
function classDGatedInSubset() {
  return false;
}

/**
 * derive_bits_keys/cfrg_curves_bits (X25519): served except "mismatched
 * algorithms", whose fixture needs an imported ECDH public key (null
 * here, so the failure is the wrong `TypeError`).
 * @param {string} name
 */
function cfrgBitsInSubset(name) {
  return !name.includes("mismatched algorithms");
}

/**
 * import_export/okp_importKey (Ed25519): every served form — raw and spki
 * public, private PKCS#8 and OKP JWKs (public and private).
 */
function okpEd25519ImportInSubset() {
  return true;
}

/**
 * import_export/okp_importKey_failures (Ed25519): every form's rejections
 * are served.
 */
function okpEd25519FailuresInSubset() {
  return true;
}

/**
 * derive_bits_keys/{hkdf,pbkdf2}: the served subset is SHA-256/384/512
 * derivations over importable base secrets, with derived-key targets the
 * WIT's `derive-key` mints span (AES-GCM 256, HMAC-SHA-256).
 *
 * Excluded, in match order: subtests needing an ECDH key (`generateKey`
 * does not serve ECDH, so the fixture is null); the empty HKDF base key
 * (WIT-forced — `import-ikm` rejects empty material by ruling); and
 * unserved derived-key targets. The SHA-1 rows are served (the
 * `hkdf-sha1`/`pbkdf2-sha1` interfaces).
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
      /^Derived key of type name: AES-(GCM|CBC|CTR) length: (128|256)/.test(name) ||
      /^Derived key of type name: HMAC hash: SHA-(1|256|384|512)\b/.test(name);
    if (!served) {
      return false;
    }
  }
  if (/bad hash name|missing deriveBits usage|missing deriveKey usage/.test(name)) {
    return true;
  }
  return true;
}

/**
 * import_export/ec_importKey: the public ECDSA P-256/P-384 forms are
 * served — raw and spki uncompressed points and public EC JWKs. Out: the
 * compressed-point rows (an optional feature: `assert_implements_optional`
 * is a failure in this two-status harness, and whether the WIT spki
 * import accepts compression is implementation-defined — the composed
 * provider happens to, which the census pins as `outPassed`), the private
 * forms (pkcs8 and JWKs carrying `d` — class D, see the shim header),
 * P-521 (declared by the WIT and served by nothing), and ECDH (not an
 * algorithm here at all).
 * @param {string} name
 */
function ecImportInSubset(name) {
  if (!name.includes("name: ECDSA") || name.includes("P-521") || name.includes("compressed")) {
    return false;
  }
  return !name.includes("(pkcs8") && !name.includes(", d)");
}

/**
 * import_export/ec_importKey_failures (ECDSA): the public-form rejections
 * are served — for P-521 only the usage rejections, whose check precedes
 * the curve's — plus the missing-algorithm-name rows, whose `TypeError`
 * precedes every format and curve consideration. The private forms stay
 * out (class D).
 * @param {string} name
 */
function ecImportFailuresInSubset(name) {
  if (name.startsWith("Missing algorithm name")) {
    return true;
  }
  if (name.includes("(pkcs8") || name.includes("jwk(private)")) {
    return false;
  }
  return name.startsWith("Bad usages") || !name.includes("P-521");
}

/** getRandomValues: the whole group is served. */
function getRandomValuesInSubset() {
  return true;
}

/**
 * digest/digest: the whole group — the SHA-2 family, the bad-algorithm-name
 * rejections, the missing-name `TypeError`s, and the SHA-1 rows, which the
 * shim serves through the package's `sha1-checked` interface (mitigating
 * posture: byte-identical to the platform on every honest input, which is
 * all WPT hashes).
 */
function digestInSubset() {
  return true;
}

/**
 * import_export/okp_importKey (X25519): every served form — raw and spki
 * public, private PKCS#8 and OKP JWKs (public and private), extractable
 * or not (the gated private exports are served).
 */
function okpImportInSubset() {
  return true;
}

/**
 * import_export/okp_importKey_failures (X25519): every form's rejections
 * are served.
 */
function okpImportFailuresInSubset() {
  return true;
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
  ["encrypt_decrypt/aes_cbc", () => runAesCbc(), cipherInSubset],
  ["encrypt_decrypt/aes_ctr", () => runAesCtr(), cipherInSubset],
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
    cfrgBitsInSubset,
  ],
  [
    "derive_bits_keys/cfrg_curves_keys (X25519)",
    () => promise_test(defineCfrgKeys, "setup - define tests"),
    cfrgBitsInSubset,
  ],
  ["import_export/okp_importKey (X25519)", () => runOkpImportKey("X25519"), okpImportInSubset],
  [
    "import_export/okp_importKey_failures (X25519)",
    () => runOkpImportKeyFailures(["X25519"]),
    okpImportFailuresInSubset,
  ],
  ["generateKey/successes (X25519)", () => runGenerateKey(["X25519"]), () => true],
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
  ["sign_verify/eddsa (Ed25519)", () => runEddsa("Ed25519"), () => true],
  ["sign_verify/eddsa_small_order_points", () => runEddsaSmallOrder(), () => true],
  ["sign_verify/ecdsa", () => runEcdsa(), classDGatedInSubset],
  ["import_export/okp_importKey (Ed25519)", () => runOkpImportKey("Ed25519"), okpEd25519ImportInSubset],
  [
    "import_export/okp_importKey_failures (Ed25519)",
    () => runOkpImportKeyFailures(["Ed25519"]),
    okpEd25519FailuresInSubset,
  ],
  ["generateKey/successes (Ed25519)", () => runGenerateKey(["Ed25519"]), () => true],
  ["import_export/ec_importKey", () => runEcImportKey(), ecImportInSubset],
  [
    "import_export/ec_importKey_failures (ECDSA)",
    () => runEcImportKeyFailures(["ECDSA"]),
    ecImportFailuresInSubset,
  ],
  ["getRandomValues", () => runGetRandomValues(), getRandomValuesInSubset],
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

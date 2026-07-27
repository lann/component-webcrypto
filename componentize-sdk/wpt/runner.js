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
// WPT sweeps parameters the library deliberately does not serve (other
// hashes and AES key sizes, JWK format, non-128-bit tag lengths, wrap/unwrap
// usages, extractable generateKey cases that export JWK). Each result is
// classified by its test name: *in-subset* tests — those whose parameters
// the library documents as served — must all pass; *out-of-subset* tests are
// reported by count and expected to fail with the library's documented
// fail-closed errors. The classifiers below are the machine-readable
// definition of "the portion of WPT this library implements".
//
// Module specifiers resolve against componentize-js's `--base-directory`,
// which the justfile recipe sets to the repository root.

import { crypto, CryptoKey } from "./componentize-sdk/webcrypto.js";
import { drain, takeResults } from "./componentize-sdk/wpt/harness.js";
import { run_test as runHmac } from "./componentize-sdk/wpt/build/group-hmac.js";
import { run_test as runAesGcm } from "./componentize-sdk/wpt/build/group-aes-gcm.js";
import { runTests as runImportKey } from "./componentize-sdk/wpt/build/group-import-key.js";
import { run_test as runGenerateKey } from "./componentize-sdk/wpt/build/group-generate-key.js";

globalThis.crypto = crypto;
globalThis.CryptoKey = CryptoKey;

// --- the subset definition, one classifier per group ---------------------------

/** sign_verify/hmac: SHA-256 vectors; the wrong-algorithm tests need ECDSA. */
function hmacInSubset(name) {
  if (name === "setup") {
    return true;
  }
  return name.includes("SHA-256") && !/wrong algorithm|generate wrong key/.test(name);
}

/**
 * encrypt_decrypt/aes_gcm (96-bit iv): 256-bit keys with 128-bit tags, plus
 * the illegal-tag-length rejections; other key sizes and legal-but-unserved
 * tag lengths are out, as is the mismatched-key test (it needs AES-CBC
 * normalization to succeed before the key check).
 */
function gcmInSubset(name) {
  if (name === "setup") {
    return true;
  }
  if (!name.includes("256-bit key") || name.includes("mismatched key and algorithm")) {
    return false;
  }
  return name.includes("128-bit tag") || name.includes("illegal tag length");
}

/**
 * import_export/symmetric_importKey: "raw" format only; HMAC-SHA-256 at any
 * key size, AES-GCM at 256 bits. Empty-usages tests are in for any
 * parameters (usages are validated before key material either way).
 */
function importKeyInSubset(name) {
  if (!name.includes("(raw, ")) {
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
 * generateKey/successes: non-extractable only (the extractable cases export
 * JWK, which the library does not serve), without wrap/unwrap usages;
 * HMAC-SHA-256 with the default length, AES-GCM at 256 bits. Algorithm-name
 * case variants are in (names are case-insensitive).
 */
function generateKeyInSubset(name) {
  if (!name.includes(", false, [") || /wrapKey|unwrapKey/.test(name)) {
    return false;
  }
  if (/name: hmac/i.test(name)) {
    return name.includes("hash: SHA-256") && !name.includes("length:");
  }
  if (/name: aes-gcm/i.test(name)) {
    return name.includes("length: 256");
  }
  return false;
}

// --- runner -----------------------------------------------------------------------

const GROUPS = [
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
];

export const demoWebcryptoDemoDemo010 = {
  run: async function () {
    const lines = [];
    const failures = [];
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
      totalIn += inPassed + inFailed;
      totalInPassed += inPassed;
      lines.push(
        `${groupName}: in-subset ${inPassed}/${inPassed + inFailed} passed; ` +
          `out-of-subset ${outFailed} failed as designed, ${outPassed} passed`,
      );
    }

    if (failures.length > 0) {
      throw new ComponentError(
        `${failures.length} in-subset WPT failures:\n` + failures.join("\n"),
      );
    }
    return (
      `WPT WebCryptoAPI subset: ${totalInPassed}/${totalIn} in-subset tests passed\n` +
      lines.join("\n")
    );
  },
};

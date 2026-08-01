// The recorded WPT census: how many tests each vendored group contributes to
// each bucket. `runner.js` asserts the observed census matches this exactly.
//
// Counting results is not asserting them. Subset membership is decided by
// matching WPT test *names*, so without this file an upstream rename could
// move a test from "must pass" to "expected to fail" silently, and a suite
// that registered nothing would report 0/0 in-subset passes and gate green
// having tested nothing. Pinning all four buckets makes any of those a
// failure with a diff — including an out-of-subset test that starts passing,
// which is the signal that the subset definition has drifted from what
// `componentize-sdk/webcrypto.js` actually serves.
//
// This is the WPT path's equivalent of conformance/*/tests.lock, and it is
// maintained the same way: regenerate with `just update-wpt-expectations`
// when a change to the library or the vendored files legitimately moves a
// number, and review the diff.

export const EXPECTED = {
  "sign_verify/hmac": { inPassed: 43, inFailed: 0, outPassed: 0, outFailed: 22 },
  "encrypt_decrypt/aes_gcm (96-bit iv)": { inPassed: 179, inFailed: 0, outPassed: 0, outFailed: 398 },
  "import_export/symmetric_importKey (HMAC, AES-GCM)": { inPassed: 260, inFailed: 0, outPassed: 0, outFailed: 100 },
  "generateKey/successes (HMAC, AES-GCM)": { inPassed: 240, inFailed: 0, outPassed: 0, outFailed: 240 },
  "derive_bits_keys/cfrg_curves_bits (X25519)": { inPassed: 0, inFailed: 0, outPassed: 3, outFailed: 16 },
  "derive_bits_keys/cfrg_curves_keys (X25519)": { inPassed: 0, inFailed: 0, outPassed: 4, outFailed: 13 },
  "import_export/okp_importKey (X25519)": { inPassed: 12, inFailed: 0, outPassed: 0, outFailed: 42 },
  "import_export/okp_importKey_failures (X25519)": { inPassed: 228, inFailed: 0, outPassed: 0, outFailed: 226 },
  "generateKey/successes (X25519)": { inPassed: 0, inFailed: 0, outPassed: 0, outFailed: 32 },
  "derive_bits_keys/hkdf": { inPassed: 577, inFailed: 0, outPassed: 788, outFailed: 2296 },
  "derive_bits_keys/pbkdf2": { inPassed: 1918, inFailed: 0, outPassed: 2025, outFailed: 4689 },
  "digest/digest": { inPassed: 92, inFailed: 0, outPassed: 0, outFailed: 24 },
};

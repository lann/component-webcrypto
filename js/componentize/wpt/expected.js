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
// `js/componentize/webcrypto.js` actually serves.
//
// This is the WPT path's equivalent of conformance/*/tests.lock, and it is
// maintained the same way: regenerate with `just update-wpt-expectations`
// when a change to the library or the vendored files legitimately moves a
// number, and review the diff.

export const EXPECTED = {
  "sign_verify/hmac": { inPassed: 57, inFailed: 0, outPassed: 0, outFailed: 8 },
  "encrypt_decrypt/aes_gcm (96-bit iv)": { inPassed: 385, inFailed: 0, outPassed: 0, outFailed: 192 },
  "encrypt_decrypt/aes_gcm (256-bit iv)": { inPassed: 385, inFailed: 0, outPassed: 0, outFailed: 192 },
  "encrypt_decrypt/aes_cbc": { inPassed: 41, inFailed: 0, outPassed: 0, outFailed: 20 },
  "encrypt_decrypt/aes_ctr": { inPassed: 35, inFailed: 0, outPassed: 0, outFailed: 17 },
  "import_export/symmetric_importKey (HMAC, AES-GCM)": { inPassed: 340, inFailed: 0, outPassed: 0, outFailed: 20 },
  "generateKey/successes (HMAC, AES-GCM)": { inPassed: 384, inFailed: 0, outPassed: 0, outFailed: 96 },
  "generateKey/failures (HMAC, AES, Ed25519, X25519)": { inPassed: 1974, inFailed: 0, outPassed: 0, outFailed: 0 },
  "derive_bits_keys/cfrg_curves_bits (X25519)": { inPassed: 18, inFailed: 0, outPassed: 0, outFailed: 1 },
  "derive_bits_keys/cfrg_curves_keys (X25519)": { inPassed: 16, inFailed: 0, outPassed: 0, outFailed: 1 },
  "import_export/okp_importKey (X25519)": { inPassed: 54, inFailed: 0, outPassed: 0, outFailed: 0 },
  "import_export/okp_importKey_failures (X25519)": { inPassed: 454, inFailed: 0, outPassed: 0, outFailed: 0 },
  "generateKey/successes (X25519)": { inPassed: 32, inFailed: 0, outPassed: 0, outFailed: 0 },
  "derive_bits_keys/hkdf": { inPassed: 1449, inFailed: 0, outPassed: 532, outFailed: 1680 },
  "derive_bits_keys/pbkdf2": { inPassed: 4474, inFailed: 0, outPassed: 1242, outFailed: 2916 },
  "derive_bits_keys/derived_bits_length": { inPassed: 22, inFailed: 0, outPassed: 0, outFailed: 7 },
  "digest/digest": { inPassed: 116, inFailed: 0, outPassed: 0, outFailed: 0 },
  "sign_verify/eddsa (Ed25519)": { inPassed: 19, inFailed: 0, outPassed: 0, outFailed: 0 },
  "sign_verify/eddsa_small_order_points": { inPassed: 14, inFailed: 0, outPassed: 0, outFailed: 0 },
  "sign_verify/ecdsa": { inPassed: 0, inFailed: 0, outPassed: 1, outFailed: 324 },
  "import_export/okp_importKey (Ed25519)": { inPassed: 72, inFailed: 0, outPassed: 0, outFailed: 0 },
  "import_export/okp_importKey_failures (Ed25519)": { inPassed: 530, inFailed: 0, outPassed: 0, outFailed: 0 },
  "generateKey/successes (Ed25519)": { inPassed: 36, inFailed: 0, outPassed: 0, outFailed: 0 },
  "import_export/ec_importKey": { inPassed: 36, inFailed: 0, outPassed: 12, outFailed: 216 },
  "import_export/ec_importKey_failures (ECDSA)": { inPassed: 276, inFailed: 0, outPassed: 0, outFailed: 344 },
  "getRandomValues": { inPassed: 39, inFailed: 0, outPassed: 0, outFailed: 0 },
  "randomUUID": { inPassed: 3, inFailed: 0, outPassed: 0, outFailed: 0 },
};

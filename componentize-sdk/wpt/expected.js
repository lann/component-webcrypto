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
  "sign_verify/hmac": { inPassed: 15, inFailed: 0, outPassed: 0, outFailed: 50 },
  "encrypt_decrypt/aes_gcm (96-bit iv)": {
    inPassed: 35,
    inFailed: 0,
    outPassed: 0,
    outFailed: 542,
  },
  "import_export/symmetric_importKey (HMAC, AES-GCM)": {
    inPassed: 78,
    inFailed: 0,
    outPassed: 0,
    outFailed: 282,
  },
  "generateKey/successes (HMAC, AES-GCM)": {
    inPassed: 21,
    inFailed: 0,
    outPassed: 0,
    outFailed: 459,
  },
};

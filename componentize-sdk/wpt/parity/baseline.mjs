// The baseline leg of the WPT parity gate: run the vendored WPT suites
// directly against this platform's own `crypto.subtle`, with no shim, no
// WIT, and no wasm in the path. The comparator holds the round trip to
// this leg's pass set, so whatever this platform does not implement falls
// out of scope without an exclusion list.
//
// Emits the same `{ group, name, status, message? }` records as
// parity-runner.js, as JSON on stdout.
//
// The group table below mirrors `GROUPS` in ../runner.js, which this
// module cannot import (the shim's `lann:webcrypto` specifiers only
// resolve under componentize-js). The comparator fails on any drift
// between the two: a group present in one leg and absent from the other
// surfaces as bulk name churn.

import { drain, takeResults } from "../harness.js";
import { run_test as runHmac } from "../build/group-hmac.js";
import { run_test as runAesGcm } from "../build/group-aes-gcm.js";
import { runTests as runImportKey } from "../build/group-import-key.js";
import { run_test as runGenerateKey } from "../build/group-generate-key.js";
import { define_tests_25519 as defineCfrgBits } from "../build/group-cfrg-bits.js";
import { define_tests_25519 as defineCfrgKeys } from "../build/group-cfrg-keys.js";
import { runTests as runOkpImportKey } from "../build/group-okp-import-key.js";
import { run_test as runOkpImportKeyFailures } from "../build/group-okp-import-key-failures.js";
import { run_digest_tests as runDigest } from "../build/group-digest.js";
import { define_tests as defineHkdf } from "../build/group-hkdf-derive.js";
import { define_tests as definePbkdf2 } from "../build/group-pbkdf2-derive.js";

const GROUPS = [
  ["sign_verify/hmac", () => runHmac()],
  ["encrypt_decrypt/aes_gcm (96-bit iv)", () => runAesGcm()],
  [
    "import_export/symmetric_importKey (HMAC, AES-GCM)",
    () => {
      runImportKey("HMAC");
      runImportKey("AES-GCM");
    },
  ],
  ["generateKey/successes (HMAC, AES-GCM)", () => runGenerateKey(["HMAC", "AES-GCM"])],
  [
    "derive_bits_keys/cfrg_curves_bits (X25519)",
    () => promise_test(defineCfrgBits, "setup - define tests"),
  ],
  [
    "derive_bits_keys/cfrg_curves_keys (X25519)",
    () => promise_test(defineCfrgKeys, "setup - define tests"),
  ],
  ["import_export/okp_importKey (X25519)", () => runOkpImportKey("X25519")],
  ["import_export/okp_importKey_failures (X25519)", () => runOkpImportKeyFailures(["X25519"])],
  ["generateKey/successes (X25519)", () => runGenerateKey(["X25519"])],
  ["derive_bits_keys/hkdf", () => promise_test(defineHkdf, "setup - define tests")],
  ["derive_bits_keys/pbkdf2", () => promise_test(definePbkdf2, "setup - define tests")],
  ["digest/digest", () => runDigest()],
];

const records = [];
for (const [group, start] of GROUPS) {
  start();
  await drain();
  for (const { name, status, message } of takeResults()) {
    records.push(message === undefined ? { group, name, status } : { group, name, status, message });
  }
}
process.stdout.write(JSON.stringify(records));

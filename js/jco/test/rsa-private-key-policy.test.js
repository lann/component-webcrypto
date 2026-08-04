// Tests for the RSA private-key environment-default policy — the posture
// the conformance suite cannot observe: its jco targets run under Node,
// where the default is to serve, so the decline default (browsers, unknown
// runtimes) and the module-level opt-in are exercised here by masking
// `globalThis.process`. One posture governs every gated RSA private-key
// minting interface — the two signing interfaces and `rsa-oaep-decrypt` —
// while the ungated `rsa-oaep-encrypt` is served everywhere, posture
// notwithstanding. These run the host directly — no component, no jco —
// because the policy is reached through the same minting functions a
// transpiled component calls.

import assert from "node:assert/strict";
import { after, test } from "node:test";

import {
  DecryptionKeyOptions,
  SigningKeyOptions,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
  rsaPssSign,
  rsassaPkcs1V15Sign,
  setRsaPrivateKeyPolicy,
} from "../webcrypto.js";

/** Restore the environment default, whatever a test set. */
const resetPolicy = () => setRsaPrivateKeyPolicy(undefined);
after(resetPolicy);

const options = () => {
  const o = new SigningKeyOptions();
  o.canSign(true);
  return o;
};

const decryptionOptions = () => {
  const o = new DecryptionKeyOptions();
  o.canDecrypt(true);
  return o;
};

/** Run `fn` with `globalThis.process` hidden, as in a browser. */
async function withoutNodeProcess(fn) {
  const saved = globalThis.process;
  delete globalThis.process;
  try {
    return await fn();
  } finally {
    globalThis.process = saved;
  }
}

const declined = (err) =>
  err.tag === "unsupported" && err.val.includes("setRsaPrivateKeyPolicy");

test("Node serves RSA signing by default", async () => {
  const [signing, verifying] = await rsassaPkcs1V15Sign.generateKey("sha256", "m2048", options());
  assert.equal(signing.algorithmName(), "RSASSA-PKCS1-v1_5");
  assert.equal(verifying.algorithmLength(), 2048);
});

test("Node serves RSA-OAEP decryption minting by default", async () => {
  const [decryption, encryption] = await rsaOaepDecrypt.generateKey(
    "sha256",
    "m2048",
    decryptionOptions(),
  );
  assert.equal(decryption.algorithmName(), "RSA-OAEP");
  assert.equal(encryption.algorithmLength(), 2048);
});

test("a non-Node environment declines every signing minting function by default", async () => {
  await withoutNodeProcess(async () => {
    for (const iface of [rsassaPkcs1V15Sign, rsaPssSign]) {
      await assert.rejects(() => iface.generateKey("sha256", "m2048", options()), declined);
      await assert.rejects(
        () => iface.importSigningKeyPkcs8("sha256", new Uint8Array(64), options()),
        declined,
      );
      await assert.rejects(() => iface.importSigningKeyJwk("sha256", "{}", options()), declined);
    }
  });
});

test("a non-Node environment declines every decryption minting function by default", async () => {
  await withoutNodeProcess(async () => {
    await assert.rejects(
      () => rsaOaepDecrypt.generateKey("sha256", "m2048", decryptionOptions()),
      declined,
    );
    await assert.rejects(
      () => rsaOaepDecrypt.importDecryptionKeyPkcs8("sha256", new Uint8Array(64), decryptionOptions()),
      declined,
    );
    await assert.rejects(
      () => rsaOaepDecrypt.importDecryptionKeyJwk("sha256", "{}", decryptionOptions()),
      declined,
    );
  });
});

test("encryption minting is served everywhere, posture notwithstanding", async () => {
  // `rsa-oaep-encrypt` is ungated: public-key operations are secret-free,
  // so neither the browser default nor an explicit decline reaches it.
  const [, encryption] = await rsaOaepDecrypt.generateKey("sha256", "m2048", decryptionOptions());
  const publicJwk = await encryption.exportKeyJwk();
  await withoutNodeProcess(async () => {
    setRsaPrivateKeyPolicy("decline");
    try {
      const key = await rsaOaepEncrypt.importEncryptionKeyJwk("sha256", publicJwk);
      const ciphertext = await key.encrypt(undefined, new Uint8Array([1, 2, 3]));
      assert.equal(ciphertext.length, 256);
    } finally {
      resetPolicy();
    }
  });
});

test("the posture check precedes argument validation", async () => {
  // A decline is uniform: a declined variant or a grantless options
  // resource must not change the answer a declining environment gives.
  await withoutNodeProcess(async () => {
    await assert.rejects(
      () => rsaPssSign.generateKey("sha1", "m2048", new SigningKeyOptions()),
      declined,
    );
    await assert.rejects(
      () => rsaOaepDecrypt.generateKey("sha1", "m2048", new DecryptionKeyOptions()),
      declined,
    );
  });
});

test("the opt-in serves a non-Node environment", async () => {
  await withoutNodeProcess(async () => {
    setRsaPrivateKeyPolicy("serve");
    try {
      const [signing] = await rsaPssSign.generateKey("sha256", "m2048", options());
      assert.equal(signing.algorithmName(), "RSA-PSS");
      const [decryption] = await rsaOaepDecrypt.generateKey(
        "sha256",
        "m2048",
        decryptionOptions(),
      );
      assert.equal(decryption.algorithmName(), "RSA-OAEP");
    } finally {
      resetPolicy();
    }
  });
});

test("an explicit decline overrides Node's serve default", async () => {
  setRsaPrivateKeyPolicy("decline");
  try {
    await assert.rejects(
      () => rsassaPkcs1V15Sign.generateKey("sha256", "m2048", options()),
      declined,
    );
    await assert.rejects(
      () => rsaOaepDecrypt.generateKey("sha256", "m2048", decryptionOptions()),
      declined,
    );
  } finally {
    resetPolicy();
  }
});

test("the policy is read per minting call, not captured at first use", async () => {
  // Flipping the policy between calls must govern the later call: the
  // check runs inside each mint rather than at module load.
  setRsaPrivateKeyPolicy("decline");
  try {
    await assert.rejects(
      () => rsassaPkcs1V15Sign.generateKey("sha256", "m2048", options()),
      declined,
    );
    setRsaPrivateKeyPolicy("serve");
    await rsassaPkcs1V15Sign.generateKey("sha256", "m2048", options());
  } finally {
    resetPolicy();
  }
});

test("the policy setter rejects unknown postures", () => {
  assert.throws(() => setRsaPrivateKeyPolicy("maybe"), TypeError);
  assert.throws(() => setRsaPrivateKeyPolicy(null), TypeError);
});

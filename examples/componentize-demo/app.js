// The componentize-demo guest: exercises the WebCrypto-subset library in
// `js/componentize/webcrypto.js` (HMAC-SHA-256 + AES-256-GCM over the
// `lann:webcrypto` imports) end to end, and exports the same
// `demo:webcrypto-demo/demo@0.1.0` entry point as the Rust `crypto-demo`
// guest so the existing `crypto-demo-driver` component can drive it.
//
// Module specifiers resolve against componentize-js's `--base-directory`,
// which the justfile recipe sets to the repository root — hence the
// root-relative library path below.

import {
  crypto,
  subtle,
  CryptoKey,
  DOMException,
  setSha1CollisionPolicy,
} from "./js/componentize/webcrypto.js";

const encoder = new TextEncoder();

// --- known-answer vectors (shared with the Rust crypto-demo guest) -----------

// RFC 4231 test case 2 (HMAC-SHA-256).
const HMAC_KEY = encoder.encode("Jefe");
const HMAC_DATA = encoder.encode("what do ya want for nothing?");
const HMAC_TAG = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

// NIST GCM revised spec, test case 16 (AES-256-GCM).
const GCM_KEY = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const GCM_IV = "cafebabefacedbaddecaf888";
const GCM_PLAINTEXT =
  "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72" +
  "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
const GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
const GCM_CIPHERTEXT =
  "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa" +
  "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
const GCM_TAG = "76fc6ece0f4e1768cddf8853bb2d551b";

// The first SHAttered message's five-block prefix: the shortest input on
// which sha1dc's collision detection fires (shared with the Rust
// conformance probe, which pins the same answers cross-target).
const SHATTERED_PREFIX =
  "255044462d312e330a25e2e3cfd30a0a0a312030206f626a0a3c3c2f57696474" +
  "682032203020522f4865696768742033203020522f547970652034203020522f" +
  "537562747970652035203020522f46696c7465722036203020522f436f6c6f72" +
  "53706163652037203020522f4c656e6774682038203020522f42697473506572" +
  "436f6d706f6e656e7420383e3e0a73747265616d0affd8fffe00245348412d31" +
  "20697320646561642121212121852fec092339759c39b1a1c63c4c97e1fffe01" +
  "7346dc9166b67e118f029ab621b2560ff9ca67cca8c7f85ba84c79030c2b3de2" +
  "18f86db3a90901d5df45c14f26fedfb3dc38e96ac22fe7bd728f0e45bce046d2" +
  "3c570feb141398bb552ef5a0a82be331fea48037b8b5d71f0e332edf93ac3500" +
  "eb4ddc0decc1a864790c782c76215660dd309791d06bd0af3f98cda4bc4629b1";
// Its deterministic sha1dc safe hash, and the FIPS 180-1 SHA-1 of "abc".
const SHATTERED_SAFE_HASH = "7117b3cb9225aaf0d8ef1a40e493957b0bf8693d";
const ABC_SHA1 = "a9993e364706816aba3e25717850c26c9cd0d89d";

// RFC 3394 §4.1 (AES-KW: a 128-bit KEK wrapping 128 bits of key data).
const KW_KEK = "000102030405060708090a0b0c0d0e0f";
const KW_DATA = "00112233445566778899aabbccddeeff";
const KW_WRAPPED = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";

// --- small helpers ------------------------------------------------------------

function hex(bytes) {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; ++i) {
    out[i] = parseInt(s.substring(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function expectEq(got, expected, what) {
  if (got !== expected) {
    throw new Error(`${what}: got ${got}, expected ${expected}`);
  }
}

async function expectDomException(name, what, f) {
  try {
    await f();
  } catch (e) {
    if (e instanceof DOMException && e.name === name) {
      return;
    }
    throw new Error(`${what}: expected ${name}, got ${e}`);
  }
  throw new Error(`${what}: expected ${name}, got success`);
}

// --- checks ---------------------------------------------------------------------

/** RFC 4231 known answer: import the raw key, `sign`, compare the tag. */
async function hmacKnownAnswer() {
  const key = await subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  if (!(key instanceof CryptoKey)) {
    throw new Error("importKey did not return a CryptoKey");
  }
  expectEq(key.algorithm.name, "HMAC", "key algorithm name");
  expectEq(key.algorithm.hash.name, "SHA-256", "key algorithm hash");
  expectEq(key.algorithm.length, HMAC_KEY.length * 8, "key algorithm length");
  const tag = await subtle.sign("HMAC", key, HMAC_DATA);
  expectEq(hex(tag), HMAC_TAG, "sign tag");
}

/**
 * `verify` accepts the vector's tag and rejects a tampered one — as `false`,
 * WebCrypto's verdict shape, never as a thrown error.
 */
async function hmacVerify() {
  const key = await subtle.importKey(
    "raw",
    HMAC_KEY,
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["verify"],
  );
  expectEq(await subtle.verify("HMAC", key, unhex(HMAC_TAG), HMAC_DATA), true, "good tag");
  const tampered = unhex(HMAC_TAG);
  tampered[0] ^= 0x01;
  expectEq(await subtle.verify("HMAC", key, tampered, HMAC_DATA), false, "tampered tag");
}

/**
 * `generateKey` mints WebCrypto's default HMAC-SHA-256 key (512-bit block
 * size of material); an extractable key round-trips through `exportKey` and
 * re-import, and signs consistently.
 */
async function hmacGenerateExport() {
  const key = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, [
    "sign",
    "verify",
  ]);
  expectEq(key.algorithm.length, 512, "generated key length");
  const raw = await subtle.exportKey("raw", key);
  expectEq(raw.byteLength, 64, "exported key bytes");
  const again = await subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, [
    "verify",
  ]);
  const tag = await subtle.sign("HMAC", key, HMAC_DATA);
  expectEq(await subtle.verify("HMAC", again, tag, HMAC_DATA), true, "re-imported verify");
}

/** A non-extractable key refuses `exportKey` with `InvalidAccessError`. */
async function hmacNonExtractable() {
  const key = await subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  expectEq(key.extractable, false, "extractable");
  await expectDomException("InvalidAccessError", "exportKey", () => subtle.exportKey("raw", key));
}

/** Usages are enforced: a verify-only key refuses `sign`. */
async function hmacUsageEnforced() {
  const key = await subtle.importKey("raw", HMAC_KEY, { name: "HMAC", hash: "SHA-256" }, false, [
    "verify",
  ]);
  await expectDomException("InvalidAccessError", "sign with verify-only key", () =>
    subtle.sign("HMAC", key, HMAC_DATA),
  );
}

/**
 * NIST GCM known answer: `encrypt` produces the vector's ciphertext ‖ tag
 * (the `subtle.encrypt` wire format).
 */
async function gcmKnownAnswerEncrypt() {
  const key = await subtle.importKey("raw", unhex(GCM_KEY), "AES-GCM", false, ["encrypt"]);
  expectEq(key.algorithm.name, "AES-GCM", "key algorithm name");
  expectEq(key.algorithm.length, 256, "key algorithm length");
  const sealed = await subtle.encrypt(
    { name: "AES-GCM", iv: unhex(GCM_IV), additionalData: unhex(GCM_AAD) },
    key,
    unhex(GCM_PLAINTEXT),
  );
  expectEq(hex(sealed), GCM_CIPHERTEXT + GCM_TAG, "sealed bytes");
}

/**
 * NIST GCM known answer, decrypt side; and both a tampered ciphertext and
 * tampered associated data are rejected with `OperationError`.
 */
async function gcmKnownAnswerDecrypt() {
  const key = await subtle.importKey("raw", unhex(GCM_KEY), "AES-GCM", false, ["decrypt"]);
  const sealed = unhex(GCM_CIPHERTEXT + GCM_TAG);
  const params = { name: "AES-GCM", iv: unhex(GCM_IV), additionalData: unhex(GCM_AAD) };
  const plaintext = await subtle.decrypt(params, key, sealed);
  expectEq(hex(plaintext), GCM_PLAINTEXT, "opened plaintext");

  const tampered = new Uint8Array(sealed);
  tampered[3] ^= 0x80;
  await expectDomException("OperationError", "tampered ciphertext", () =>
    subtle.decrypt(params, key, tampered),
  );
  await expectDomException("OperationError", "tampered aad", () =>
    subtle.decrypt(
      { name: "AES-GCM", iv: unhex(GCM_IV), additionalData: unhex(GCM_IV) },
      key,
      sealed,
    ),
  );
}

/**
 * A generated AES-256-GCM key round-trips encrypt → decrypt (including the
 * empty plaintext, whose sealed form is the bare 16-byte tag) and exports as
 * 32 bytes.
 */
async function gcmGenerateRoundtrip() {
  const key = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
  expectEq((await subtle.exportKey("raw", key)).byteLength, 32, "exported key bytes");

  const iv = unhex(GCM_IV);
  const message = encoder.encode("attack at dawn");
  const sealed = await subtle.encrypt({ name: "AES-GCM", iv }, key, message);
  expectEq(sealed.byteLength, message.length + 16, "sealed length");
  const opened = await subtle.decrypt({ name: "AES-GCM", iv }, key, sealed);
  expectEq(hex(opened), hex(message), "roundtrip plaintext");

  const emptySealed = await subtle.encrypt({ name: "AES-GCM", iv }, key, new Uint8Array(0));
  expectEq(emptySealed.byteLength, 16, "empty plaintext sealed length");
  const emptyOpened = await subtle.decrypt({ name: "AES-GCM", iv }, key, emptySealed);
  expectEq(emptyOpened.byteLength, 0, "empty plaintext roundtrip");
}

/**
 * Malformed requests fail closed: wrong-length raw AES key material is
 * `DataError`, an empty IV is `OperationError` (AES-GCM accepts any
 * non-empty IV), and an unsupported algorithm name is `NotSupportedError`.
 */
async function gcmRejectsMalformed() {
  await expectDomException("DataError", "31-byte key", () =>
    subtle.importKey("raw", new Uint8Array(31), "AES-GCM", false, ["encrypt"]),
  );
  const key = await subtle.importKey("raw", unhex(GCM_KEY), "AES-GCM", false, ["encrypt"]);
  await expectDomException("OperationError", "empty iv", () =>
    subtle.encrypt({ name: "AES-GCM", iv: new Uint8Array(0) }, key, HMAC_DATA),
  );
  // AES-KW keys serve the wrap pair alone: the registry defines no
  // encrypt operation for them.
  const kw = await subtle.importKey("raw", unhex(GCM_KEY), "AES-KW", false, ["wrapKey"]);
  await expectDomException("NotSupportedError", "AES-KW encrypt", () =>
    subtle.encrypt({ name: "AES-KW" }, kw, HMAC_DATA),
  );
  // The unauthenticated modes are served through the cipher kind: a CBC
  // round trip, and its uniform decrypt failure on a corrupted padding
  // block.
  const cbc = await subtle.importKey("raw", unhex(GCM_KEY), "AES-CBC", false, [
    "encrypt",
    "decrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, cbc, HMAC_DATA));
  const opened = new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, cbc, sealed));
  if (opened.length !== HMAC_DATA.length || opened.some((b, i) => b !== HMAC_DATA[i])) {
    throw new Error("AES-CBC round trip disagreed");
  }
  sealed[sealed.length - 1] ^= 0x01;
  await expectDomException("OperationError", "corrupt CBC padding", () =>
    subtle.decrypt({ name: "AES-CBC", iv }, cbc, sealed),
  );
}

// --- entry point -----------------------------------------------------------------

/**
 * JWK round trip: an HMAC key imported as an RFC 7517 `oct` JWK computes
 * the RFC 4231 known answer, and its export re-imports to the same key.
 */
async function jwkRoundtrip() {
  // "Jefe" as unpadded base64url.
  const jwk = { kty: "oct", k: "SmVmZQ", alg: "HS256" };
  const key = await subtle.importKey("jwk", jwk, { name: "HMAC", hash: "SHA-256" }, true, [
    "sign",
  ]);
  const tag = await subtle.sign("HMAC", key, HMAC_DATA);
  expectEq(hex(new Uint8Array(tag)), HMAC_TAG, "tag from JWK-imported key");

  const exported = await subtle.exportKey("jwk", key);
  expectEq(exported.kty, "oct", "exported kty");
  expectEq(exported.k, "SmVmZQ", "exported k");
  expectEq(exported.alg, "HS256", "exported alg");
  expectEq(exported.ext, true, "exported ext");
  const again = await subtle.importKey("jwk", exported, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const tag2 = await subtle.sign("HMAC", again, HMAC_DATA);
  expectEq(hex(new Uint8Array(tag2)), HMAC_TAG, "tag after JWK round trip");
}

/**
 * Malformed JWKs fail closed with `DataError`: wrong `kty`, an `alg`
 * disagreeing with the requested algorithm, padded (non-strict) base64url,
 * an `ext: false` conflict, and `key_ops` refusing a requested usage.
 */
async function jwkRejectsMalformed() {
  const cases = [
    ["wrong kty", { kty: "EC", k: "SmVmZQ" }],
    ["alg mismatch", { kty: "oct", k: "SmVmZQ", alg: "HS384" }],
    ["padded base64url", { kty: "oct", k: "SmVmZQ==" }],
    ["ext conflict", { kty: "oct", k: "SmVmZQ", ext: false }],
    ["key_ops mismatch", { kty: "oct", k: "SmVmZQ", key_ops: ["verify"] }],
  ];
  for (const [what, jwk] of cases) {
    await expectDomException("DataError", what, () =>
      subtle.importKey("jwk", jwk, { name: "HMAC", hash: "SHA-256" }, true, ["sign"]),
    );
  }
}

/**
 * Ed25519 through the shim, end to end: generate a pair, sign, verify,
 * reject a tampered signature and a tampered message, export the public
 * key raw and re-import it to the same verdicts. The vendored WPT
 * sign_verify suites import via spki, which the shim does not serve, so
 * this check is the gate on the shim's own sign/verify dispatch (the
 * algorithms themselves are pinned cross-target by the conformance
 * suites).
 */
async function ed25519SignVerify() {
  const message = new TextEncoder().encode("componentize-demo signs this");
  const pair = await subtle.generateKey("Ed25519", false, ["sign", "verify"]);
  if (!(pair.privateKey instanceof CryptoKey) || pair.privateKey.type !== "private") {
    throw new Error("generateKey did not yield a private CryptoKey");
  }
  if (pair.publicKey.usages.join() !== "verify" || pair.privateKey.usages.join() !== "sign") {
    throw new Error("pair usages did not split sign/verify");
  }
  const sig = new Uint8Array(await subtle.sign("Ed25519", pair.privateKey, message));
  if (sig.length !== 64) {
    throw new Error(`Ed25519 signature is ${sig.length} bytes, not 64`);
  }
  if (!(await subtle.verify("Ed25519", pair.publicKey, sig, message))) {
    throw new Error("fresh signature did not verify");
  }
  const tampered = sig.slice();
  tampered[0] ^= 1;
  if (await subtle.verify("Ed25519", pair.publicKey, tampered, message)) {
    throw new Error("tampered signature verified");
  }
  const wrongMessage = new TextEncoder().encode("some other message");
  if (await subtle.verify("Ed25519", pair.publicKey, sig, wrongMessage)) {
    throw new Error("signature verified over a different message");
  }
  const raw = await subtle.exportKey("raw", pair.publicKey);
  const reimported = await subtle.importKey("raw", raw, "Ed25519", true, ["verify"]);
  if (!(await subtle.verify("Ed25519", reimported, sig, message))) {
    throw new Error("signature did not verify under the re-imported public key");
  }
  await expectDomException("InvalidAccessError", "sign with the public key", () =>
    subtle.sign("Ed25519", pair.publicKey, message),
  );
  await expectDomException("InvalidAccessError", "export the non-extractable private key", () =>
    subtle.exportKey("jwk", pair.privateKey),
  );
  // An extractable private key round-trips through the gated JWK export:
  // the re-import signs, and the original public half verifies it.
  const extractable = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const privateJwk = await subtle.exportKey("jwk", extractable.privateKey);
  if (privateJwk.kty !== "OKP" || typeof privateJwk.d !== "string") {
    throw new Error("exported private JWK is not an OKP key carrying d");
  }
  const reimportedPrivate = await subtle.importKey("jwk", privateJwk, "Ed25519", false, ["sign"]);
  const sig2 = await subtle.sign("Ed25519", reimportedPrivate, message);
  if (!(await subtle.verify("Ed25519", extractable.publicKey, sig2, message))) {
    throw new Error("signature from the re-imported private key did not verify");
  }
}

/**
 * getRandomValues through the shim: fills from the host entropy, returns
 * the array, honors the type and quota errors.
 */
async function getRandomValuesCheck() {
  const a = crypto.getRandomValues(new Uint8Array(64));
  const b = crypto.getRandomValues(new Uint8Array(64));
  if (a.every((byte, i) => byte === b[i])) {
    throw new Error("two 64-byte fills were identical");
  }
  if (new Set(a).size < 8) {
    throw new Error("64 random bytes with fewer than 8 distinct values");
  }
  const words = crypto.getRandomValues(new BigUint64Array(4));
  if (words.length !== 4 || (words[0] === 0n && words[1] === 0n && words[2] === 0n && words[3] === 0n)) {
    throw new Error("BigUint64Array fill looks wrong");
  }
  await expectDomException("TypeMismatchError", "float fill", () =>
    Promise.resolve().then(() => crypto.getRandomValues(new Float64Array(4))),
  );
  await expectDomException("QuotaExceededError", "oversized fill", () =>
    Promise.resolve().then(() => crypto.getRandomValues(new Uint8Array(65537))),
  );
}

/**
 * `digest("SHA-1")` and the collision policy, end to end: honest input
 * digests to standard SHA-1 in both postures; input carrying a collision
 * attack yields the deterministic sha1dc safe hash under the default
 * mitigating posture, and under `setSha1CollisionPolicy("reject")` throws
 * `OperationError` (the shim's mapping of the package's
 * `("lann:webcrypto", "collision-detected")` extension condition; the
 * `bindings-transport` check asserts the condition's delivery).
 */
async function sha1CollisionPolicy() {
  const attacked = unhex(SHATTERED_PREFIX);
  try {
    // The default posture: mitigate.
    expectEq(hex(await subtle.digest("SHA-1", encoder.encode("abc"))), ABC_SHA1, "mitigate: abc");
    expectEq(hex(await subtle.digest("SHA-1", attacked)), SHATTERED_SAFE_HASH, "mitigate: attacked input safe hash");

    setSha1CollisionPolicy("reject");
    expectEq(hex(await subtle.digest("SHA-1", encoder.encode("abc"))), ABC_SHA1, "reject: abc");
    await expectDomException("OperationError", "reject: attacked input", () =>
      subtle.digest("SHA-1", attacked),
    );
  } finally {
    setSha1CollisionPolicy("mitigate");
  }
  let badPolicy;
  try {
    setSha1CollisionPolicy("plain");
  } catch (e) {
    badPolicy = e;
  }
  if (!(badPolicy instanceof TypeError)) {
    throw new Error(`invalid policy: expected TypeError, got ${badPolicy ?? "success"}`);
  }
}

/**
 * Bindings-transport probe: asserts field-exact delivery of the composite
 * WIT shapes whose transport no known-answer check observes. A toolchain
 * that permutes or truncates a shape's fields (#184's record reversal)
 * fails here directly, not as a downstream crypto mismatch.
 *
 * Today that is the `extension-error` record — the package's only
 * multi-field record — delivered by the rejecting SHA-1 digest's error
 * and preserved verbatim as the `DOMException`'s `cause`. All three
 * string fields are asserted exactly, `message` included: this is a
 * transport assertion (bytes in = bytes out, the message pinned as the
 * Rust conformance probe pins it), not a consumer contract on the
 * message. The other shapes crossing the boundary are covered
 * incidentally but adequately elsewhere: enum discriminants and
 * list/string payloads by every known-answer check, `generate-key`'s
 * tuple order by ed25519-sign-verify (a swapped tuple delivers
 * wrong-typed resource handles), option/bool/numeric getters by the key
 * metadata assertions. New shapes (key-storage metadata records,
 * stream-aead parameters) get their assertions here as they land.
 */
async function bindingsTransport() {
  let thrown;
  try {
    setSha1CollisionPolicy("reject");
    await subtle.digest("SHA-1", unhex(SHATTERED_PREFIX));
  } catch (e) {
    thrown = e;
  } finally {
    setSha1CollisionPolicy("mitigate");
  }
  if (thrown === undefined) {
    throw new Error("a rejecting digest hashed an attacked input");
  }
  const payload = thrown.cause;
  expectEq(payload?.tag, "extension", "error variant tag");
  const ext = payload?.val;
  expectEq(
    Object.keys(ext ?? {})
      .sort()
      .join(),
    "message,name,origin",
    "extension-error field census",
  );
  expectEq(ext?.origin, "lann:webcrypto", "extension-error origin");
  expectEq(ext?.name, "collision-detected", "extension-error name");
  expectEq(
    ext?.message,
    "input carries a SHA-1 collision attack pattern",
    "extension-error message",
  );
}

/**
 * RFC 3394 §4.1 known answer: `wrapKey("raw")` under an AES-KW KEK
 * reproduces the vector's wrapped bytes, a tampered wrap fails closed,
 * and `unwrapKey` mints the key data back out as a working key.
 */
async function aesKwKnownAnswer() {
  const kek = await subtle.importKey("raw", unhex(KW_KEK), { name: "AES-KW" }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
  expectEq(kek.algorithm.name, "AES-KW", "KEK algorithm name");
  expectEq(kek.algorithm.length, 128, "KEK algorithm length");
  const payload = await subtle.importKey("raw", unhex(KW_DATA), { name: "AES-GCM" }, true, [
    "encrypt",
    "decrypt",
  ]);

  const wrapped = await subtle.wrapKey("raw", payload, kek, { name: "AES-KW" });
  expectEq(hex(wrapped), KW_WRAPPED, "RFC 3394 wrapped bytes");

  const tampered = new Uint8Array(wrapped.slice(0));
  tampered[0] ^= 1;
  await expectDomException("OperationError", "tampered unwrap", () =>
    subtle.unwrapKey("raw", tampered, kek, { name: "AES-KW" }, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]),
  );

  const minted = await subtle.unwrapKey(
    "raw",
    wrapped,
    kek,
    { name: "AES-KW" },
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
  expectEq(minted.extractable, false, "unwrapped key extractability");
  expectEq(minted.algorithm.length, 128, "unwrapped key length");
  // The minted key is the wrapped material: what it seals, the original
  // material opens.
  const iv = unhex(GCM_IV);
  const sealed = await subtle.encrypt({ name: "AES-GCM", iv }, minted, HMAC_DATA);
  const opened = await subtle.decrypt({ name: "AES-GCM", iv }, payload, sealed);
  expectEq(hex(opened), hex(HMAC_DATA), "cross-key round trip");
}

/**
 * The AEAD wrap path: a `wrapKey("jwk")` under AES-GCM round-trips
 * through `unwrapKey` (minting non-extractable), the wrap gate refuses
 * non-extractable keys, and the format sweep matches the export rules.
 */
async function wrapUnwrapRoundtrip() {
  const kek = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "wrapKey",
    "unwrapKey",
  ]);
  const iv = unhex(GCM_IV);
  const wrapParams = { name: "AES-GCM", iv };
  const hmacAlg = { name: "HMAC", hash: "SHA-256" };
  const payload = await subtle.importKey("raw", unhex(KW_KEK), hmacAlg, true, ["sign"]);

  const wrapped = await subtle.unwrapKey(
    "jwk",
    await subtle.wrapKey("jwk", payload, kek, wrapParams),
    kek,
    wrapParams,
    hmacAlg,
    false,
    ["sign"],
  );
  expectEq(wrapped.extractable, false, "unwrapped key extractability");
  const viaWrap = await subtle.sign("HMAC", wrapped, HMAC_DATA);
  const direct = await subtle.sign("HMAC", payload, HMAC_DATA);
  expectEq(hex(viaWrap), hex(direct), "wrapped and direct keys agree");

  // The wrap gate: a non-extractable key cannot enter the wrap path.
  const sealed = await subtle.importKey("raw", unhex(KW_DATA), hmacAlg, false, ["sign"]);
  await expectDomException("InvalidAccessError", "wrapping a non-extractable key", () =>
    subtle.wrapKey("raw", sealed, kek, wrapParams),
  );
  // A wrapping key without the grant refuses.
  const sealOnly = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  await expectDomException("InvalidAccessError", "wrapping under an ungranted key", () =>
    subtle.wrapKey("raw", payload, sealOnly, wrapParams),
  );
}

/**
 * The unwrap path enforces a foreign wrap's JWK metadata: `ext: false`
 * against an extractable unwrap, and a `key_ops` set missing a requested
 * usage, are both the platform's `DataError`. (Built by encrypting
 * hand-written JWK text — the WPT census cannot observe the WIT's
 * unwrap-path member checks any other way.)
 */
async function unwrapEnforcesJwkMetadata() {
  const kekRaw = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "wrapKey",
    "unwrapKey",
  ]);
  const iv = unhex(GCM_IV);
  const params = { name: "AES-GCM", iv };
  const hmacAlg = { name: "HMAC", hash: "SHA-256" };
  const k = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

  const wrapOf = async (members) =>
    subtle.encrypt(params, kekRaw, encoder.encode(JSON.stringify({ kty: "oct", k, ...members })));

  // ext: false cannot unwrap extractable…
  await expectDomException("DataError", "ext:false unwrapped extractable", async () =>
    subtle.unwrapKey("jwk", await wrapOf({ ext: false }), kekRaw, params, hmacAlg, true, ["sign"]),
  );
  // …but unwraps non-extractable.
  await subtle.unwrapKey("jwk", await wrapOf({ ext: false }), kekRaw, params, hmacAlg, false, [
    "sign",
  ]);
  // key_ops must cover every requested usage.
  await expectDomException("DataError", "key_ops missing a requested usage", async () =>
    subtle.unwrapKey(
      "jwk",
      await wrapOf({ key_ops: ["sign"] }),
      kekRaw,
      params,
      hmacAlg,
      false,
      ["sign", "verify"],
    ),
  );
  await subtle.unwrapKey(
    "jwk",
    await wrapOf({ key_ops: ["sign", "verify"] }),
    kekRaw,
    params,
    hmacAlg,
    false,
    ["sign", "verify"],
  );
}

const CHECKS = [
  ["hmac-known-answer", hmacKnownAnswer],
  ["hmac-verify", hmacVerify],
  ["hmac-generate-export", hmacGenerateExport],
  ["hmac-non-extractable", hmacNonExtractable],
  ["hmac-usage-enforced", hmacUsageEnforced],
  ["gcm-known-answer-encrypt", gcmKnownAnswerEncrypt],
  ["gcm-known-answer-decrypt", gcmKnownAnswerDecrypt],
  ["gcm-generate-roundtrip", gcmGenerateRoundtrip],
  ["gcm-rejects-malformed", gcmRejectsMalformed],
  ["aes-kw-known-answer", aesKwKnownAnswer],
  ["wrap-unwrap-roundtrip", wrapUnwrapRoundtrip],
  ["unwrap-enforces-jwk-metadata", unwrapEnforcesJwkMetadata],
  ["jwk-roundtrip", jwkRoundtrip],
  ["jwk-rejects-malformed", jwkRejectsMalformed],
  ["ed25519-sign-verify", ed25519SignVerify],
  ["get-random-values", getRandomValuesCheck],
  ["sha1-collision-policy", sha1CollisionPolicy],
  ["bindings-transport", bindingsTransport],
];

// The `demo:webcrypto-demo/demo@0.1.0` export. `run` returns the ok summary
// string; a failure is thrown as a `ComponentError` (the componentize-js
// convention for an exported function's `err` result).
export const demoWebcryptoDemoDemo010 = {
  run: async function () {
    const passed = [];
    for (const [name, check] of CHECKS) {
      try {
        await check();
      } catch (e) {
        throw new ComponentError(`check ${name}: ${e}`);
      }
      passed.push(name);
    }
    return `${passed.length} checks passed: ${passed.join(", ")}`;
  },
};

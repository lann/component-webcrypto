// Host implementation of the `lann:webcrypto` imports (`mac`, `aead`,
// `digest`, `bytes`, `hmac-sha2`, `aes-gcm`, `chacha20-poly1305`, `sha2`)
// for jco-transpiled components.
//
// This is the "browser-first" host: it is written against the standard Web
// Crypto API only — `globalThis.crypto.subtle` and
// `globalThis.crypto.getRandomValues` — so the same file runs unchanged in a
// browser. No `node:crypto` imports and no Node-only APIs are used; Node
// provides the same globals natively.
//
// `jco --map` wires this module in as the component's imports: the `mac`,
// `aead`, and `digest` resource interfaces map to the module itself (the
// `MacKey`, `AeadKey`, and `Digest` class exports), while the minting and
// utility interfaces map to named exports (`--map '…=./webcrypto.js#hmacSha2'`,
// `#aesGcm`, `#chacha20Poly1305`, `#sha2`, `#bytes`) since the minting names
// would otherwise collide.
//
// ## jco conventions this host relies on
//
// Two aspects of the jco runtime's host-facing surface are conventions
// rather than documented API, so they are isolated behind single functions
// and version-anchored here. Validated against jco 1.26.1 /
// jco-transpile 0.5.2 (the versions pinned by this repo's npm consumers);
// revalidate both functions when bumping either package.
//
// - **Error lifting** (`witError`, and every throw site through it): a WIT
//   `result<_, error>` err case is produced by throwing the variant's
//   payload value — `{ tag, val? }` — which the generated bindings lift.
//   Anything else thrown out of this host is unliftable and becomes a trap,
//   so every platform call goes through `platformCall`, which maps
//   `DOMException`s onto the taxonomy.
// - **Stream ingestion** (`collectByteStream`): guest-provided `stream<u8>`
//   values arrive as jco's async-iterable `Stream` objects (a web
//   `ReadableStream` is also tolerated), with chunk batching left to the
//   runtime. Chunk *ownership* is not part of that contract, so ingested
//   chunks are copied (`toByteChunk`) rather than retained by reference.
//   Host-returned `stream<u8>` values are web `ReadableStream`s of
//   `Uint8Array`.

const subtle = globalThis.crypto.subtle;

/**
 * Construct the throwable representation of a WIT `types.error` case: jco's
 * convention lifts a thrown `{ tag, val? }` into the declared
 * `result<_, error>` (see the header note; the sole place that convention
 * is encoded).
 * @param {string} tag
 * @param {string} [val]
 */
function witError(tag, val) {
  return val === undefined ? { tag } : { tag, val };
}

/** `error.invalid-key` with a human-readable detail. */
function errInvalidKey(val) {
  return witError("invalid-key", val);
}

/** `error.invalid-nonce` with a human-readable detail. */
function errInvalidNonce(val) {
  return witError("invalid-nonce", val);
}

/** `error.authentication-failed` (deliberately detail-free). */
function errAuthenticationFailed() {
  return witError("authentication-failed");
}

/** `error.not-extractable`. */
function errNotExtractable() {
  return witError("not-extractable");
}

/** `error.unsupported` with a human-readable detail. */
function errUnsupported(val) {
  return witError("unsupported", val);
}

/** `error.key-exhausted`. */
function errKeyExhausted() {
  return witError("key-exhausted");
}

/** `error.other` with a human-readable detail. */
function errOther(val) {
  return witError("other", val);
}

/** Whether `value` is already a WIT error payload (`{ tag, val? }`). */
function isWitError(value) {
  return typeof value === "object" && value !== null && typeof value.tag === "string";
}

/**
 * Await a `crypto.subtle` call, lifting any platform failure into the WIT
 * error taxonomy.
 *
 * Every platform call goes through this. A `DOMException` escaping the host
 * is not a `{ tag, val }` payload, so the bindings cannot lift it into the
 * declared `result<_, error>`: it becomes a trap, and the guest sees the
 * component abort instead of the error the WIT mandates. `NotSupportedError`
 * is precisely the WIT's "well-formed request this implementation does not
 * serve" (`error.unsupported`) — an engine without Ed25519, or declining a
 * curve, reports it; every other platform failure is operational, so
 * `error.other`.
 * @template T
 * @param {string} what
 * @param {() => Promise<T>} run
 * @returns {Promise<T>}
 */
async function platformCall(what, run) {
  try {
    return await run();
  } catch (err) {
    if (isWitError(err)) throw err;
    if (err?.name === "NotSupportedError") {
      throw errUnsupported(`${what} is not served by this platform: ${err.message ?? err}`);
    }
    throw errOther(`${what} failed: ${err?.message ?? err}`);
  }
}

/**
 * The hash name and block length for each served `sha2-variant` enum case
 * (jco lowers WIT enums as their kebab-case names). The truncated variants
 * (sha224, sha512-224, sha512-256) are absent: WebCrypto does not serve
 * them, so this implementation declines them (see the WIT `sha2-variant`
 * doc).
 */
const SHA2_VARIANTS = {
  sha256: { hash: "SHA-256", blockBytes: 64 },
  sha384: { hash: "SHA-384", blockBytes: 128 },
  sha512: { hash: "SHA-512", blockBytes: 128 },
};

/**
 * The served `sha2-variant` entry for `variant`, throwing
 * `{ tag: 'unsupported', val }` for a variant this implementation declines.
 */
function sha2Variant(variant) {
  const entry = SHA2_VARIANTS[variant];
  if (entry === undefined) {
    throw errUnsupported(`${variant} is not served by this implementation`);
  }
  return entry;
}

/**
 * The `mac-key` resource: an HMAC key bound to a SHA-2 variant. Holds a
 * `CryptoKey` imported with usages `["sign", "verify"]` and the caller's
 * `extractable` flag; instances are minted only by the `hmac-sha2`
 * interface functions below.
 * `sign`/`verify` are one-shot and stateless per call, matching
 * `subtle.sign`/`verify` exactly (WebCrypto has no incremental HMAC): each
 * call collects its entire input stream, then signs or verifies it whole.
 */
export class MacKey {
  #key;

  /** @param {CryptoKey} key */
  constructor(key) {
    this.#key = key;
  }

  /**
   * Compute the authentication tag over an entire byte stream, resolving
   * once the stream is fully drained.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async sign(data) {
    const reservation = await admitInput();
    try {
      const message = await collectByteStream(data, reservation.cap);
      return new Uint8Array(
        await platformCall("HMAC sign", () => subtle.sign("HMAC", this.#key, message)),
      );
    } finally {
      reservation.release();
    }
  }

  /**
   * Verify `tag` against the tag computed over an entire byte stream; the
   * platform performs the constant-time comparison. Throws
   * `{ tag: 'authentication-failed' }` if the tag does not verify.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   * @param {Uint8Array} tag
   */
  async verify(data, tag) {
    const reservation = await admitInput();
    try {
      const message = await collectByteStream(data, reservation.cap);
      const ok = await platformCall("HMAC verify", () =>
        subtle.verify("HMAC", this.#key, tag, message),
      );
      if (!ok) {
        throw errAuthenticationFailed();
      }
    } finally {
      reservation.release();
    }
  }

  /**
   * The algorithm getters: direct projections of the `CryptoKey`'s
   * `HmacKeyAlgorithm` (`name`, `hash.name`, and `length`).
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmHash() {
    return this.#key.algorithm.hash?.name;
  }

  algorithmLength() {
    return this.#key.algorithm.length;
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the key
   * was created with `extractable` true (checked on the `CryptoKey` itself
   * rather than relying on the `DOMException` from `exportKey`).
   */
  async exportKey() {
    if (!this.#key.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }
}

/**
 * The `aead-key` resource: an AES-GCM key. Holds a `CryptoKey` imported
 * with usages `["encrypt", "decrypt"]` and the caller's `extractable` flag;
 * instances are minted only by the `aes-gcm` interface functions below.
 */
export class AeadKey {
  #key;

  /** @param {CryptoKey} key */
  constructor(key) {
    this.#key = key;
  }

  /**
   * Encrypt and authenticate the plaintext stream under `nonce` and `aad`.
   * Returns a `ReadableStream` carrying ciphertext followed by the 16-byte
   * authentication tag (the `crypto.subtle.encrypt` wire format). Throws
   * `{ tag: 'invalid-nonce', val }` for a nonce that is not exactly 12 bytes
   * (AES-GCM per this package's WIT; WebCrypto itself would accept other
   * lengths). The plaintext stream is drained before any failure is raised,
   * so the guest's writer always completes rather than blocking on an
   * unread stream.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async seal(nonce, aad, plaintext) {
    const reservation = await admitInput();
    let handedOff = false;
    try {
      const message = await collectByteStream(plaintext, reservation.cap);
      requireGcmNonce(nonce);
      const sealed = await platformCall("AES-GCM seal", () =>
        subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, this.#key, message),
      );
      handedOff = true;
      return bytesToStream(new Uint8Array(sealed), reservation);
    } finally {
      if (!handedOff) reservation.release();
    }
  }

  /**
   * Decrypt and verify the ciphertext‖tag stream under `nonce` and `aad`.
   * Resolves only after the stream is fully drained and the tag verified
   * (`subtle.decrypt` releases no unverified plaintext); a verification
   * failure throws `{ tag: 'authentication-failed' }`. As with `seal`, the
   * ciphertext stream is drained before any failure is raised.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {AsyncIterable<unknown> | ReadableStream} ciphertext
   */
  async open(nonce, aad, ciphertext) {
    const reservation = await admitInput();
    let handedOff = false;
    try {
      const message = await collectByteStream(ciphertext, reservation.cap);
      requireGcmNonce(nonce);
      let opened;
      try {
        opened = await subtle.decrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad },
          this.#key,
          message,
        );
      } catch {
        // WebCrypto reports every decrypt failure as an opaque
        // OperationError; the WIT error deliberately carries no detail
        // either.
        throw errAuthenticationFailed();
      }
      handedOff = true;
      return bytesToStream(new Uint8Array(opened), reservation);
    } finally {
      if (!handedOff) reservation.release();
    }
  }

  /**
   * The algorithm getters: direct projections of the `CryptoKey`'s
   * `AesKeyAlgorithm` (`name` and `length`), plus the operation-contract
   * sizes (every AEAD this host serves is AES-GCM: 12-byte nonces, 16-byte
   * tags).
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#key.algorithm.length;
  }

  nonceSize() {
    return 12;
  }

  tagSize() {
    return 16;
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the key
   * was created with `extractable` true (checked on the `CryptoKey` itself
   * rather than relying on the `DOMException` from `exportKey`).
   */
  async exportKey() {
    if (!this.#key.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }
}

/**
 * Import raw key material as an HMAC key over the declared SHA-2 variant. A
 * variant this implementation declines throws `{ tag: 'unsupported', val }`.
 * Any non-empty length is accepted (RFC 2104); empty material throws
 * `{ tag: 'invalid-key', val }`.
 * @param {string} variant
 * @param {Uint8Array} raw
 * @param {boolean} extractable
 */
async function importHmacKey(variant, raw, extractable) {
  const { hash } = sha2Variant(variant);
  if (raw.length === 0) throw errInvalidKey("empty key");
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "HMAC", hash }, extractable, [
      "sign",
      "verify",
    ]);
  } catch (err) {
    throw errInvalidKey(String(err));
  }
  return new MacKey(key);
}

/**
 * Generate a fresh random HMAC key over the declared SHA-2 variant, with
 * the underlying hash's block size of key material (WebCrypto's
 * `generateKey` default). A variant this implementation declines throws
 * `{ tag: 'unsupported', val }`.
 * @param {string} variant
 * @param {boolean} extractable
 */
async function generateHmacKey(variant, extractable) {
  const { hash } = sha2Variant(variant);
  const key = await platformCall(`HMAC-${hash} key generation`, () =>
    subtle.generateKey({ name: "HMAC", hash }, extractable, ["sign", "verify"]),
  );
  return new MacKey(key);
}

/** The `lann:webcrypto/hmac-sha2` interface (`--map '…#hmacSha2'`). */
export const hmacSha2 = { importKey: importHmacKey, generateKey: generateHmacKey };

/**
 * The `digest` resource: a digest algorithm bound at creation. Holds only
 * the variant's hash name; `compute` is one-shot and stateless per call
 * (`subtle.digest` exactly), so the resource is reusable. Instances are
 * minted only by the `sha2` interface function below.
 */
export class Digest {
  #hash;

  /** @param {string} hash */
  constructor(hash) {
    this.#hash = hash;
  }

  /**
   * Digest an entire byte stream, resolving once the stream is fully
   * drained. The WIT `err` case carries only operational failures here:
   * an input beyond the per-call buffer limit, or a platform digest
   * failure lifted by `platformCall`.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async compute(data) {
    const reservation = await admitInput();
    try {
      const message = await collectByteStream(data, reservation.cap);
      return new Uint8Array(
        await platformCall(`${this.#hash} digest`, () => subtle.digest(this.#hash, message)),
      );
    } finally {
      reservation.release();
    }
  }

  /** The registry name of the algorithm, e.g. `"SHA-256"`. */
  algorithmName() {
    return this.#hash;
  }
}

/**
 * A `digest` bound to the declared SHA-2 variant. A variant this
 * implementation declines throws `{ tag: 'unsupported', val }`.
 * @param {string} variant
 */
function makeDigest(variant) {
  return new Digest(sha2Variant(variant).hash);
}

/** The `lann:webcrypto/sha2` interface (`--map '…#sha2'`). */
export const sha2 = { makeDigest };

/**
 * Whether `a` and `b` are equal, in time independent of their contents
 * (necessarily dependent on their lengths). WebCrypto has no comparison
 * primitive and `timingSafeEqual` is Node-only, so this is a hand-rolled
 * accumulate-then-test XOR loop with no data-dependent branches.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** The `lann:webcrypto/bytes` interface (`--map '…#bytes'`). */
export const bytes = { constantTimeEqual };

/**
 * The raw key length in bytes for each served `aes-variant` enum case (jco
 * lowers WIT enums as their kebab-case names). AES-192 is absent: this
 * implementation declines it (browsers do not reliably serve it — Chromium
 * implements no AES-192; see the WIT `aes-variant` doc).
 */
const AES_VARIANT_BYTES = { aes128: 16, aes256: 32 };

/**
 * The raw key length in bytes declared by `variant`, throwing
 * `{ tag: 'unsupported', val }` for a variant this implementation declines.
 */
function aesVariantByteLength(variant) {
  const expected = AES_VARIANT_BYTES[variant];
  if (expected === undefined) {
    throw errUnsupported(`${variant} is not served by this implementation`);
  }
  return expected;
}

/**
 * Import raw key material as the declared AES variant. A variant this
 * implementation declines throws `{ tag: 'unsupported', val }`; material
 * whose length disagrees with `variant` throws `{ tag: 'invalid-key', val }`.
 * @param {string} variant
 * @param {Uint8Array} raw
 * @param {boolean} extractable
 */
async function importAesKey(variant, raw, extractable) {
  const expected = aesVariantByteLength(variant);
  if (raw.length !== expected) {
    throw errInvalidKey(
      `${variant} requires ${expected} key bytes, got ${raw.length}`,
    );
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, extractable, [
      "encrypt",
      "decrypt",
    ]);
  } catch (err) {
    throw errInvalidKey(String(err));
  }
  return new AeadKey(key);
}

/**
 * Generate a fresh random AES key of the declared variant. A variant this
 * implementation declines throws `{ tag: 'unsupported', val }`.
 * @param {string} variant
 * @param {boolean} extractable
 */
async function generateAesKey(variant, extractable) {
  const length = aesVariantByteLength(variant) * 8;
  const key = await platformCall(`${variant} key generation`, () =>
    subtle.generateKey({ name: "AES-GCM", length }, extractable, ["encrypt", "decrypt"]),
  );
  return new AeadKey(key);
}

/** The `lann:webcrypto/aes-gcm` interface (`--map '…#aesGcm'`). */
export const aesGcm = { importKey: importAesKey, generateKey: generateAesKey };

/**
 * Throw `{ tag: 'unsupported', val }` for a ChaCha construction: browser
 * WebCrypto implements no ChaCha20-Poly1305 (the WICG proposal is
 * unimplemented), so this host declines these interfaces whole and a
 * composition needing them must supply another provider (the in-guest
 * provider serves both constructions).
 * @param {string} name
 */
function unsupportedChacha(name) {
  throw errUnsupported(`${name} is not served by this implementation`);
}

/** The `lann:webcrypto/chacha20-poly1305` interface (`--map '…#chacha20Poly1305'`). */
export const chacha20Poly1305 = {
  importKey: async () => unsupportedChacha("ChaCha20-Poly1305"),
  generateKey: async () => unsupportedChacha("ChaCha20-Poly1305"),
};

/** The `lann:webcrypto/xchacha20-poly1305` interface (`--map '…#xchacha20Poly1305'`). */
export const xchacha20Poly1305 = {
  importKey: async () => unsupportedChacha("XChaCha20-Poly1305"),
  generateKey: async () => unsupportedChacha("XChaCha20-Poly1305"),
};

/** The `lann:webcrypto/xchacha20-poly1305-internal-nonce` interface (`--map '…#xchachaInternalNonce'`). */
export const xchachaInternalNonce = {
  importKey: async () => unsupportedChacha("XChaCha20-Poly1305"),
  generateKey: async () => unsupportedChacha("XChaCha20-Poly1305"),
};

/**
 * The `internal-nonce-key` resource: an AES-GCM key whose nonce is generated
 * here per `seal` (the SP 800-38D §8.2.2 RBG-based construction: 96 random
 * bits from `getRandomValues`) and carried as the sealed message's prefix
 * (`iv ‖ ciphertext ‖ tag`, per the `aes-gcm-internal-nonce` interface
 * docs). Only AES-GCM keys exist on this host: browser WebCrypto implements
 * no ChaCha20-Poly1305, so the ChaCha minting interface declines below.
 *
 * The key counts its `seal` invocations against the WIT nonce budget (2^32
 * for 12-byte nonces) and throws `{ tag: 'key-exhausted' }` beyond it.
 */
export class InternalNonceKey {
  #key;
  #sealed = 0n;

  /** The 12-byte AES-GCM IV length. */
  static #IV_BYTES = 12;

  /** The WIT nonce budget for 12-byte nonces: 2^32 seal invocations. */
  static #NONCE_BUDGET = 1n << 32n;

  /** @param {CryptoKey} key */
  constructor(key) {
    this.#key = key;
  }

  /**
   * Encrypt and authenticate the plaintext stream under a fresh random IV
   * with `aad`, returning `iv ‖ ciphertext ‖ tag`. The plaintext stream is
   * drained before any failure is raised, per the WIT drain rule.
   * @param {Uint8Array} aad
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async seal(aad, plaintext) {
    const reservation = await admitInput();
    let handedOff = false;
    try {
      const message = await collectByteStream(plaintext, reservation.cap);
      if (this.#sealed >= InternalNonceKey.#NONCE_BUDGET) {
        throw errKeyExhausted();
      }
      this.#sealed += 1n;
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(InternalNonceKey.#IV_BYTES));
      const body = new Uint8Array(
        await platformCall("AES-GCM seal", () =>
          subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, this.#key, message),
        ),
      );
      const sealed = new Uint8Array(iv.length + body.length);
      sealed.set(iv, 0);
      sealed.set(body, iv.length);
      handedOff = true;
      return bytesToStream(sealed, reservation);
    } finally {
      if (!handedOff) reservation.release();
    }
  }

  /**
   * Decrypt and verify a sealed message (`iv ‖ ciphertext ‖ tag`) under
   * `aad`. Any failure — input too short to carry the wire format, a bad
   * tag, wrong associated data — throws `{ tag: 'authentication-failed' }`
   * with no detail, per the WIT contract. The input stream is drained
   * before any failure is raised.
   * @param {Uint8Array} aad
   * @param {AsyncIterable<unknown> | ReadableStream} sealed
   */
  async open(aad, sealed) {
    const reservation = await admitInput();
    let handedOff = false;
    try {
      const message = await collectByteStream(sealed, reservation.cap);
      if (message.length < InternalNonceKey.#IV_BYTES) {
        throw errAuthenticationFailed();
      }
      const iv = message.subarray(0, InternalNonceKey.#IV_BYTES);
      const body = message.subarray(InternalNonceKey.#IV_BYTES);
      let opened;
      try {
        opened = await subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          this.#key,
          body,
        );
      } catch {
        throw errAuthenticationFailed();
      }
      handedOff = true;
      return bytesToStream(new Uint8Array(opened), reservation);
    } finally {
      if (!handedOff) reservation.release();
    }
  }

  /** The algorithm getters: direct `AesKeyAlgorithm` projections. */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#key.algorithm.length;
  }

  /**
   * The remaining seal budget (the WIT 2^32 bound for 12-byte nonces minus
   * seals so far), as a rotation-scheduling hint.
   */
  sealsRemaining() {
    const remaining = InternalNonceKey.#NONCE_BUDGET - this.#sealed;
    return remaining > 0n ? remaining : 0n;
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the
   * key was created with `extractable` true.
   */
  async exportKey() {
    if (!this.#key.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }
}

/**
 * Import raw key material as an internal-nonce AES-GCM key of the declared
 * variant. Same variant/length contract as `aesGcm.importKey`.
 * @param {string} variant
 * @param {Uint8Array} raw
 * @param {boolean} extractable
 */
async function importAesInternalNonceKey(variant, raw, extractable) {
  const expected = aesVariantByteLength(variant);
  if (raw.length !== expected) {
    throw errInvalidKey(
      `${variant} requires ${expected} key bytes, got ${raw.length}`,
    );
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, extractable, [
      "encrypt",
      "decrypt",
    ]);
  } catch (err) {
    throw errInvalidKey(String(err));
  }
  return new InternalNonceKey(key);
}

/**
 * Generate a fresh random internal-nonce AES-GCM key of the declared
 * variant.
 * @param {string} variant
 * @param {boolean} extractable
 */
async function generateAesInternalNonceKey(variant, extractable) {
  const length = aesVariantByteLength(variant) * 8;
  const key = await platformCall(`${variant} key generation`, () =>
    subtle.generateKey({ name: "AES-GCM", length }, extractable, ["encrypt", "decrypt"]),
  );
  return new InternalNonceKey(key);
}

/** The `lann:webcrypto/aes-gcm-internal-nonce` interface (`--map '…#aesGcmInternalNonce'`). */
export const aesGcmInternalNonce = {
  importKey: importAesInternalNonceKey,
  generateKey: generateAesInternalNonceKey,
};

/**
 * Throw `{ tag: 'invalid-nonce', val }` unless `nonce` is the 12 bytes
 * AES-GCM specifies in this package's WIT.
 * @param {Uint8Array} nonce
 */
function requireGcmNonce(nonce) {
  if (nonce.length !== 12) {
    throw errInvalidNonce(`AES-GCM requires a 12-byte nonce, got ${nonce.length}`);
  }
}

/**
 * Input-buffering limits. Every stream-taking operation buffers its whole
 * input (the single-message contract), and concurrent calls multiply — so
 * admission bounds aggregate retention: each operation reserves its
 * per-call cap from a shared pool before collecting, waiting FIFO when the
 * pool is full, and releases when its buffers are gone (including the
 * returned output stream). Inputs beyond the per-call cap are drained and
 * discarded (the WIT drain rule holds) and the operation throws a
 * recoverable `{ tag: 'other' }`. Defaults mirror the wasmtime host: a
 * 128 MiB pool, per-call cap of a quarter of it.
 */
const DEFAULT_TOTAL_BUFFER_LIMIT = 128 * 1024 * 1024;

const bufferLimits = { perCall: undefined, total: undefined };

/**
 * Configure the input-buffering limits (bytes). `undefined` restores a
 * value's default.
 * @param {{ perCallBufferLimit?: number, totalBufferLimit?: number }} options
 */
export function configure({ perCallBufferLimit, totalBufferLimit } = {}) {
  bufferLimits.perCall = perCallBufferLimit;
  bufferLimits.total = totalBufferLimit;
}

/** The effective `(perCall, total)` limits, clamped like the wasmtime host. */
function effectiveBufferLimits() {
  const total = Math.max(1, bufferLimits.total ?? DEFAULT_TOTAL_BUFFER_LIMIT);
  const perCall = Math.max(1, Math.min(bufferLimits.perCall ?? Math.floor(total / 4), total));
  return { perCall, total };
}

let reservedBytes = 0;
/** @type {{ amount: number, total: number, resolve: () => void }[]} */
const admitQueue = [];

/** Admit queued reservations from the front while they fit (FIFO). */
function admitFromFront() {
  while (admitQueue.length > 0 && reservedBytes + admitQueue[0].amount <= admitQueue[0].total) {
    const entry = admitQueue.shift();
    reservedBytes += entry.amount;
    entry.resolve();
  }
}

/**
 * Reserve one operation's buffering capacity, waiting FIFO for the pool.
 * The returned reservation's `release` is idempotent.
 * @returns {Promise<{ cap: number, release: () => void }>}
 */
async function admitInput() {
  const { perCall, total } = effectiveBufferLimits();
  const amount = Math.min(perCall, total);
  await new Promise((resolve) => {
    admitQueue.push({ amount, total, resolve });
    admitFromFront();
  });
  let released = false;
  return {
    cap: amount,
    release() {
      if (!released) {
        released = true;
        reservedBytes -= amount;
        admitFromFront();
      }
    },
  };
}

/**
 * A single-chunk byte `ReadableStream` over `bytes`, releasing
 * `reservation` (when given) once the bytes are handed off or the stream
 * is cancelled.
 */
function bytesToStream(bytes, reservation = undefined) {
  return new ReadableStream({
    pull(controller) {
      if (bytes.length) controller.enqueue(bytes);
      controller.close();
      reservation?.release();
    },
    cancel() {
      reservation?.release();
    },
  });
}

/**
 * Coerce one chunk of a WIT byte stream (a number, an array of numbers, or a
 * typed array, depending on how the runtime batched the read) to a
 * `Uint8Array` the collector owns.
 *
 * A typed-array chunk is *copied*, never retained by reference: nothing in
 * the runtime's stream contract promises the chunk is not a view over a
 * buffer the next read reuses, and `collectByteStream` holds every chunk
 * until the stream ends. Aliasing there would silently corrupt plaintext or
 * ciphertext — the copy costs one pass over bytes already copied at
 * concatenation.
 */
function toByteChunk(value) {
  if (typeof value === "number") return Uint8Array.of(value);
  if (value instanceof Uint8Array) return value.slice();
  return Uint8Array.from(value);
}

/**
 * Collect every byte of a WIT byte stream into one `Uint8Array`, retaining
 * at most `cap` bytes: past the cap the stream is still drained (the WIT
 * drain rule) but discarded, and a recoverable `{ tag: 'other' }` is thrown
 * once the stream ends.
 */
async function collectByteStream(stream, cap = Infinity) {
  let chunks = [];
  let total = 0;
  let overflowed = false;
  const push = (value) => {
    if (value === undefined || value === null) return;
    const chunk = toByteChunk(value);
    if (!chunk.length) return;
    if (!overflowed && total + chunk.length > cap) {
      // Stop retaining (free what we held), keep draining below.
      overflowed = true;
      chunks = [];
    }
    if (!overflowed) {
      chunks.push(chunk);
      total += chunk.length;
    }
  };
  if (globalThis.ReadableStream && stream instanceof ReadableStream) {
    const reader = stream.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        push(value);
      }
    } finally {
      reader.releaseLock();
    }
  } else if (typeof stream.read === "function") {
    // jco's own Stream object: read in batches rather than per element.
    for (;;) {
      const { value, done } = await stream.read({ count: 65536 });
      push(value);
      if (done) break;
    }
  } else {
    for await (const value of stream) {
      push(value);
    }
  }
  if (overflowed) {
    throw errOther(
      `input exceeds the per-call buffer limit (${cap} bytes); see configure()`,
    );
  }
  return concatChunks(chunks, total);
}

/** Concatenate `chunks` (totalling `total` bytes) into one `Uint8Array`. */
function concatChunks(chunks, total) {
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * The per-variant ECDSA parameters: WebCrypto's `namedCurve`, the
 * mint-bound hash, the uncompressed-SEC1 public key length, the raw scalar
 * length, the exact P1363 signature width the WIT fixes, and the curve OID
 * for the PKCS#8 wrapping.
 *
 * Every per-curve quantity lives here rather than in a ternary at its use
 * site: a ternary keyed on one curve silently hands every *other* curve
 * that branch's value, so adding a curve would weaken the checks these
 * quantities drive.
 */
const ECDSA_VARIANTS = {
  "p256-sha256": {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
    publicLength: 65,
    scalarLength: 32,
    signatureLength: 64,
    curveOid: [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  },
  "p384-sha384": {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-384",
    publicLength: 97,
    scalarLength: 48,
    signatureLength: 96,
    curveOid: [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
  },
};

/**
 * The Ed25519 algorithm record, in the same shape as an `ECDSA_VARIANTS`
 * entry: no curve, no mint-bound hash (RFC 8032 fixes SHA-512 internally),
 * a 32-byte public key and a 64-byte `R ‖ S` signature.
 */
const ED25519_ALGORITHM = {
  name: "Ed25519",
  namedCurve: undefined,
  hash: undefined,
  publicLength: 32,
  scalarLength: 32,
  signatureLength: 64,
};

/**
 * The served `ecdsa-variant` entry for `variant`, throwing
 * `{ tag: 'unsupported', val }` for anything unknown.
 */
function ecdsaVariant(variant) {
  const entry = ECDSA_VARIANTS[variant];
  if (entry === undefined) {
    throw errUnsupported(`${variant} is not served by this implementation`);
  }
  return entry;
}

/** The WebCrypto sign/verify algorithm parameter for a key's mint binding. */
function signParams(algorithm) {
  return algorithm.name === "ECDSA" ? { name: "ECDSA", hash: algorithm.hash } : algorithm.name;
}

/**
 * The `verifying-key` resource: a public `CryptoKey` plus the algorithm
 * record bound at mint (`ED25519_ALGORITHM` or an `ECDSA_VARIANTS` entry).
 * The record — not `CryptoKey.algorithm` — is the authority for every
 * algorithm fact this class needs: the hash WebCrypto passes per-operation
 * for ECDSA, the signature width, and the getters' answers. Instances are
 * minted by the `ed25519-verify` / `ecdsa-verify` interface functions
 * below, or paired with a `SigningKey` by `generate-key`.
 */
export class VerifyingKey {
  #key;
  #algorithm;

  /**
   * @param {CryptoKey} key
   * @param {typeof ED25519_ALGORITHM} algorithm the mint-bound algorithm record
   */
  constructor(key, algorithm) {
    this.#key = key;
    this.#algorithm = algorithm;
  }

  /**
   * Verify `sig` over an entire byte stream; resolves only after the stream
   * is fully drained. Throws `{ tag: 'authentication-failed' }` on failure
   * (including malformed signatures — WebCrypto reports both as `false`).
   *
   * The validation predicates below branch on the algorithm record bound at
   * mint, never on `CryptoKey.algorithm`: an engine that names its
   * algorithms differently must not be able to switch a mandatory check
   * off.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   * @param {Uint8Array} sig
   */
  async verify(data, sig) {
    const reservation = await admitInput();
    try {
      const message = await collectByteStream(data, reservation.cap);
      // Each algorithm's signature width is fixed by the WIT (Ed25519's
      // 64-byte `R ‖ S`; ECDSA's P1363 `r ‖ s`). Chromium's engine rejects
      // other lengths itself; Firefox zero-pads short halves and accepts
      // truncated encodings (observed accepting a 2-byte signature), so
      // enforce the width here — a pure length check on public data,
      // strictly monotone: it only adds rejections in front of the engine.
      // The message stream is drained first, per the WIT drain rule.
      if (sig.length !== this.#algorithm.signatureLength) {
        throw errAuthenticationFailed();
      }
      // The `ed25519-verify` WIT criterion (verify_strict semantics): the
      // engine implements plain RFC 8032, so reject non-canonical `S`, and
      // non-canonical or small-order `R`, before delegating.
      if (this.#algorithm.name === "Ed25519") {
        if (!ltLittleEndian(sig.subarray(32), ED25519_L)) {
          throw errAuthenticationFailed();
        }
        if (!ed25519PointStrict(sig.subarray(0, 32))) {
          throw errAuthenticationFailed();
        }
      }
      const params = signParams(this.#algorithm);
      const ok = await platformCall(`${this.#algorithm.name} verify`, () =>
        subtle.verify(params, this.#key, sig, message),
      );
      if (!ok) {
        throw errAuthenticationFailed();
      }
    } finally {
      reservation.release();
    }
  }

  /** Projections of the mint-bound algorithm record. */
  algorithmName() {
    return this.#algorithm.name;
  }

  algorithmCurve() {
    return this.#algorithm.namedCurve;
  }

  algorithmHash() {
    return this.#algorithm.hash;
  }

  /**
   * The public key material (`raw`: 32 bytes for Ed25519, an uncompressed
   * SEC1 point for ECDSA). Public material is always exportable.
   */
  async exportKey() {
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }
}

/**
 * The `signing-key` resource: a private `CryptoKey` and the mint-bound
 * algorithm record. The WIT `extractable` flag is carried by the platform
 * key itself (it is passed through at import/generation), so the platform
 * enforces non-extractability; the JS check in `exportKey` only lifts the
 * WIT error shape. There is no stored public half: the WIT surface has no
 * derive — `generate-key` returns the pair, and importers mint the
 * verifying key from the public bytes they hold.
 */
export class SigningKey {
  #privateKey;
  #algorithm;

  /**
   * @param {CryptoKey} privateKey
   * @param {typeof ED25519_ALGORITHM} algorithm the mint-bound algorithm record
   */
  constructor(privateKey, algorithm) {
    this.#privateKey = privateKey;
    this.#algorithm = algorithm;
  }

  /**
   * Sign an entire byte stream; resolves once the stream is fully drained.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async sign(data) {
    const reservation = await admitInput();
    try {
      const message = await collectByteStream(data, reservation.cap);
      const params = signParams(this.#algorithm);
      return new Uint8Array(
        await platformCall(`${this.#algorithm.name} sign`, () =>
          subtle.sign(params, this.#privateKey, message),
        ),
      );
    } finally {
      reservation.release();
    }
  }

  /** Projections of the mint-bound algorithm record. */
  algorithmName() {
    return this.#algorithm.name;
  }

  algorithmCurve() {
    return this.#algorithm.namedCurve;
  }

  algorithmHash() {
    return this.#algorithm.hash;
  }

  extractable() {
    return this.#privateKey.extractable;
  }

  /**
   * The private key material (the 32-byte RFC 8032 seed for Ed25519, the
   * raw big-endian scalar for ECDSA), recovered from the JWK `d` field.
   * Throws `{ tag: 'not-extractable' }` unless minted with `extractable`
   * true (checked on the `CryptoKey` itself rather than relying on the
   * `DOMException` from `exportKey`).
   */
  async exportKey() {
    if (!this.#privateKey.extractable) throw errNotExtractable();
    const jwk = await platformCall("private key export", () =>
      subtle.exportKey("jwk", this.#privateKey),
    );
    return base64UrlDecode(jwk.d);
  }
}

/** Decode a base64url string (JWK field encoding) to bytes. */
function base64UrlDecode(text) {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

/**
 * Ed25519 strict-validation predicates (the `ed25519-verify` WIT criterion:
 * `verify_strict` semantics). WebCrypto engines implement plain RFC 8032,
 * which leaves acceptance of non-canonical and small-order inputs open, so
 * this host enforces the pinned rejections itself before delegating —
 * pure byte compares on public data (no constant-time requirement), and
 * strictly monotone: they only add rejections in front of the engine.
 * None of the rejected encodings can be produced by an honest signer.
 */

/** The field prime p = 2^255 - 19, little-endian. */
// prettier-ignore
const ED25519_P = Uint8Array.from([
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
]);

/** The group order L = 2^252 + 27742317777372353535851937790883648493, little-endian. */
// prettier-ignore
const ED25519_L = Uint8Array.from([
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
]);

/**
 * The y-coordinates of edwards25519's 8-torsion subgroup, little-endian:
 * every small-order point has one of these five y values (y = 0, 1, p-1,
 * and the two order-8 y values). Derived from the curve equation
 * (d·y⁴ + 2y² − 1 = 0 for the order-8 points) and cross-checked against
 * the ed25519-speccheck vectors and ed25519-dalek's torsion table.
 */
// prettier-ignore
const ED25519_SMALL_ORDER_Y = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
].map((hex) => Uint8Array.from(hex.match(/../g), (b) => parseInt(b, 16)));

/** Whether little-endian `a` < `b` (equal-length). */
function ltLittleEndian(a, b) {
  for (let i = a.length - 1; i >= 0; i--) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

/** Whether `a` and `b` are byte-equal (public data; early exit is fine). */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Whether a 32-byte Ed25519 point encoding is canonical (y < p) and not a
 * small-order point — the strict-validation predicate for both `A` (at
 * import) and `R` (at verify).
 * @param {Uint8Array} encoded
 */
function ed25519PointStrict(encoded) {
  const y = encoded.slice();
  y[31] &= 0x7f; // mask the x sign bit
  if (!ltLittleEndian(y, ED25519_P)) return false; // non-canonical
  return !ED25519_SMALL_ORDER_Y.some((torsion) => bytesEqual(y, torsion));
}

/** Rethrow a WebCrypto import failure as `{ tag: 'invalid-key', val }`. */
function invalidKey(err, what) {
  throw errInvalidKey(`invalid ${what}: ${err.message ?? err}`);
}

/**
 * Import a 32-byte raw Ed25519 public key. Non-canonical and small-order
 * encodings are rejected here (the WIT strict criterion; the platform's
 * import performs little validation of its own).
 */
async function importEd25519VerifyingKey(raw) {
  if (raw.length !== ED25519_ALGORITHM.publicLength) {
    throw errInvalidKey(
      `Ed25519 public keys are ${ED25519_ALGORITHM.publicLength} bytes, got ${raw.length}`,
    );
  }
  if (!ed25519PointStrict(raw)) {
    throw errInvalidKey("non-canonical or small-order Ed25519 public key");
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, "Ed25519", true, ["verify"]);
  } catch (err) {
    invalidKey(err, "Ed25519 public key");
  }
  return new VerifyingKey(key, ED25519_ALGORITHM);
}

/** The `lann:webcrypto/ed25519-verify` interface (`--map '…#ed25519Verify'`). */
export const ed25519Verify = { importVerifyingKey: importEd25519VerifyingKey };

/**
 * The fixed PKCS#8 prefix wrapping a 32-byte Ed25519 seed (RFC 5958 +
 * RFC 8410): WebCrypto imports private keys as `pkcs8`, not `raw`.
 */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Import a 32-byte raw Ed25519 private seed. */
async function importEd25519SigningKey(raw, extractable) {
  if (raw.length !== ED25519_ALGORITHM.scalarLength) {
    throw errInvalidKey(
      `Ed25519 private keys are ${ED25519_ALGORITHM.scalarLength}-byte seeds, got ${raw.length}`,
    );
  }
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  let privateKey;
  try {
    privateKey = await subtle.importKey("pkcs8", pkcs8, "Ed25519", extractable, ["sign"]);
  } catch (err) {
    invalidKey(err, "Ed25519 private key");
  }
  return new SigningKey(privateKey, ED25519_ALGORITHM);
}

/** Generate a fresh Ed25519 signing key, returning `[signing, verifying]`. */
async function generateEd25519Key(extractable) {
  const pair = await platformCall("Ed25519 key generation", () =>
    subtle.generateKey("Ed25519", extractable, ["sign", "verify"]),
  );
  return [
    new SigningKey(pair.privateKey, ED25519_ALGORITHM),
    new VerifyingKey(pair.publicKey, ED25519_ALGORITHM),
  ];
}

/** The `lann:webcrypto/ed25519-sign` interface (`--map '…#ed25519Sign'`). */
export const ed25519Sign = {
  importSigningKey: importEd25519SigningKey,
  generateKey: generateEd25519Key,
};

/** Import an uncompressed-SEC1 ECDSA public key of the declared variant. */
async function importEcdsaVerifyingKey(variant, raw) {
  const entry = ecdsaVariant(variant);
  if (raw.length !== entry.publicLength || raw[0] !== 0x04) {
    throw errInvalidKey(
      `${variant} public keys are uncompressed SEC1 points (${entry.publicLength} bytes, leading 0x04)`,
    );
  }
  let key;
  try {
    key = await subtle.importKey(
      "raw",
      raw,
      { name: "ECDSA", namedCurve: entry.namedCurve },
      true,
      ["verify"],
    );
  } catch (err) {
    invalidKey(err, `${variant} public key`);
  }
  return new VerifyingKey(key, entry);
}

/** The `lann:webcrypto/ecdsa-verify` interface (`--map '…#ecdsaVerify'`). */
export const ecdsaVerify = { importVerifyingKey: importEcdsaVerifyingKey };

/** Import a raw big-endian ECDSA scalar of the declared variant, via JWK. */
async function importEcdsaSigningKey(variant, raw, extractable) {
  const entry = ecdsaVariant(variant);
  if (raw.length !== entry.scalarLength) {
    throw errInvalidKey(
      `${variant} private keys are raw ${entry.scalarLength}-byte scalars, got ${raw.length}`,
    );
  }
  // WebCrypto imports EC private keys as pkcs8 or jwk only, and a JWK
  // private key requires the public coordinates — which plain JS cannot
  // compute. Import via a minimal PKCS#8/RFC 5915 wrapping instead.
  // Private-only PKCS#8 import is a recognized WebCrypto spec gap
  // (w3c/webcrypto#356) — engines diverge on it — so this import is
  // best-effort: it works where the platform cooperates and fails
  // `invalid-key` where it declines, which the WIT permits.
  const pkcs8 = ecdsaScalarToPkcs8(entry.curveOid, raw);
  let privateKey;
  try {
    privateKey = await subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "ECDSA", namedCurve: entry.namedCurve },
      extractable,
      ["sign"],
    );
  } catch (err) {
    invalidKey(err, `${variant} private key`);
  }
  return new SigningKey(privateKey, entry);
}

/**
 * Wrap a raw EC scalar in a minimal PKCS#8 `PrivateKeyInfo` (RFC 5208)
 * containing an RFC 5915 `ECPrivateKey` without the optional public key.
 * @param {number[]} curveOid the curve's encoded OID, from `ECDSA_VARIANTS`
 * @param {Uint8Array} scalar
 */
function ecdsaScalarToPkcs8(curveOid, scalar) {
  const ecPrivateKey = [
    0x30, 3 + 2 + scalar.length, // SEQUENCE { INTEGER 1, OCTET STRING d }
    0x02, 0x01, 0x01,
    0x04, scalar.length, ...scalar,
  ];
  const algorithm = [
    0x30, 9 + curveOid.length, // SEQUENCE { OID ecPublicKey, OID curve }
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    ...curveOid,
  ];
  const body = [
    0x02, 0x01, 0x00, // INTEGER 0 (version)
    ...algorithm,
    0x04, ecPrivateKey.length, ...ecPrivateKey, // OCTET STRING { ECPrivateKey }
  ];
  return new Uint8Array([0x30, body.length, ...body]);
}

/**
 * Generate a fresh ECDSA signing key of the declared variant, returning
 * `[signing, verifying]`.
 */
async function generateEcdsaKey(variant, extractable) {
  const entry = ecdsaVariant(variant);
  const pair = await platformCall(`${variant} key generation`, () =>
    subtle.generateKey({ name: "ECDSA", namedCurve: entry.namedCurve }, extractable, [
      "sign",
      "verify",
    ]),
  );
  return [new SigningKey(pair.privateKey, entry), new VerifyingKey(pair.publicKey, entry)];
}

/** The `lann:webcrypto/ecdsa-sign` interface (`--map '…#ecdsaSign'`). */
export const ecdsaSign = {
  importSigningKey: importEcdsaSigningKey,
  generateKey: generateEcdsaKey,
};

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
// would otherwise collide. Errors are surfaced to the guest by throwing the WIT
// `error` variant value (for example `{ tag: 'invalid-key', val }` or
// `{ tag: 'authentication-failed' }`), which jco lifts into the
// `result<_, error>` the WIT declares.
//
// The bulk data paths are byte `stream`s: guest-provided streams arrive as
// jco's async-iterable `Stream` objects (a web `ReadableStream` is also
// tolerated) and are drained with `collectByteStream`; host-returned
// `stream<u8>` values are web `ReadableStream`s of `Uint8Array`.

const subtle = globalThis.crypto.subtle;

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
    throw { tag: "unsupported", val: `${variant} is not served by this implementation` };
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
    const message = await collectByteStream(data);
    return new Uint8Array(await subtle.sign("HMAC", this.#key, message));
  }

  /**
   * Verify `tag` against the tag computed over an entire byte stream; the
   * platform performs the constant-time comparison. Throws
   * `{ tag: 'authentication-failed' }` if the tag does not verify.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   * @param {Uint8Array} tag
   */
  async verify(data, tag) {
    const message = await collectByteStream(data);
    if (!(await subtle.verify("HMAC", this.#key, tag, message))) {
      throw { tag: "authentication-failed" };
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
    if (!this.#key.extractable) throw { tag: "not-extractable" };
    return new Uint8Array(await subtle.exportKey("raw", this.#key));
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
    const message = await collectByteStream(plaintext);
    requireGcmNonce(nonce);
    const sealed = await subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad },
      this.#key,
      message,
    );
    return bytesToStream(new Uint8Array(sealed));
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
    const message = await collectByteStream(ciphertext);
    requireGcmNonce(nonce);
    let opened;
    try {
      opened = await subtle.decrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad },
        this.#key,
        message,
      );
    } catch {
      // WebCrypto reports every decrypt failure as an opaque OperationError;
      // the WIT error deliberately carries no detail either.
      throw { tag: "authentication-failed" };
    }
    return bytesToStream(new Uint8Array(opened));
  }

  /**
   * The algorithm getters: direct projections of the `CryptoKey`'s
   * `AesKeyAlgorithm` (`name` and `length`).
   */
  algorithmName() {
    return this.#key.algorithm.name;
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
    if (!this.#key.extractable) throw { tag: "not-extractable" };
    return new Uint8Array(await subtle.exportKey("raw", this.#key));
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
  if (raw.length === 0) throw { tag: "invalid-key", val: "empty key" };
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "HMAC", hash }, extractable, [
      "sign",
      "verify",
    ]);
  } catch (err) {
    throw { tag: "invalid-key", val: String(err) };
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
  const key = await subtle.generateKey({ name: "HMAC", hash }, extractable, ["sign", "verify"]);
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
   * drained.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async compute(data) {
    const message = await collectByteStream(data);
    return new Uint8Array(await subtle.digest(this.#hash, message));
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
    throw { tag: "unsupported", val: `${variant} is not served by this implementation` };
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
    throw {
      tag: "invalid-key",
      val: `${variant} requires ${expected} key bytes, got ${raw.length}`,
    };
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, extractable, [
      "encrypt",
      "decrypt",
    ]);
  } catch (err) {
    throw { tag: "invalid-key", val: String(err) };
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
  const key = await subtle.generateKey(
    { name: "AES-GCM", length: aesVariantByteLength(variant) * 8 },
    extractable,
    ["encrypt", "decrypt"],
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
  throw { tag: "unsupported", val: `${name} is not served by this implementation` };
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
    const message = await collectByteStream(plaintext);
    if (this.#sealed >= InternalNonceKey.#NONCE_BUDGET) {
      throw { tag: "key-exhausted" };
    }
    this.#sealed += 1n;
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(InternalNonceKey.#IV_BYTES));
    const body = new Uint8Array(
      await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, this.#key, message),
    );
    const sealed = new Uint8Array(iv.length + body.length);
    sealed.set(iv, 0);
    sealed.set(body, iv.length);
    return bytesToStream(sealed);
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
    const message = await collectByteStream(sealed);
    if (message.length < InternalNonceKey.#IV_BYTES) {
      throw { tag: "authentication-failed" };
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
      throw { tag: "authentication-failed" };
    }
    return bytesToStream(new Uint8Array(opened));
  }

  /** The algorithm getters: direct `AesKeyAlgorithm` projections. */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#key.algorithm.length;
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the
   * key was created with `extractable` true.
   */
  async exportKey() {
    if (!this.#key.extractable) throw { tag: "not-extractable" };
    return new Uint8Array(await subtle.exportKey("raw", this.#key));
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
    throw {
      tag: "invalid-key",
      val: `${variant} requires ${expected} key bytes, got ${raw.length}`,
    };
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, { name: "AES-GCM" }, extractable, [
      "encrypt",
      "decrypt",
    ]);
  } catch (err) {
    throw { tag: "invalid-key", val: String(err) };
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
  const key = await subtle.generateKey(
    { name: "AES-GCM", length: aesVariantByteLength(variant) * 8 },
    extractable,
    ["encrypt", "decrypt"],
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
    throw { tag: "invalid-nonce", val: `AES-GCM requires a 12-byte nonce, got ${nonce.length}` };
  }
}

/** A single-chunk byte `ReadableStream` over `bytes`. */
function bytesToStream(bytes) {
  return new ReadableStream({
    start(controller) {
      if (bytes.length) controller.enqueue(bytes);
      controller.close();
    },
  });
}

/**
 * Coerce one chunk of a WIT byte stream (a number, an array of numbers, or a
 * typed array, depending on how the runtime batched the read) to a
 * `Uint8Array`.
 */
function toByteChunk(value) {
  if (typeof value === "number") return Uint8Array.of(value);
  if (value instanceof Uint8Array) return value;
  return Uint8Array.from(value);
}

/** Collect every byte of a WIT byte stream into one `Uint8Array`. */
async function collectByteStream(stream) {
  const chunks = [];
  let total = 0;
  const push = (value) => {
    if (value === undefined || value === null) return;
    const chunk = toByteChunk(value);
    if (chunk.length) {
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
 * mint-bound hash, and the uncompressed-SEC1 public key length.
 */
const ECDSA_VARIANTS = {
  "p256-sha256": { namedCurve: "P-256", hash: "SHA-256", publicLength: 65 },
  "p384-sha384": { namedCurve: "P-384", hash: "SHA-384", publicLength: 97 },
};

/**
 * The served `ecdsa-variant` entry for `variant`, throwing
 * `{ tag: 'unsupported', val }` for anything unknown.
 */
function ecdsaVariant(variant) {
  const entry = ECDSA_VARIANTS[variant];
  if (entry === undefined) {
    throw { tag: "unsupported", val: `${variant} is not served by this implementation` };
  }
  return entry;
}

/** The WebCrypto sign/verify algorithm parameter for a key's mint binding. */
function signParams(algorithmName, hash) {
  return algorithmName === "ECDSA" ? { name: "ECDSA", hash } : algorithmName;
}

/**
 * The `verifying-key` resource: a public `CryptoKey` plus its mint-bound
 * hash (WebCrypto passes ECDSA's hash per-operation; this package binds it
 * at mint). Instances are minted by the `ed25519-verify` / `ecdsa-verify`
 * interface functions below, or derived from a `SigningKey`.
 */
export class VerifyingKey {
  #key;
  #hash;

  /**
   * @param {CryptoKey} key
   * @param {string | undefined} hash
   */
  constructor(key, hash) {
    this.#key = key;
    this.#hash = hash;
  }

  /**
   * Verify `sig` over an entire byte stream; resolves only after the stream
   * is fully drained. Throws `{ tag: 'authentication-failed' }` on failure
   * (including malformed signatures — WebCrypto reports both as `false`).
   * @param {AsyncIterable<unknown> | ReadableStream} data
   * @param {Uint8Array} sig
   */
  async verify(data, sig) {
    const message = await collectByteStream(data);
    const params = signParams(this.#key.algorithm.name, this.#hash);
    if (!(await subtle.verify(params, this.#key, sig, message))) {
      throw { tag: "authentication-failed" };
    }
  }

  /** Direct projections of the `CryptoKey`'s algorithm + the mint binding. */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmCurve() {
    return this.#key.algorithm.namedCurve;
  }

  algorithmHash() {
    return this.#hash;
  }

  /**
   * The public key material (`raw`: 32 bytes for Ed25519, an uncompressed
   * SEC1 point for ECDSA). Public material is always exportable.
   */
  async exportKey() {
    return new Uint8Array(await subtle.exportKey("raw", this.#key));
  }
}

/**
 * The `signing-key` resource: a private `CryptoKey` (imported
 * platform-extractable so the public half can be derived; the WIT
 * `extractable` gate is enforced by this class — extractability is an API
 * property, per the WIT), its derived public half, the mint-bound hash, and
 * the caller's `extractable` flag.
 */
export class SigningKey {
  #privateKey;
  #publicKey;
  #hash;
  #extractable;

  /**
   * @param {CryptoKey} privateKey
   * @param {CryptoKey} publicKey
   * @param {string | undefined} hash
   * @param {boolean} extractable
   */
  constructor(privateKey, publicKey, hash, extractable) {
    this.#privateKey = privateKey;
    this.#publicKey = publicKey;
    this.#hash = hash;
    this.#extractable = extractable;
  }

  /**
   * Sign an entire byte stream; resolves once the stream is fully drained.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async sign(data) {
    const message = await collectByteStream(data);
    const params = signParams(this.#privateKey.algorithm.name, this.#hash);
    return new Uint8Array(await subtle.sign(params, this.#privateKey, message));
  }

  /** The corresponding public key. */
  verifyingKey() {
    return new VerifyingKey(this.#publicKey, this.#hash);
  }

  algorithmName() {
    return this.#privateKey.algorithm.name;
  }

  algorithmCurve() {
    return this.#privateKey.algorithm.namedCurve;
  }

  algorithmHash() {
    return this.#hash;
  }

  extractable() {
    return this.#extractable;
  }

  /**
   * The private key material (the 32-byte RFC 8032 seed for Ed25519, the
   * raw big-endian scalar for ECDSA), recovered from the JWK `d` field.
   * Throws `{ tag: 'not-extractable' }` unless minted with `extractable`
   * true.
   */
  async exportKey() {
    if (!this.#extractable) throw { tag: "not-extractable" };
    const jwk = await subtle.exportKey("jwk", this.#privateKey);
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
 * Derive the public `CryptoKey` for `privateKey` by round-tripping its JWK
 * without the private field.
 * @param {CryptoKey} privateKey
 * @param {object} importParams
 */
async function derivePublicKey(privateKey, importParams) {
  const jwk = await subtle.exportKey("jwk", privateKey);
  delete jwk.d;
  jwk.key_ops = ["verify"];
  return subtle.importKey("jwk", jwk, importParams, true, ["verify"]);
}

/** Rethrow a WebCrypto import failure as `{ tag: 'invalid-key', val }`. */
function invalidKey(err, what) {
  throw { tag: "invalid-key", val: `invalid ${what}: ${err.message ?? err}` };
}

/** Import a 32-byte raw Ed25519 public key. */
async function importEd25519VerifyingKey(raw) {
  if (raw.length !== 32) {
    throw { tag: "invalid-key", val: `Ed25519 public keys are 32 bytes, got ${raw.length}` };
  }
  let key;
  try {
    key = await subtle.importKey("raw", raw, "Ed25519", true, ["verify"]);
  } catch (err) {
    invalidKey(err, "Ed25519 public key");
  }
  return new VerifyingKey(key, undefined);
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
  if (raw.length !== 32) {
    throw { tag: "invalid-key", val: `Ed25519 private keys are 32-byte seeds, got ${raw.length}` };
  }
  const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + raw.length);
  pkcs8.set(ED25519_PKCS8_PREFIX);
  pkcs8.set(raw, ED25519_PKCS8_PREFIX.length);
  let privateKey;
  try {
    // Imported platform-extractable so the public half and the WIT-gated
    // `export` can be derived; the WIT gate is `extractable` below.
    privateKey = await subtle.importKey("pkcs8", pkcs8, "Ed25519", true, ["sign"]);
  } catch (err) {
    invalidKey(err, "Ed25519 private key");
  }
  const publicKey = await derivePublicKey(privateKey, "Ed25519");
  return new SigningKey(privateKey, publicKey, undefined, extractable);
}

/** Generate a fresh Ed25519 signing key. */
async function generateEd25519Key(extractable) {
  const pair = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  return new SigningKey(pair.privateKey, pair.publicKey, undefined, extractable);
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
    throw {
      tag: "invalid-key",
      val: `${variant} public keys are uncompressed SEC1 points (${entry.publicLength} bytes, leading 0x04)`,
    };
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
  return new VerifyingKey(key, entry.hash);
}

/** The `lann:webcrypto/ecdsa-verify` interface (`--map '…#ecdsaVerify'`). */
export const ecdsaVerify = { importVerifyingKey: importEcdsaVerifyingKey };

/** Import a raw big-endian ECDSA scalar of the declared variant, via JWK. */
async function importEcdsaSigningKey(variant, raw, extractable) {
  const entry = ecdsaVariant(variant);
  const scalarLength = entry.namedCurve === "P-256" ? 32 : 48;
  if (raw.length !== scalarLength) {
    throw {
      tag: "invalid-key",
      val: `${variant} private keys are raw ${scalarLength}-byte scalars, got ${raw.length}`,
    };
  }
  // WebCrypto imports EC private keys as pkcs8 or jwk only, and a JWK
  // private key requires the public coordinates — which plain JS cannot
  // compute. Import via a minimal PKCS#8/RFC 5915 wrapping instead (the
  // platform derives the public point).
  const pkcs8 = ecdsaScalarToPkcs8(entry.namedCurve, raw);
  let privateKey;
  try {
    privateKey = await subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "ECDSA", namedCurve: entry.namedCurve },
      true,
      ["sign"],
    );
  } catch (err) {
    invalidKey(err, `${variant} private key`);
  }
  const publicKey = await derivePublicKey(privateKey, {
    name: "ECDSA",
    namedCurve: entry.namedCurve,
  });
  return new SigningKey(privateKey, publicKey, entry.hash, extractable);
}

/**
 * Wrap a raw EC scalar in a minimal PKCS#8 `PrivateKeyInfo` (RFC 5208)
 * containing an RFC 5915 `ECPrivateKey` without the optional public key.
 * @param {string} namedCurve
 * @param {Uint8Array} scalar
 */
function ecdsaScalarToPkcs8(namedCurve, scalar) {
  const curveOid =
    namedCurve === "P-256"
      ? [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
      : [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
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

/** Generate a fresh ECDSA signing key of the declared variant. */
async function generateEcdsaKey(variant, extractable) {
  const entry = ecdsaVariant(variant);
  const pair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: entry.namedCurve },
    true,
    ["sign", "verify"],
  );
  return new SigningKey(pair.privateKey, pair.publicKey, entry.hash, extractable);
}

/** The `lann:webcrypto/ecdsa-sign` interface (`--map '…#ecdsaSign'`). */
export const ecdsaSign = {
  importSigningKey: importEcdsaSigningKey,
  generateKey: generateEcdsaKey,
};

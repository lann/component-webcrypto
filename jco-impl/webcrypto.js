// Host implementation of the `lann:webcrypto` imports (`mac`, `aead`, `hmac`,
// `aes-gcm`) for jco-transpiled components.
//
// This is the "browser-first" host: it is written against the standard Web
// Crypto API only — `globalThis.crypto.subtle` and
// `globalThis.crypto.getRandomValues` — so the same file runs unchanged in a
// browser. No `node:crypto` imports and no Node-only APIs are used; Node
// provides the same globals natively.
//
// `jco --map` wires this module in as the component's `mac`/`aead`/`hmac`/
// `aes-gcm` imports (one module for all four, since their export names do not
// collide). Errors are surfaced to the guest by throwing the WIT `error`
// variant value (for example `{ tag: 'invalid-key', val }` or
// `{ tag: 'authentication-failed' }`), which jco lifts into the
// `result<_, error>` the WIT declares.
//
// The bulk data paths are byte `stream`s: guest-provided streams arrive as
// jco's async-iterable `Stream` objects (a web `ReadableStream` is also
// tolerated) and are drained with `collectByteStream`; host-returned
// `stream<u8>` values are web `ReadableStream`s of `Uint8Array`.

const subtle = globalThis.crypto.subtle;

/** HMAC-SHA-256 `importKey` parameters. */
const HMAC_ALGORITHM = { name: "HMAC", hash: "SHA-256" };

/**
 * The `mac-key` resource: an HMAC-SHA-256 key. Holds a `CryptoKey` imported
 * with usages `["sign", "verify"]` and the caller's `extractable` flag;
 * instances are minted only by the `hmac` interface functions below.
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
  async export() {
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
  async export() {
    if (!this.#key.extractable) throw { tag: "not-extractable" };
    return new Uint8Array(await subtle.exportKey("raw", this.#key));
  }
}

/**
 * Import raw key material as an HMAC-SHA-256 key. Any non-empty length is
 * accepted (RFC 2104); empty material throws `{ tag: 'invalid-key', val }`.
 * @param {Uint8Array} raw
 * @param {boolean} extractable
 */
export async function importHmacSha256Key(raw, extractable) {
  if (raw.length === 0) throw { tag: "invalid-key", val: "empty key" };
  let key;
  try {
    key = await subtle.importKey("raw", raw, HMAC_ALGORITHM, extractable, ["sign", "verify"]);
  } catch (err) {
    throw { tag: "invalid-key", val: String(err) };
  }
  return new MacKey(key);
}

/**
 * Generate a fresh random HMAC-SHA-256 key (32 bytes of key material).
 * @param {boolean} extractable
 */
export async function generateHmacSha256Key(extractable) {
  const raw = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const key = await subtle.importKey("raw", raw, HMAC_ALGORITHM, extractable, ["sign", "verify"]);
  return new MacKey(key);
}

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
export async function importKey(variant, raw, extractable) {
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
export async function generateKey(variant, extractable) {
  const key = await subtle.generateKey(
    { name: "AES-GCM", length: aesVariantByteLength(variant) * 8 },
    extractable,
    ["encrypt", "decrypt"],
  );
  return new AeadKey(key);
}

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

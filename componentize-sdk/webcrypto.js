// @ts-check
// A WebCrypto-subset library for JS guests componentized with
// componentize-js (https://github.com/dicej/componentize-js, the wit-dylib
// reboot of ComponentizeJS), backed by the `lann:webcrypto` interfaces.
//
// The surface mirrors `crypto.subtle` for the supported algorithms:
//
//   - `importKey` / `exportKey` ("raw" format only)
//   - `generateKey`
//   - `sign` / `verify`     (HMAC-SHA-256)
//   - `encrypt` / `decrypt` (AES-256-GCM)
//
// The component's world must import `lann:webcrypto/hmac-sha2@0.1.0` and
// `lann:webcrypto/aes-gcm@0.1.0` (their `mac`/`aead`/`types` dependencies
// are pulled in by WIT elaboration). Module specifiers here name those
// imports directly, so this file needs no bundler: componentize-js resolves
// them against the world at componentize time.
//
// Documented deviations from the Web Cryptography API (all fail closed with
// clear errors, never silently differ). Each is classified — *unserved*
// (the WIT carries the semantics; this library does not serve them yet) or
// *WIT-forced* (no shim could express the behavior through the interface
// shape; a recorded design ruling) — per AGENTS.md, "WPT fidelity is a
// first-class design constraint":
//
//   - Unserved: only HMAC-SHA-256 and AES-256-GCM are served; other
//     algorithms, hashes, and AES key sizes throw `NotSupportedError`.
//   - Unserved: only the `"raw"` and `"jwk"` key formats are served;
//     others throw `NotSupportedError`.
//   - Runtime gap, not a deviation of this library: there is no
//     `DOMException` in the componentize-js runtime, so this module exports
//     a minimal stand-in with the standard `.name` values
//     ("OperationError", "InvalidAccessError", "NotSupportedError",
//     "DataError", "SyntaxError").
//
// The WIT-forced set is empty: AES-GCM's per-call IV lengths and
// `tagLength`s are carried by `aead-key.seal`/`open`'s parameters.

import * as hmacSha2 from "lann:webcrypto/hmac-sha2@0.1.0";
import * as aesGcm from "lann:webcrypto/aes-gcm@0.1.0";
import * as witWorld from "wit-world";
// The resource-owning interfaces must be imported (evaluated) for their
// generated resource classes to exist: componentize-js builds each returned
// `mac-key`/`aead-key` wrapper from the class in its interface's module.
import "lann:webcrypto/mac@0.1.0";
import "lann:webcrypto/aead@0.1.0";

// --- errors -------------------------------------------------------------------

/**
 * Minimal stand-in for the platform `DOMException` (which the
 * componentize-js runtime lacks): an `Error` whose `name` carries the
 * WebCrypto error type. Errors mapped from a WIT `types.error` carry the
 * original `{ tag, val }` variant as `cause`.
 */
export class DOMException extends Error {
  /**
   * @param {string} message
   * @param {string} [name]
   * @param {ErrorOptions} [options]
   */
  constructor(message, name = "Error", options = undefined) {
    super(message, options);
    this.name = name;
  }
}

/**
 * @param {string} name
 * @param {string} message
 * @param {WitError} [cause]
 */
function dom(name, message, cause = undefined) {
  return new DOMException(message, name, cause === undefined ? undefined : { cause });
}

/**
 * A WIT `types.error` variant, as componentize-js delivers it.
 * @typedef {{ tag: string, val?: string }} WitError
 */

/**
 * True for errors raised by the `lann:webcrypto` imports: componentize-js
 * surfaces an `err` result as a thrown `ComponentError` whose `payload` is
 * the WIT `types.error` variant, a `{ tag, val }` object.
 * @param {unknown} e
 * @returns {e is Error & { payload: WitError }}
 */
function isWitError(e) {
  if (!(e instanceof Error)) return false;
  const payload = /** @type {{ payload?: unknown }} */ (e).payload;
  return (
    typeof payload === "object" &&
    payload !== null &&
    typeof (/** @type {{ tag?: unknown }} */ (payload).tag) === "string"
  );
}

/**
 * Map a WIT `types.error` variant onto the WebCrypto error vocabulary.
 * @param {WitError} payload
 */
function mapWitError(payload) {
  switch (payload.tag) {
    case "invalid-key":
      return dom("DataError", payload.val ?? "invalid key", payload);
    case "invalid-nonce":
      return dom("OperationError", payload.val ?? "invalid nonce", payload);
    case "authentication-failed":
      return dom("OperationError", "authentication failed", payload);
    case "not-extractable":
      return dom("InvalidAccessError", "key is not extractable", payload);
    case "unsupported":
      return dom("NotSupportedError", payload.val ?? "unsupported", payload);
    case "key-exhausted":
      return dom("OperationError", "key exhausted", payload);
    default:
      return dom("OperationError", String(payload.val ?? "operation failed"), payload);
  }
}

/**
 * @param {unknown} e
 * @returns {never}
 */
function rethrow(e) {
  throw isWitError(e) ? mapWitError(e.payload) : e;
}

/**
 * Await an async `lann:webcrypto` import and normalize its settlement.
 *
 * componentize-js (as of the revision pinned in componentize-js.rev)
 * settles async imports through two paths: an import that suspends resolves
 * with the `ok` value unwrapped and rejects an `err` as a `ComponentError`,
 * but an import that completes without blocking resolves with the raw
 * canonical `result` wrapper (`{ tag: "ok" | "err", val }`). Detecting the
 * wrapper is unambiguous for this surface: every `ok` payload is a
 * resource, typed array, or `undefined` — never a plain `{ tag }` object.
 * @param {unknown} promise
 * @returns {Promise<any>}
 */
async function callImport(promise) {
  /** @type {unknown} */
  let value;
  try {
    value = await promise;
  } catch (e) {
    rethrow(e);
  }
  const wrapper = /** @type {{ tag?: unknown, val?: unknown } | null} */ (
    typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype
      ? value
      : null
  );
  if (wrapper !== null && (wrapper.tag === "ok" || wrapper.tag === "err")) {
    if (wrapper.tag === "err") {
      throw mapWitError(/** @type {WitError} */ (wrapper.val));
    }
    return wrapper.val;
  }
  return value;
}

// --- byte plumbing --------------------------------------------------------------

/**
 * Copy a BufferSource into a fresh Uint8Array (WebCrypto operates on a copy
 * of its input taken at call time). A detached ArrayBuffer yields an empty
 * copy, matching how "get a copy of the bytes held by the buffer source"
 * behaves after a `transfer()` — detached buffers report `byteLength` 0, so
 * the zero-length short-circuits below never reach `slice()` (which throws
 * on detached buffers).
 * @param {unknown} data
 * @param {string} what
 * @returns {Uint8Array}
 */
function bytesOf(data, what) {
  if (data instanceof ArrayBuffer) {
    return data.byteLength === 0 ? new Uint8Array(0) : new Uint8Array(data.slice(0));
  }
  if (ArrayBuffer.isView(data)) {
    if (data.byteLength === 0 || data.buffer.byteLength === 0) {
      return new Uint8Array(0);
    }
    return new Uint8Array(
      data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
    );
  }
  throw new TypeError(`${what} must be a BufferSource`);
}

/**
 * @param {Uint8Array} u8
 * @returns {ArrayBuffer}
 */
function toArrayBuffer(u8) {
  return /** @type {ArrayBuffer} */ (
    u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
  );
}

/**
 * Write `bytes` to the writable end of a stream and drop it: writer drop is
 * the stream's only end-of-input signal.
 * @param {any} tx the writable half of a `wit-world` `u8Stream()` pair
 * @param {Uint8Array} bytes
 */
async function feedAll(tx, bytes) {
  try {
    await tx.writeAll(bytes);
  } finally {
    tx[Symbol.dispose]();
  }
}

/**
 * Drain a `stream<u8>` readable end to a single Uint8Array.
 * @param {any} rx the readable half of a `wit-world` `u8Stream()` pair
 * @returns {Promise<Uint8Array>}
 */
async function collectStream(rx) {
  using _rx = rx;
  /** @type {Uint8Array[]} */
  const chunks = [];
  let total = 0;
  while (!rx.writerDropped) {
    const chunk = await rx.read(64 * 1024);
    if (chunk && chunk.length > 0) {
      chunks.push(chunk);
      total += chunk.length;
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Run one stream-taking operation over an in-memory input: mint a stream
 * pair, hand the readable end to `start`, and feed the input concurrently
 * (operations resolve only once their input stream is fully drained, and
 * the package's drain rule guarantees the feed completes even when the
 * operation fails).
 * @param {(rx: any) => unknown} start
 * @param {Uint8Array} input
 * @returns {Promise<any>}
 */
async function callFed(start, input) {
  const [tx, rx] = witWorld.u8Stream();
  const operation = callImport(start(rx));
  const fed = feedAll(tx, input);
  let result;
  try {
    result = await operation;
  } catch (e) {
    // Don't let a feed failure mask the operation's error.
    await fed.catch(() => {});
    throw e;
  }
  await fed;
  return result;
}

/**
 * Like `callFed`, for operations resolving to an output `stream<u8>`
 * (`seal`/`open`): collect the output concurrently with the feed, so an
 * implementation producing output incrementally can never deadlock against
 * an unfinished feed.
 * @param {(rx: any) => unknown} start
 * @param {Uint8Array} input
 * @returns {Promise<Uint8Array>}
 */
async function callFedCollect(start, input) {
  const out = await callFed(start, input);
  return await collectStream(out);
}

// --- keys -----------------------------------------------------------------------

// CryptoKey construction is private to this module; the WIT key resource
// handles live in a WeakMap rather than on the key object.
const HANDLES = new WeakMap();
const MINT_TOKEN = Symbol("CryptoKey mint token");

/**
 * The WebCrypto `CryptoKey` projection of a `lann:webcrypto` key resource.
 * Always `type: "secret"` here (HMAC and AES-GCM keys).
 */
export class CryptoKey {
  /** @type {KeyAlgorithm} */
  #algorithm;
  #extractable;
  /** @type {readonly KeyUsage[]} */
  #usages;

  /**
   * @param {symbol} token
   * @param {any} handle the `lann:webcrypto` key resource
   * @param {KeyAlgorithm} algorithm
   * @param {boolean} extractable
   * @param {readonly KeyUsage[]} usages
   */
  constructor(token, handle, algorithm, extractable, usages) {
    if (token !== MINT_TOKEN) {
      throw new TypeError("CryptoKey cannot be constructed directly");
    }
    this.#algorithm = Object.freeze(algorithm);
    this.#extractable = extractable;
    this.#usages = Object.freeze([...usages]);
    HANDLES.set(this, handle);
  }

  /** @returns {KeyType} */
  get type() {
    return "secret";
  }
  get algorithm() {
    return this.#algorithm;
  }
  get extractable() {
    return this.#extractable;
  }
  /**
   * @returns {KeyUsage[]} the usage list. The API declares a mutable
   * sequence; the list handed out here is frozen, so a caller cannot edit a
   * key's permissions through it.
   */
  get usages() {
    return /** @type {KeyUsage[]} */ (this.#usages);
  }
  get [Symbol.toStringTag]() {
    return "CryptoKey";
  }
}

/**
 * @param {any} handle
 * @param {KeyAlgorithm} algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
function mintKey(handle, algorithm, extractable, usages) {
  return new CryptoKey(MINT_TOKEN, handle, algorithm, extractable, usages);
}

/**
 * @param {CryptoKey} key
 * @returns {any}
 */
function handleOf(key) {
  const handle = HANDLES.get(key);
  if (handle === undefined) {
    throw new TypeError("not a CryptoKey minted by this library");
  }
  return handle;
}

// --- algorithm and usage normalization --------------------------------------------

/**
 * An author-supplied algorithm object after normalization: the `name` is
 * validated, every other member is whatever the caller passed and is
 * validated at its use site.
 * @typedef {{
 *   name: string,
 *   hash?: unknown,
 *   length?: unknown,
 *   iv?: unknown,
 *   additionalData?: unknown,
 *   tagLength?: unknown,
 * }} NormalizedAlgorithm
 */

/**
 * @param {unknown} algorithm
 * @returns {NormalizedAlgorithm}
 */
function normalizeAlgorithm(algorithm) {
  if (typeof algorithm === "string") {
    algorithm = { name: algorithm };
  }
  if (typeof algorithm !== "object" || algorithm === null) {
    throw new TypeError("algorithm must be a string or an object with a string `name`");
  }
  // Snapshot own enumerable properties in one pass: normalization reads each
  // property (author getters included) exactly once, like the spec's
  // conversion to an IDL dictionary.
  const alg = /** @type {NormalizedAlgorithm & { name?: unknown }} */ ({ ...algorithm });
  if (typeof alg.name !== "string") {
    throw new TypeError("algorithm must be a string or an object with a string `name`");
  }
  const name = alg.name.toUpperCase();
  if (name !== "HMAC" && name !== "AES-GCM") {
    throw dom("NotSupportedError", `unsupported algorithm ${alg.name}`);
  }
  alg.name = name;
  return /** @type {NormalizedAlgorithm} */ (alg);
}

/**
 * @param {unknown} hash
 * @returns {"SHA-256"}
 */
function normalizeHash(hash) {
  if (typeof hash === "object" && hash !== null) {
    const named = /** @type {{ name?: unknown }} */ (hash).name;
    if (typeof named === "string") hash = named;
  }
  if (typeof hash !== "string") {
    throw new TypeError("HMAC requires a `hash` member (a string or { name })");
  }
  if (hash.toUpperCase() !== "SHA-256") {
    throw dom("NotSupportedError", `unsupported hash ${hash}; only SHA-256 is served`);
  }
  return "SHA-256";
}

/** @type {Readonly<Record<string, readonly KeyUsage[] | undefined>>} */
const USAGES = {
  HMAC: ["sign", "verify"],
  // `wrapKey`/`unwrapKey` are recognized AES-GCM usages a key may carry
  // even though this library exposes no wrap operations yet: usages are
  // key metadata, validated at use.
  "AES-GCM": ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
};

/**
 * @param {unknown} keyUsages
 * @param {string} name
 * @returns {KeyUsage[]}
 */
function normalizeUsages(keyUsages, name) {
  const iterable = /** @type {Iterable<KeyUsage> | null | undefined} */ (keyUsages);
  if (iterable == null || typeof iterable[Symbol.iterator] !== "function") {
    throw new TypeError("keyUsages must be a sequence");
  }
  const allowed = USAGES[name];
  if (allowed === undefined) {
    throw dom("NotSupportedError", `unsupported algorithm ${name}`);
  }
  /** @type {KeyUsage[]} */
  const usages = [];
  for (const usage of iterable) {
    if (!allowed.includes(usage)) {
      throw dom("SyntaxError", `usage ${usage} is not valid for ${name} keys`);
    }
    if (!usages.includes(usage)) {
      usages.push(usage);
    }
  }
  if (usages.length === 0) {
    throw dom("SyntaxError", "usages cannot be empty for secret keys");
  }
  return usages;
}

/**
 * @param {globalThis.CryptoKey} key
 * @param {KeyUsage} usage
 */
function requireUsage(key, usage) {
  if (!key.usages.includes(usage)) {
    throw dom("InvalidAccessError", `key does not permit ${usage}`);
  }
}

/**
 * @param {unknown} key
 * @param {string} name
 * @returns {asserts key is CryptoKey}
 */
function requireKeyAlgorithm(key, name) {
  if (!(key instanceof CryptoKey)) {
    throw new TypeError("key must be a CryptoKey");
  }
  if (key.algorithm.name !== name) {
    throw dom("InvalidAccessError", `key algorithm is ${key.algorithm.name}, not ${name}`);
  }
}

// --- JWK ----------------------------------------------------------------------------

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Unpadded base64url of `bytes` (RFC 7515's JWK `k` encoding).
 * @param {Uint8Array} bytes
 */
function toBase64url(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += B64URL[(n >> 18) & 63];
    out += B64URL[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += B64URL[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += B64URL[n & 63];
  }
  return out;
}

/**
 * Decode unpadded base64url, throwing `DataError` on anything else (the
 * spec's JWK parse failure).
 * @param {string} text
 */
function fromBase64url(text) {
  if (text.length % 4 === 1) {
    throw dom("DataError", "invalid base64url length in JWK `k`");
  }
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let at = 0;
  for (const ch of text) {
    const v = B64URL.indexOf(ch);
    if (v < 0) {
      throw dom("DataError", "invalid base64url in JWK `k`");
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (acc >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * Validate a JsonWebKey's fields against the requested import and return
 * the raw key bytes — the spec's oct-key JWK import steps, shared by HMAC
 * and AES-GCM (which differ only in the expected `alg` and `use` values).
 * @param {unknown} keyData
 * @param {string} alg the expected JWK `alg` (e.g. `"HS256"`, `"A256GCM"`)
 * @param {string} use the expected JWK `use` (`"sig"` or `"enc"`)
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
function rawFromJwk(keyData, alg, use, extractable, usages) {
  if (typeof keyData !== "object" || keyData === null) {
    throw new TypeError("JWK key data must be an object");
  }
  const jwk = /** @type {JsonWebKey} */ (keyData);
  if (jwk.kty !== "oct") {
    throw dom("DataError", `JWK kty must be "oct", got ${jwk.kty}`);
  }
  if (typeof jwk.k !== "string") {
    throw dom("DataError", "JWK must carry `k` (base64url key material)");
  }
  if (jwk.alg !== undefined && jwk.alg !== alg) {
    throw dom("DataError", `JWK alg is ${jwk.alg}, not ${alg}`);
  }
  if (jwk.use !== undefined && usages.length !== 0 && jwk.use !== use) {
    throw dom("DataError", `JWK use is ${jwk.use}, not ${use}`);
  }
  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops)) {
      throw dom("DataError", "JWK key_ops must be an array");
    }
    for (const usage of usages) {
      if (!jwk.key_ops.includes(usage)) {
        throw dom("DataError", `JWK key_ops does not permit ${usage}`);
      }
    }
  }
  if (jwk.ext === false && extractable) {
    throw dom("DataError", "JWK ext is false; the key cannot be imported extractable");
  }
  return fromBase64url(jwk.k);
}

/**
 * Build the oct-key JsonWebKey for an export (RFC 7517/7518; the spec's
 * HMAC and AES export-key JWK steps).
 * @param {Uint8Array} raw
 * @param {string} alg
 * @param {globalThis.CryptoKey} key
 * @returns {JsonWebKey}
 */
function jwkOf(raw, alg, key) {
  return {
    kty: "oct",
    k: toBase64url(raw),
    alg,
    key_ops: [...key.usages],
    ext: key.extractable,
  };
}

/**
 * The JWK `alg` for a served key's algorithm.
 * @param {globalThis.CryptoKey} key
 */
function jwkAlgOf(key) {
  return key.algorithm.name === "HMAC" ? "HS256" : "A256GCM";
}

// --- minting ------------------------------------------------------------------------

/**
 * @param {() => unknown} start
 * @param {number | undefined} length the `HmacKeyAlgorithm.length` to
 *   project, when it differs from the handle's material bits (a sub-byte
 *   import shave); `undefined` projects the handle's own length
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
async function mintHmacKey(start, length, extractable, usages) {
  const handle = await callImport(start());
  /** @type {HmacKeyAlgorithm} */
  const projected = {
    name: "HMAC",
    hash: Object.freeze({ name: "SHA-256" }),
    length: length ?? handle.algorithmLength(),
  };
  return mintKey(handle, projected, extractable, usages);
}

/**
 * @param {() => unknown} start
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
async function mintAesGcmKey(start, extractable, usages) {
  const handle = await callImport(start());
  /** @type {AesKeyAlgorithm} */
  const projected = { name: "AES-GCM", length: 256 };
  return mintKey(handle, projected, extractable, usages);
}

// --- subtle --------------------------------------------------------------------------

/**
 * @param {KeyFormat} format
 * @param {BufferSource | JsonWebKey} keyData
 * @param {AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams | HmacImportParams | AesKeyAlgorithm} algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
async function importKey(format, keyData, algorithm, extractable, keyUsages) {
  if (format !== "raw" && format !== "jwk") {
    throw dom(
      "NotSupportedError",
      `unsupported key format ${format}; only "raw" and "jwk" are served`,
    );
  }
  const alg = normalizeAlgorithm(algorithm);
  const usages = normalizeUsages(keyUsages, alg.name);

  if (alg.name === "HMAC") {
    normalizeHash(alg.hash);
    const raw =
      format === "jwk"
        ? rawFromJwk(keyData, "HS256", "sig", !!extractable, usages)
        : bytesOf(keyData, "keyData");
    // The spec's HMAC length window: when present, `length` may shave up
    // to 7 trailing bits off the material's bit length. The WIT key holds
    // the material unchanged (HMAC zero-pads keys to the block size, so
    // the shave cannot change a tag); the shaved length is CryptoKey
    // metadata, projected below.
    let length;
    if (alg.length !== undefined) {
      const requested = Number(alg.length);
      const dataBits = raw.length * 8;
      if (!(requested > dataBits - 8 && requested <= dataBits)) {
        throw dom("DataError", `HMAC length ${alg.length} does not fit ${dataBits} bits of key`);
      }
      length = requested;
    }
    return await mintHmacKey(
      () => hmacSha2.importKey("sha256", raw, !!extractable),
      length,
      !!extractable,
      usages,
    );
  } else {
    const raw =
      format === "jwk"
        ? rawFromJwk(keyData, "A256GCM", "enc", !!extractable, usages)
        : bytesOf(keyData, "keyData");
    // The library serves AES-256-GCM only, so key material is always minted
    // as the aes256 variant; other lengths fail with `DataError` (from the
    // WIT contract's `invalid-key`).
    return await mintAesGcmKey(
      () => aesGcm.importKey("aes256", raw, !!extractable),
      !!extractable,
      usages,
    );
  }
}

/**
 * @param {AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams | HmacKeyGenParams | AesKeyGenParams | Pbkdf2Params} algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
async function generateKey(algorithm, extractable, keyUsages) {
  const alg = normalizeAlgorithm(algorithm);
  const usages = normalizeUsages(keyUsages, alg.name);

  if (alg.name === "HMAC") {
    normalizeHash(alg.hash);
    // The spec's get-key-length: absent means the hash's block size (the
    // WIT default); zero is an `OperationError` before any key exists.
    if (alg.length === 0) {
      throw dom("OperationError", "HMAC length cannot be 0");
    }
    const length = alg.length === undefined ? undefined : Number(alg.length);
    return await mintHmacKey(
      () => hmacSha2.generateKey("sha256", length, !!extractable),
      undefined,
      !!extractable,
      usages,
    );
  } else {
    if (alg.length !== 256) {
      throw dom("NotSupportedError", `unsupported AES-GCM length ${alg.length}; only 256 is served`);
    }
    return await mintAesGcmKey(
      () => aesGcm.generateKey("aes256", !!extractable),
      !!extractable,
      usages,
    );
  }
}

/**
 * @overload
 * @param {"jwk"} format
 * @param {globalThis.CryptoKey} key
 * @returns {Promise<JsonWebKey>}
 */
/**
 * @overload
 * @param {Exclude<KeyFormat, "jwk">} format
 * @param {globalThis.CryptoKey} key
 * @returns {Promise<ArrayBuffer>}
 */
/**
 * @param {KeyFormat} format
 * @param {globalThis.CryptoKey} key
 * @returns {Promise<ArrayBuffer | JsonWebKey>}
 */
async function exportKey(format, key) {
  if (format !== "raw" && format !== "jwk") {
    throw dom(
      "NotSupportedError",
      `unsupported key format ${format}; only "raw" and "jwk" are served`,
    );
  }
  if (!(key instanceof CryptoKey)) {
    throw new TypeError("key must be a CryptoKey");
  }
  if (!key.extractable) {
    throw dom("InvalidAccessError", "key is not extractable");
  }
  const raw = /** @type {Uint8Array} */ (await callImport(handleOf(key).exportKey()));
  if (format === "jwk") {
    return jwkOf(raw, jwkAlgOf(key), key);
  }
  return toArrayBuffer(raw);
}

/**
 * @param {AlgorithmIdentifier | RsaPssParams | EcdsaParams} algorithm
 * @param {globalThis.CryptoKey} key
 * @param {BufferSource} data
 * @returns {Promise<ArrayBuffer>}
 */
async function sign(algorithm, key, data) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name !== "HMAC") {
    throw dom("NotSupportedError", `unsupported sign algorithm ${alg.name}`);
  }
  requireKeyAlgorithm(key, "HMAC");
  requireUsage(key, "sign");
  const handle = handleOf(key);
  const tag = await callFed((rx) => handle.sign(rx), bytesOf(data, "data"));
  return toArrayBuffer(tag);
}

/**
 * @param {AlgorithmIdentifier | RsaPssParams | EcdsaParams} algorithm
 * @param {globalThis.CryptoKey} key
 * @param {BufferSource} signature
 * @param {BufferSource} data
 * @returns {Promise<boolean>}
 */
async function verify(algorithm, key, signature, data) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name !== "HMAC") {
    throw dom("NotSupportedError", `unsupported verify algorithm ${alg.name}`);
  }
  requireKeyAlgorithm(key, "HMAC");
  requireUsage(key, "verify");
  const handle = handleOf(key);
  const tag = bytesOf(signature, "signature");
  try {
    await callFed((rx) => handle.verify(rx, tag), bytesOf(data, "data"));
    return true;
  } catch (e) {
    // The WIT surface is fail-closed (`result` rather than `bool`);
    // WebCrypto's `verify` is the one place a failed verification maps back
    // to `false`. Only `authentication-failed` is a verdict — operational
    // failures stay thrown.
    const cause = e instanceof DOMException ? /** @type {WitError | undefined} */ (e.cause) : undefined;
    if (cause?.tag === "authentication-failed") {
      return false;
    }
    throw e;
  }
}

// The tag lengths the AES-GCM registry entry permits, in bits. A value
// outside this set is *illegal* (`OperationError`, as the AES-GCM encrypt
// operation defines); every value in it is served, carried per call by
// `aead-key.seal`/`open`'s `tag-size`.
const GCM_LEGAL_TAG_LENGTHS = [32, 64, 96, 104, 112, 120, 128];

/**
 * @param {unknown} algorithm
 * @returns {{ iv: Uint8Array, aad: Uint8Array, tagSize: number | undefined }}
 */
function gcmParams(algorithm) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name !== "AES-GCM") {
    throw dom("NotSupportedError", `unsupported algorithm ${alg.name}`);
  }
  let tagSize;
  if (alg.tagLength !== undefined) {
    if (!GCM_LEGAL_TAG_LENGTHS.includes(/** @type {number} */ (alg.tagLength))) {
      throw dom("OperationError", `illegal AES-GCM tagLength ${alg.tagLength}`);
    }
    tagSize = /** @type {number} */ (alg.tagLength) / 8;
  }
  const iv = bytesOf(alg.iv, "iv");
  const aad =
    alg.additionalData === undefined
      ? new Uint8Array(0)
      : bytesOf(alg.additionalData, "additionalData");
  return { iv, aad, tagSize };
}

/**
 * @param {AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams} algorithm
 * @param {globalThis.CryptoKey} key
 * @param {BufferSource} data
 * @returns {Promise<ArrayBuffer>}
 */
async function encrypt(algorithm, key, data) {
  const { iv, aad, tagSize } = gcmParams(algorithm);
  requireKeyAlgorithm(key, "AES-GCM");
  requireUsage(key, "encrypt");
  const handle = handleOf(key);
  // `seal` output is ciphertext ‖ tag: exactly `subtle.encrypt`'s format.
  const sealed = await callFedCollect(
    (rx) => handle.seal(iv, aad, tagSize, rx),
    bytesOf(data, "data"),
  );
  return toArrayBuffer(sealed);
}

/**
 * @param {AlgorithmIdentifier | RsaOaepParams | AesCtrParams | AesCbcParams | AesGcmParams} algorithm
 * @param {globalThis.CryptoKey} key
 * @param {BufferSource} data
 * @returns {Promise<ArrayBuffer>}
 */
async function decrypt(algorithm, key, data) {
  const { iv, aad, tagSize } = gcmParams(algorithm);
  requireKeyAlgorithm(key, "AES-GCM");
  requireUsage(key, "decrypt");
  const handle = handleOf(key);
  const plaintext = await callFedCollect(
    (rx) => handle.open(iv, aad, tagSize, rx),
    bytesOf(data, "data"),
  );
  return toArrayBuffer(plaintext);
}

/** The `crypto.subtle` subset. */
export const subtle = Object.freeze({
  importKey,
  exportKey,
  generateKey,
  sign,
  verify,
  encrypt,
  decrypt,
});

/** A `crypto`-shaped namespace for code expecting `crypto.subtle`. */
export const crypto = Object.freeze({ subtle });

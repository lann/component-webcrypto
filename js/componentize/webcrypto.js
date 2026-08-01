// @ts-check
// A WebCrypto-subset library for JS guests componentized with
// componentize-js (https://github.com/dicej/componentize-js, the wit-dylib
// reboot of ComponentizeJS), backed by the `lann:webcrypto` interfaces.
//
// The surface mirrors `crypto.subtle` for the supported algorithms:
//
//   - `importKey` / `exportKey` ("raw", "jwk", "spki", and "pkcs8"
//     formats)
//   - `generateKey`
//   - `sign` / `verify`         (HMAC over SHA-1 and SHA-256/384/512;
//     Ed25519; ECDSA P-256/P-384 verification)
//   - `encrypt` / `decrypt`     (AES-GCM, and the unauthenticated
//     AES-CBC/AES-CTR through the package's `cipher` kind — see
//     `wit/README.md`, "Unauthenticated modes are in, for compatibility";
//     128- and 256-bit keys)
//   - `deriveBits` / `deriveKey` (HKDF and PBKDF2 over SHA-1 and
//     SHA-256/384/512; X25519 key agreement; derived-key targets HMAC
//     over the same hashes and AES-GCM/CBC/CTR)
//   - `digest`                  (SHA-256/384/512; SHA-1 through the
//     package's checked implementation — see the additive surface below)
//   - `getRandomValues`         (from the host's `wasi:random` entropy)
//   - `randomUUID`              (a version 4 UUID from the same entropy)
//   - `generateKey`             (the secret-key algorithms, X25519, and
//     Ed25519 pairs)
//
// The component's world must import `lann:webcrypto/hmac-sha2@0.1.0`,
// `hmac-sha1`, `aes-gcm`, `aes-cbc`, `aes-ctr`, `derivation`, `hkdf`,
// `hkdf-sha2`, `hkdf-sha1`, `pbkdf2`, `pbkdf2-sha2`, `pbkdf2-sha1`,
// `key-agreement`, `x25519`,
// `sha2`, `sha1-checked`, `digest`, `signature`, `ed25519-verify`,
// `ed25519-sign`, and
// `ecdsa-verify` — plus `wasi:random/random@0.2.0` for `getRandomValues`
// and `randomUUID`
// (their `mac`/`aead`/`types` dependencies are pulled in by WIT
// elaboration). Module specifiers here name those imports directly, so this
// file needs no bundler: componentize-js resolves them against the world at
// componentize time.
//
// Documented deviations from the Web Cryptography API (all fail closed with
// clear errors, never silently differ). Each is classified — *unserved*
// (the WIT carries the semantics; this library does not serve them yet) or
// *WIT-forced* (no shim could express the behavior through the interface
// shape; a recorded design ruling) — per AGENTS.md, "WPT fidelity is a
// first-class design constraint":
//
//   - Unserved: beyond the algorithms above, everything throws
//     `NotSupportedError` — including AES-192 (which every implementation
//     of the package declines) and AES-KW (parked with the package's wrap
//     direction).
//   - Unserved by composition: ECDSA signing, key generation, and
//     private-key import. The interface exists (`ecdsa-sign`), but it is
//     class D and the in-guest provider this library composes with
//     withholds it, so the world cannot import it without failing every
//     composition at `wac plug` time. `NotSupportedError`, with the
//     reason in the message.
//   - WIT-forced: an empty HKDF key imports on the platform but not here —
//     `hkdf.import-ikm` rejects empty input keying material by ruling
//     (`wit/README.md`, "Design notes": a zero-entropy IKM is never what a
//     caller meant), so it fails with `DataError` instead.
//   - Additive surface, not a deviation: `subtle.digest("SHA-1")` is
//     served through the package's `sha1-checked` interface (sha1dc
//     collision detection; the package never serves plain SHA-1), in the
//     *mitigating* posture by default — byte-identical to the platform on
//     every honest input, and returning the deterministic sha1dc safe
//     hash for input carrying a collision attack. The module export
//     `setSha1CollisionPolicy("mitigate" | "reject")` (not a global, not
//     on the frozen `crypto` object) opts into the rejecting posture,
//     where such input throws `OperationError` instead.
//   - Runtime gap, not a deviation of this library: there is no
//     `DOMException` in the componentize-js runtime, so this module exports
//     a minimal stand-in with the standard `.name` values
//     ("OperationError", "InvalidAccessError", "NotSupportedError",
//     "DataError", "SyntaxError", "TypeMismatchError",
//     "QuotaExceededError").
//
// AES-GCM's per-call IV lengths and `tagLength`s are carried by
// `aead-key.seal`/`open`'s parameters, so they are not deviations. Neither
// is ECDSA's per-operation `verify` hash: the WIT binds curve and hash at
// mint, and the `ecdsa-variant` enum carries the SHA-2 cross pairings of
// the served curves, so this library keeps a verifying key's public point
// and mints the (curve, hash) binding a `verify` call asks for on demand. The WIT
// grants do not ride this library's derive mints: a WIT `derive-input`'s
// grants gate `derive-bits` and cap extractable `derive-key` mints, while
// the platform's usage checks live on the *base key* and carry no cap — so
// derive sources mint with both grants and the platform's usage model is
// enforced here, the jco host's agreement-key pattern.

import * as hmacSha2 from "lann:webcrypto/hmac-sha2@0.1.0";
import * as hmacSha1Iface from "lann:webcrypto/hmac-sha1@0.1.0";
import * as aesGcm from "lann:webcrypto/aes-gcm@0.1.0";
import * as aesCbcIface from "lann:webcrypto/aes-cbc@0.1.0";
import * as aesCtrIface from "lann:webcrypto/aes-ctr@0.1.0";
import * as hkdfIface from "lann:webcrypto/hkdf@0.1.0";
import * as hkdfSha2Iface from "lann:webcrypto/hkdf-sha2@0.1.0";
import * as hkdfSha1Iface from "lann:webcrypto/hkdf-sha1@0.1.0";
import * as pbkdf2Iface from "lann:webcrypto/pbkdf2@0.1.0";
import * as pbkdf2Sha2Iface from "lann:webcrypto/pbkdf2-sha2@0.1.0";
import * as pbkdf2Sha1Iface from "lann:webcrypto/pbkdf2-sha1@0.1.0";
import * as x25519Iface from "lann:webcrypto/x25519@0.1.0";
import * as sha2Iface from "lann:webcrypto/sha2@0.1.0";
import * as sha1CheckedIface from "lann:webcrypto/sha1-checked@0.1.0";
import * as ed25519Verify from "lann:webcrypto/ed25519-verify@0.1.0";
import * as ed25519Sign from "lann:webcrypto/ed25519-sign@0.1.0";
import * as ecdsaVerify from "lann:webcrypto/ecdsa-verify@0.1.0";
// Imported for evaluation only: `make-digest` returns `digest` resources,
// whose generated class lives in this module (see the note below).
import "lann:webcrypto/digest@0.1.0";
import * as wasiRandom from "wasi:random/random@0.2.0";
import * as witWorld from "wit-world";
// The resource-owning interfaces must be imported (evaluated) for their
// generated resource classes to exist: componentize-js builds each returned
// `mac-key`/`aead-key` wrapper from the class in its interface's module.
// The `*-key-options` classes are the same interfaces' mint-time policy
// resources, constructed here per mint.
import { MacKeyOptions } from "lann:webcrypto/mac@0.1.0";
import { AeadKeyOptions } from "lann:webcrypto/aead@0.1.0";
import { CipherKeyOptions } from "lann:webcrypto/cipher@0.1.0";
import { DeriveOptions } from "lann:webcrypto/derivation@0.1.0";
import { AgreementKeyOptions } from "lann:webcrypto/key-agreement@0.1.0";
import { SigningKeyOptions } from "lann:webcrypto/signature@0.1.0";

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
 * A WIT `types.error` variant, as componentize-js delivers it: `val` is a
 * string for the detail-carrying closed cases, an `extension-error`
 * record for `extension`, and absent for the detail-free cases.
 * @typedef {{ tag: string, val?: string | { origin: string, name: string, message: string } }} WitError
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
 * The `DOMException` names for the known extension conditions, by
 * (`origin`, `name`); a pair not listed here is handled as an operational
 * failure (the package's rule for unrecognized pairs). The full WIT
 * payload rides in the `DOMException`'s `cause`.
 * @type {Readonly<Record<string, Readonly<Record<string, string>> | undefined>>}
 */
const EXTENSION_ERRORS = {
  "lann:webcrypto": { "collision-detected": "OperationError" },
};

/**
 * Map a WIT `types.error` variant onto the WebCrypto error vocabulary.
 * @param {WitError} payload
 */
function mapWitError(payload) {
  switch (payload.tag) {
    case "invalid-key":
      return dom("DataError", String(payload.val ?? "invalid key"), payload);
    case "invalid-nonce":
      return dom("OperationError", String(payload.val ?? "invalid nonce"), payload);
    case "authentication-failed":
      return dom("OperationError", "authentication failed", payload);
    case "not-extractable":
      return dom("InvalidAccessError", "key is not extractable", payload);
    case "unsupported":
      return dom("NotSupportedError", String(payload.val ?? "unsupported"), payload);
    case "not-permitted":
      return dom("InvalidAccessError", String(payload.val ?? "not permitted"), payload);
    case "key-exhausted":
      return dom("OperationError", "key exhausted", payload);
    case "extension": {
      const ext = /** @type {{ origin: string, name: string, message: string }} */ (payload.val);
      const name = EXTENSION_ERRORS[ext.origin]?.[ext.name] ?? "OperationError";
      return dom(name, ext.message || `${ext.origin} ${ext.name}`, payload);
    }
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
  return unwrapResult(value);
}

/**
 * Unwrap a possible raw canonical `result` wrapper (see `callImport`).
 * @param {unknown} value
 * @returns {any}
 */
function unwrapResult(value) {
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

/**
 * Call a synchronous `lann:webcrypto` import, normalizing a thrown
 * `ComponentError` and the raw `result` wrapper (the sync counterpart of
 * `callImport`).
 * @param {() => unknown} run
 * @returns {any}
 */
function callSync(run) {
  /** @type {unknown} */
  let value;
  try {
    value = run();
  } catch (e) {
    rethrow(e);
  }
  return unwrapResult(value);
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
 * The WebCrypto `CryptoKey` projection of a `lann:webcrypto` key resource:
 * `"secret"` for the HMAC, AES-GCM, and KDF keys, `"public"`/`"private"`
 * for the X25519 pair.
 */
export class CryptoKey {
  /** @type {KeyType} */
  #type;
  /** @type {KeyAlgorithm} */
  #algorithm;
  #extractable;
  /** @type {readonly KeyUsage[]} */
  #usages;

  /**
   * @param {symbol} token
   * @param {any} handle the `lann:webcrypto` key resource
   * @param {KeyType} type
   * @param {KeyAlgorithm} algorithm
   * @param {boolean} extractable
   * @param {readonly KeyUsage[]} usages
   */
  constructor(token, handle, type, algorithm, extractable, usages) {
    if (token !== MINT_TOKEN) {
      throw new TypeError("CryptoKey cannot be constructed directly");
    }
    this.#type = type;
    this.#algorithm = Object.freeze(algorithm);
    this.#extractable = extractable;
    this.#usages = Object.freeze([...usages]);
    HANDLES.set(this, handle);
  }

  /** @returns {KeyType} */
  get type() {
    return this.#type;
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
 * @param {KeyType} type
 * @param {KeyAlgorithm} algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
function mintKey(handle, type, algorithm, extractable, usages) {
  return new CryptoKey(MINT_TOKEN, handle, type, algorithm, extractable, usages);
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
 *   salt?: unknown,
 *   info?: unknown,
 *   iterations?: unknown,
 *   public?: unknown,
 *   namedCurve?: unknown,
 * }} NormalizedAlgorithm
 */

/** The algorithm names this library serves, in their registry spellings. */
const SERVED_ALGORITHMS = [
  "HMAC",
  "AES-GCM",
  "AES-CBC",
  "AES-CTR",
  "HKDF",
  "PBKDF2",
  "X25519",
  "Ed25519",
  "ECDSA",
];

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
  const upper = alg.name.toUpperCase();
  const name = SERVED_ALGORITHMS.find((served) => served.toUpperCase() === upper);
  if (name === undefined) {
    throw dom("NotSupportedError", `unsupported algorithm ${alg.name}`);
  }
  alg.name = name;
  // The spec normalizes nested algorithms during algorithm normalization,
  // so a bad `hash` member fails here — before usages are looked at.
  if (alg.hash !== undefined) {
    alg.hash = normalizeHashName(alg.hash);
  }
  return /** @type {NormalizedAlgorithm} */ (alg);
}

/**
 * Normalize a `hash` member to its registry spelling: a string or
 * `{ name }` object naming SHA-1 or the SHA-2 family, case-insensitively.
 * Unknown hash names are the spec's `NotSupportedError`.
 * @param {unknown} hash
 * @returns {"SHA-1" | "SHA-256" | "SHA-384" | "SHA-512"}
 */
function normalizeHashName(hash) {
  if (typeof hash === "object" && hash !== null) {
    const named = /** @type {{ name?: unknown }} */ (hash).name;
    if (typeof named === "string") hash = named;
  }
  if (typeof hash !== "string") {
    throw new TypeError("a hash algorithm must be named by a string or a { name } object");
  }
  const upper = hash.toUpperCase();
  const name = /** @type {const} */ (["SHA-1", "SHA-256", "SHA-384", "SHA-512"]).find(
    (served) => served === upper,
  );
  if (name === undefined) {
    throw dom("NotSupportedError", `unsupported hash ${hash}`);
  }
  return name;
}

/**
 * The registry spelling for each served WIT `sha2-variant` (the projected
 * `HmacKeyAlgorithm.hash` and the digest family).
 * @type {Readonly<Record<"sha256" | "sha384" | "sha512", "SHA-256" | "SHA-384" | "SHA-512">>}
 */
const SHA2_REGISTRY_NAMES = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };

/**
 * The hash parameter of the HMAC-family algorithms (HMAC, HKDF, PBKDF2),
 * resolved to the WIT route: the `sha2-variant` interfaces, or the
 * per-algorithm SHA-1 interfaces (served for compatibility — see
 * `wit/README.md`, "The SHA-1 HMAC constructions are in").
 * @param {unknown} hash
 * @returns {{ variant: "sha256" | "sha384" | "sha512" } | { sha1: true }}
 */
function hmacHashOf(hash) {
  if (typeof hash === "object" && hash !== null) {
    const named = /** @type {{ name?: unknown }} */ (hash).name;
    if (typeof named === "string") hash = named;
  }
  if (typeof hash === "string" && hash.toUpperCase() === "SHA-1") {
    return { sha1: true };
  }
  return { variant: sha2VariantOf(hash) };
}

/**
 * The WIT `sha2-variant` for a `hash` member (HMAC, the KDFs, `digest`):
 * the whole SHA-2 family the WIT carries; SHA-1 (which WPT sweeps) is not
 * in the package at all.
 * @param {unknown} hash
 * @returns {"sha256" | "sha384" | "sha512"}
 */
function sha2VariantOf(hash) {
  if (typeof hash === "object" && hash !== null) {
    const named = /** @type {{ name?: unknown }} */ (hash).name;
    if (typeof named === "string") hash = named;
  }
  if (typeof hash !== "string") {
    throw new TypeError("a hash algorithm must be named by a string or a { name } object");
  }
  switch (hash.toUpperCase()) {
    case "SHA-256":
      return "sha256";
    case "SHA-384":
      return "sha384";
    case "SHA-512":
      return "sha512";
    default:
      throw dom("NotSupportedError", `unsupported hash ${hash}; SHA-256/384/512 are served`);
  }
}

/** @type {Readonly<Record<string, readonly KeyUsage[] | undefined>>} */
const USAGES = {
  HMAC: ["sign", "verify"],
  // `wrapKey`/`unwrapKey` are recognized AES-GCM usages a key may carry
  // even though this library exposes no wrap operations yet: usages are
  // key metadata, validated at use.
  "AES-GCM": ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  // The unauthenticated modes share AES-GCM's usage vocabulary (the WIT
  // `cipher` kind records wrap/unwrap as vocabulary ahead of operations).
  "AES-CBC": ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  "AES-CTR": ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  // The derive sources share WebCrypto's usage pair. X25519's entry is the
  // *private* key's vocabulary; public keys carry no usages and are
  // validated at their import site.
  HKDF: ["deriveKey", "deriveBits"],
  PBKDF2: ["deriveKey", "deriveBits"],
  X25519: ["deriveKey", "deriveBits"],
  // The signature vocabulary; which of it a given key *position* admits
  // (public keys verify only) is checked at the import and generate sites.
  Ed25519: ["sign", "verify"],
  ECDSA: ["sign", "verify"],
};

/**
 * The WIT `ecdsa-variant` curve tags and each curve's natural hash (the
 * binding used where an operation carries no hash of its own: key
 * import). P-521 is declared by the WIT and served by no implementation;
 * it is passed through so the WIT's own `unsupported` renders it.
 * @type {Readonly<Record<string, { tag: string, hash: string } | undefined>>}
 */
const ECDSA_CURVES = {
  "P-256": { tag: "p256", hash: "SHA-256" },
  "P-384": { tag: "p384", hash: "SHA-384" },
  "P-521": { tag: "p521", hash: "SHA-512" },
};

/**
 * The WIT `ecdsa-variant` for a (curve, hash) pairing. The enum carries
 * the SHA-2 cross products of P-256/P-384 and `p521-sha512` only; a hash
 * outside the pairing set is `NotSupportedError` (the WIT cannot mint the
 * binding).
 * @param {{ tag: string }} curve
 * @param {string} hashName a registry-spelled hash name
 * @returns {string}
 */
function ecdsaVariantFor(curve, hashName) {
  const suffix = { "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512" }[hashName];
  if (suffix === undefined || (curve.tag === "p521" && suffix !== "sha512")) {
    throw dom("NotSupportedError", `unsupported ECDSA hash ${hashName} for this curve`);
  }
  return `${curve.tag}-${suffix}`;
}

/**
 * The per-hash reminting state of an ECDSA public `CryptoKey`: the WIT
 * binds curve and hash at mint, so serving WebCrypto's per-operation
 * `verify` hash means holding the public point and minting the (curve,
 * hash) binding a call asks for, cached per hash. `handles` starts with
 * the import-time binding under the curve's natural hash.
 * @type {WeakMap<CryptoKey, { point: Uint8Array, curve: { tag: string }, handles: Map<string, any> }>}
 */
const ECDSA_PUBLIC_STATE = new WeakMap();

/**
 * The WIT verifying-key handle of an ECDSA public key under `hashName`,
 * minted from the stored point on first use.
 * @param {CryptoKey} key
 * @param {string} hashName
 * @returns {Promise<any>}
 */
async function ecdsaHandleFor(key, hashName) {
  const state = ECDSA_PUBLIC_STATE.get(key);
  if (state === undefined) {
    throw new TypeError("not an ECDSA public CryptoKey minted by this library");
  }
  let handle = state.handles.get(hashName);
  if (handle === undefined) {
    const variant = ecdsaVariantFor(state.curve, hashName);
    handle = await callImport(ecdsaVerify.importVerifyingKeyRaw(variant, state.point));
    state.handles.set(hashName, handle);
  }
  return handle;
}

/**
 * The registry name of a per-operation hash, for the ECDSA mint-bound
 * comparison (any SHA name is representable; served-ness is decided by
 * the comparison, not here).
 * @param {unknown} hash
 * @returns {string}
 */
function hashNameOf(hash) {
  if (typeof hash === "object" && hash !== null) {
    const named = /** @type {{ name?: unknown }} */ (hash).name;
    if (typeof named === "string") hash = named;
  }
  if (typeof hash !== "string") {
    throw new TypeError("a hash algorithm must be named by a string or a { name } object");
  }
  return hash.toUpperCase();
}

/**
 * Validate a *public* signature-key usage set: any subset of `verify`
 * (the spec's rule for public Ed25519/ECDSA keys; empty is allowed —
 * only secret and private keys must carry a usage).
 * @param {unknown} keyUsages
 * @returns {KeyUsage[]}
 */
function verifyOnlyUsages(keyUsages) {
  const usages = normalizeUsageSequence(keyUsages);
  for (const usage of usages) {
    if (usage !== "verify") {
      throw dom("SyntaxError", `usage ${usage} is not valid for public signature keys`);
    }
  }
  return [...new Set(usages)];
}

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
  return usages;
}

/**
 * The spec's empty-usage check for secret- and private-key mints. Kept
 * separate from `normalizeUsages` because the two fire at different
 * points: usage *membership* is validated during normalization, while an
 * empty set is only rejected after the algorithm's own parameter checks
 * (a bad AES length is an `OperationError` even with empty usages).
 * @param {readonly KeyUsage[]} usages
 */
function requireNonEmptyUsages(usages) {
  if (usages.length === 0) {
    throw dom("SyntaxError", "usages cannot be empty for secret or private keys");
  }
}

/**
 * Validate that `keyUsages` is a sequence and collect it, without the
 * non-empty requirement — for the key types whose usage set must be empty
 * (X25519 public keys).
 * @param {unknown} keyUsages
 * @returns {KeyUsage[]}
 */
function normalizeUsageSequence(keyUsages) {
  const iterable = /** @type {Iterable<KeyUsage> | null | undefined} */ (keyUsages);
  if (iterable == null || typeof iterable[Symbol.iterator] !== "function") {
    throw new TypeError("keyUsages must be a sequence");
  }
  return [...iterable];
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
 * The `mac-key-options` resource carrying `usages` and `extractable` (the
 * WIT options resources are single-use, so one is built per mint).
 * Every minting path rejects empty usages with the spec's `SyntaxError`
 * before reaching here, so the WIT's own zero-usage refusal is
 * unreachable.
 * @param {readonly KeyUsage[]} usages
 * @param {boolean} extractable
 */
function hmacMintOptions(usages, extractable) {
  const options = new MacKeyOptions();
  options.canSign(usages.includes("sign"));
  options.canVerify(usages.includes("verify"));
  options.extractable(extractable);
  return options;
}

/**
 * The `aead-key-options` resource carrying `usages` and `extractable`. See
 * `hmacMintOptions`; `wrapKey`/`unwrapKey` map onto the WIT wrap usages.
 * @param {readonly KeyUsage[]} usages
 * @param {boolean} extractable
 */
function aesGcmMintOptions(usages, extractable) {
  const options = new AeadKeyOptions();
  options.canSeal(usages.includes("encrypt"));
  options.canOpen(usages.includes("decrypt"));
  options.canWrap(usages.includes("wrapKey"));
  options.canUnwrap(usages.includes("unwrapKey"));
  options.extractable(extractable);
  return options;
}

/**
 * The `cipher-key-options` resource for the unauthenticated AES modes.
 * See `hmacMintOptions`.
 * @param {readonly KeyUsage[]} usages
 * @param {boolean} extractable
 */
function cipherMintOptions(usages, extractable) {
  const options = new CipherKeyOptions();
  options.canEncrypt(usages.includes("encrypt"));
  options.canDecrypt(usages.includes("decrypt"));
  options.canWrap(usages.includes("wrapKey"));
  options.canUnwrap(usages.includes("unwrapKey"));
  options.extractable(extractable);
  return options;
}

/**
 * The WIT minting interface and JWK `alg` suffix for each served
 * unauthenticated mode (the `cipher` kind; see the header's design-note
 * pointer — nothing these keys do authenticates).
 * @type {Readonly<Record<string, { iface: any, jwkTag: string } | undefined>>}
 */
const CIPHER_MODES = {
  "AES-CBC": { iface: aesCbcIface, jwkTag: "CBC" },
  "AES-CTR": { iface: aesCtrIface, jwkTag: "CTR" },
};

/**
 * The `derive-options` resource for a KDF base-secret mint. Both grants,
 * always: the platform's usage checks live on the *base key* and carry no
 * cap rule, so the WebCrypto usages are enforced here (`requireUsage`) and
 * the WIT grants do not ride them (see the header note).
 */
function deriveMintOptions() {
  const options = new DeriveOptions();
  options.canDeriveBits(true);
  options.canDeriveKey(true);
  return options;
}

/**
 * The `agreement-key-options` resource for an X25519 secret-key mint. Both
 * derive grants, like `deriveMintOptions`; `extractable` is recorded
 * faithfully (the WIT keeps it as mint-time policy).
 * @param {boolean} extractable
 */
function agreementMintOptions(extractable) {
  const options = new AgreementKeyOptions();
  options.canDeriveBits(true);
  options.canDeriveKey(true);
  options.extractable(extractable);
  return options;
}

/**
 * The WIT `derive-input` for one derive operation: the fully parameterized
 * derivation the spec's (baseKey, normalized params) pair denotes.
 *
 * For X25519 this is where the agreement runs (`agree` computes the shared
 * secret eagerly), so two spec-mandated errors surface here: an
 * algorithm-mismatched or non-public `public` member is `InvalidAccessError`
 * (checked before the call, like the spec's derive-bits steps), and the
 * remaining `invalid-key` from `agree` is exactly the contributory all-zero
 * check, which the spec reports as `OperationError` — remapped from
 * `mapWitError`'s generic `DataError` because this call site knows which
 * check it is.
 * @param {NormalizedAlgorithm} alg
 * @param {CryptoKey} baseKey narrowed by the caller's `requireKeyAlgorithm`
 * @returns {Promise<any>} a `derivation.derive-input` resource
 */
async function prepareInput(alg, baseKey) {
  if (alg.name === "X25519") {
    const peer = alg.public;
    if (!(peer instanceof CryptoKey)) {
      throw new TypeError("X25519 derivation requires a CryptoKey as `public`");
    }
    if (peer.type !== "public") {
      throw dom("InvalidAccessError", "the `public` member must be a public key");
    }
    if (peer.algorithm.name !== "X25519") {
      throw dom(
        "InvalidAccessError",
        `public key algorithm is ${peer.algorithm.name}, not X25519`,
      );
    }
    try {
      return await callImport(handleOf(baseKey).agree(handleOf(peer)));
    } catch (e) {
      const cause = e instanceof DOMException ? /** @type {WitError | undefined} */ (e.cause) : undefined;
      if (cause?.tag === "invalid-key") {
        throw dom(
          "OperationError",
          String(cause.val ?? "the shared secret is the all-zero value"),
          cause,
        );
      }
      throw e;
    }
  }
  if (alg.name === "HKDF") {
    const route = hmacHashOf(alg.hash);
    const salt = bytesOf(alg.salt, "salt");
    const info = bytesOf(alg.info, "info");
    return await callImport(
      "sha1" in route
        ? hkdfSha1Iface.prepare(handleOf(baseKey), salt, info)
        : hkdfSha2Iface.prepare(route.variant, handleOf(baseKey), salt, info),
    );
  }
  // PBKDF2. A zero iteration count fails at `prepare` with the WIT's
  // `other`, which maps onto the platform's own `OperationError`.
  const route = hmacHashOf(alg.hash);
  const salt = bytesOf(alg.salt, "salt");
  const iterations = Number(alg.iterations);
  if (!Number.isInteger(iterations) || iterations < 0 || iterations > 0xffffffff) {
    throw new TypeError("PBKDF2 iterations must be a u32");
  }
  return await callImport(
    "sha1" in route
      ? pbkdf2Sha1Iface.prepare(handleOf(baseKey), salt, iterations)
      : pbkdf2Sha2Iface.prepare(route.variant, handleOf(baseKey), salt, iterations),
  );
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
//
// The material-bearing JWK work — JSON parsing, strict base64url, `kty`/
// `alg`/`ext` validation, and building on export — lives behind the WIT
// (`import-key-jwk`/`export-key-jwk`; the contract is on
// `mac-key.export-key-jwk`). What remains here is the policy the WIT
// deliberately does not model: `use`/`key_ops` against the requested
// usages, and stamping `key_ops`/`ext` onto exported JWKs.

/**
 * The spec's `use`/`key_ops` checks — consumer policy over the usages
 * model, which the WIT does not carry. The material fields go down as-is.
 * @param {unknown} keyData
 * @param {string} use the expected JWK `use` (`"sig"` or `"enc"`)
 * @param {readonly KeyUsage[]} usages
 * @returns {string} the JWK as JSON text, for the WIT import
 */
function jwkForImport(keyData, use, usages) {
  if (typeof keyData !== "object" || keyData === null) {
    throw new TypeError("JWK key data must be an object");
  }
  const jwk = /** @type {JsonWebKey} */ (keyData);
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
  return JSON.stringify(jwk);
}

/**
 * An exported JWK: the WIT returns the material-bearing members; the
 * metadata the interface does not model is this library's to stamp.
 * @param {string} jwkText
 * @param {globalThis.CryptoKey} key
 * @returns {JsonWebKey}
 */
function jwkForExport(jwkText, key) {
  const jwk = /** @type {JsonWebKey} */ (JSON.parse(jwkText));
  if (key.algorithm.name === "Ed25519") {
    // The one algorithm whose JWK export carries `alg` — always the
    // algorithm name, whatever alg the import carried (w3c/webcrypto#401;
    // ECDH-family and ECDSA exports set none).
    jwk.alg = "Ed25519";
  }
  jwk.key_ops = [...key.usages];
  jwk.ext = key.extractable;
  return jwk;
}

// --- minting ------------------------------------------------------------------------

/**
 * @param {() => unknown} start
 * @param {string} hashName the mint-bound hash's registry name, for the
 *   projected `HmacKeyAlgorithm.hash`
 * @param {number | undefined} requestedLength the `HmacKeyAlgorithm.length`
 *   to project, validated against the handle's material bits per the
 *   spec's shave window; `undefined` projects the handle's own length
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
async function mintHmacKey(start, hashName, requestedLength, extractable, usages) {
  const handle = await callImport(start());
  const dataBits = /** @type {number} */ (handle.algorithmLength());
  let length = dataBits;
  if (requestedLength !== undefined) {
    // The spec's HMAC length window: `length` may shave up to 7 trailing
    // bits off the material's bit length. The WIT key holds the material
    // unchanged (HMAC zero-pads keys to the block size, so the shave
    // cannot change a tag); the shaved length is CryptoKey metadata.
    if (!(requestedLength > dataBits - 8 && requestedLength <= dataBits)) {
      throw dom("DataError", `HMAC length ${requestedLength} does not fit ${dataBits} bits of key`);
    }
    length = requestedLength;
  }
  /** @type {HmacKeyAlgorithm} */
  const projected = {
    name: "HMAC",
    hash: Object.freeze({ name: hashName }),
    length,
  };
  return mintKey(handle, "secret", projected, extractable, usages);
}

/**
 * The WIT `aes-variant` for an AES key length in bits. 128 and 256 are
 * served; 192 is representable and passed through, so the WIT's own
 * package-wide decline (`unsupported`) renders it; anything else is the
 * spec's `OperationError` (the get-key-length step).
 * @param {number} bits
 * @returns {"aes128" | "aes192" | "aes256"}
 */
function aesVariantOf(bits) {
  switch (bits) {
    case 128:
      return "aes128";
    case 192:
      return "aes192";
    case 256:
      return "aes256";
    default:
      throw dom("OperationError", `AES key length must be 128, 192, or 256 bits, got ${bits}`);
  }
}

/**
 * @param {() => unknown} start
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
async function mintAesGcmKey(start, extractable, usages) {
  const handle = await callImport(start());
  /** @type {AesKeyAlgorithm} */
  const projected = { name: "AES-GCM", length: /** @type {number} */ (handle.algorithmLength()) };
  return mintKey(handle, "secret", projected, extractable, usages);
}

/**
 * @param {() => unknown} start
 * @param {string} name the mode's registry name, for the projected algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} usages
 */
async function mintCipherKey(start, name, extractable, usages) {
  const handle = await callImport(start());
  /** @type {AesKeyAlgorithm} */
  const projected = { name, length: /** @type {number} */ (handle.algorithmLength()) };
  return mintKey(handle, "secret", projected, extractable, usages);
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
  // Algorithm normalization precedes the format gate, the spec's order: a
  // malformed algorithm is a TypeError even alongside an unserved format.
  const alg = normalizeAlgorithm(algorithm);
  if (format !== "raw" && format !== "jwk" && format !== "spki" && format !== "pkcs8") {
    throw new TypeError(`${format} is not a KeyFormat`);
  }

  if (alg.name === "HKDF" || alg.name === "PBKDF2") {
    // The spec's import steps for both KDFs: "raw" is the only format, and
    // the key is forced non-extractable.
    if (format !== "raw") {
      throw dom("NotSupportedError", `${alg.name} keys support the "raw" format only`);
    }
    const usages = normalizeUsages(keyUsages, alg.name);
    requireNonEmptyUsages(usages);
    if (extractable) {
      throw dom("SyntaxError", `${alg.name} keys cannot be extractable`);
    }
    const raw = bytesOf(keyData, "keyData");
    const handle = await callImport(
      alg.name === "HKDF"
        ? hkdfIface.importIkm(raw, deriveMintOptions())
        : pbkdf2Iface.importPassword(raw, deriveMintOptions()),
    );
    return mintKey(handle, "secret", { name: alg.name }, false, usages);
  }

  if (alg.name === "X25519") {
    if (format === "raw" || format === "spki") {
      // Both public formats: public keys carry no usages.
      const requested = normalizeUsageSequence(keyUsages);
      if (requested.length !== 0) {
        throw dom("SyntaxError", "X25519 public keys take no usages");
      }
      const raw = bytesOf(keyData, "keyData");
      const handle = await callImport(
        format === "raw"
          ? x25519Iface.importPublicKeyRaw(raw)
          : x25519Iface.importPublicKeySpki(raw),
      );
      return mintKey(handle, "public", { name: "X25519" }, !!extractable, []);
    }
    if (format === "pkcs8") {
      const usages = normalizeUsages(keyUsages, "X25519");
      requireNonEmptyUsages(usages);
      const handle = await callImport(
        x25519Iface.importSecretKeyPkcs8(
          bytesOf(keyData, "keyData"),
          agreementMintOptions(!!extractable),
        ),
      );
      return mintKey(handle, "private", { name: "X25519" }, !!extractable, usages);
    }
    if (typeof keyData !== "object" || keyData === null) {
      throw new TypeError("JWK key data must be an object");
    }
    const jwk = /** @type {JsonWebKey} */ (keyData);
    if (jwk.d === undefined) {
      const requested = normalizeUsageSequence(keyUsages);
      if (requested.length !== 0) {
        throw dom("SyntaxError", "X25519 public keys take no usages");
      }
      const handle = await callImport(x25519Iface.importPublicKeyJwk(jwkForImport(jwk, "enc", [])));
      return mintKey(handle, "public", { name: "X25519" }, !!extractable, []);
    }
    const usages = normalizeUsages(keyUsages, "X25519");
    requireNonEmptyUsages(usages);
    const handle = await callImport(
      x25519Iface.importSecretKeyJwk(
        jwkForImport(jwk, "enc", usages),
        agreementMintOptions(!!extractable),
      ),
    );
    return mintKey(handle, "private", { name: "X25519" }, !!extractable, usages);
  }

  if (alg.name === "Ed25519" || alg.name === "ECDSA") {
    /** @type {string | undefined} */
    let namedCurve;
    /** @type {{ tag: string, hash: string } | undefined} */
    let curve;
    if (alg.name === "ECDSA") {
      namedCurve = typeof alg.namedCurve === "string" ? alg.namedCurve : undefined;
      curve = namedCurve === undefined ? undefined : ECDSA_CURVES[namedCurve];
      if (namedCurve === undefined || curve === undefined) {
        throw dom("NotSupportedError", `unsupported ECDSA namedCurve ${alg.namedCurve}`);
      }
    }

    // A JWK carrying `d` and the PKCS#8 format are private imports; the
    // other forms are public.
    /** @type {JsonWebKey | undefined} */
    let jwk;
    if (format === "jwk") {
      if (typeof keyData !== "object" || keyData === null) {
        throw new TypeError("JWK key data must be an object");
      }
      jwk = /** @type {JsonWebKey} */ (keyData);
    }
    if (format === "pkcs8" || jwk?.d !== undefined) {
      if (alg.name === "ECDSA") {
        // Unserved by composition: `ecdsa-sign` is class D, withheld by
        // the in-guest provider this library composes with (see the
        // header).
        throw dom(
          "NotSupportedError",
          "ECDSA private-key import is not served: ecdsa-sign is class D",
        );
      }
      const usages = normalizeUsages(keyUsages, "Ed25519");
      requireNonEmptyUsages(usages);
      if (usages.includes("verify")) {
        throw dom("SyntaxError", "verify is not valid for private signature keys");
      }
      const options = new SigningKeyOptions();
      options.canSign(true);
      options.extractable(!!extractable);
      const handle = await callImport(
        format === "pkcs8"
          ? ed25519Sign.importSigningKeyPkcs8(bytesOf(keyData, "keyData"), options)
          : ed25519Sign.importSigningKeyJwk(jwkForImport(jwk, "sig", usages), options),
      );
      return mintKey(handle, "private", { name: "Ed25519" }, !!extractable, usages);
    }

    const usages = verifyOnlyUsages(keyUsages);
    if (alg.name === "Ed25519") {
      const handle = await callImport(
        format === "jwk"
          ? ed25519Verify.importVerifyingKeyJwk(jwkForImport(jwk, "sig", usages))
          : format === "spki"
            ? ed25519Verify.importVerifyingKeySpki(bytesOf(keyData, "keyData"))
            : ed25519Verify.importVerifyingKeyRaw(bytesOf(keyData, "keyData")),
      );
      return mintKey(handle, "public", { name: "Ed25519" }, !!extractable, usages);
    }
    // ECDSA public keys keep their point for per-operation-hash reminting
    // (see `ECDSA_PUBLIC_STATE`); the import-time binding uses the curve's
    // natural hash.
    const boundCurve = /** @type {{ tag: string, hash: string }} */ (curve);
    const variant = ecdsaVariantFor(boundCurve, boundCurve.hash);
    const handle = await callImport(
      format === "jwk"
        ? ecdsaVerify.importVerifyingKeyJwk(variant, jwkForImport(jwk, "sig", usages))
        : format === "spki"
          ? ecdsaVerify.importVerifyingKeySpki(variant, bytesOf(keyData, "keyData"))
          : ecdsaVerify.importVerifyingKeyRaw(variant, bytesOf(keyData, "keyData")),
    );
    const point = /** @type {Uint8Array} */ (await callImport(handle.exportKeyRaw()));
    /** @type {EcKeyAlgorithm} */
    const projected = { name: "ECDSA", namedCurve: /** @type {string} */ (namedCurve) };
    const key = mintKey(handle, "public", projected, !!extractable, usages);
    ECDSA_PUBLIC_STATE.set(key, {
      point,
      curve: boundCurve,
      handles: new Map([[boundCurve.hash, handle]]),
    });
    return key;
  }

  if (format === "spki" || format === "pkcs8") {
    throw dom("NotSupportedError", `${alg.name} keys do not use the ${format} format`);
  }
  const usages = normalizeUsages(keyUsages, alg.name);
  requireNonEmptyUsages(usages);

  if (alg.name === "HMAC") {
    const route = hmacHashOf(alg.hash);
    const options = () => hmacMintOptions(usages, !!extractable);
    const start =
      format === "jwk"
        ? "sha1" in route
          ? () => hmacSha1Iface.importKeyJwk(jwkForImport(keyData, "sig", usages), options())
          : () => hmacSha2.importKeyJwk(route.variant, jwkForImport(keyData, "sig", usages), options())
        : "sha1" in route
          ? () => hmacSha1Iface.importKeyRaw(bytesOf(keyData, "keyData"), options())
          : () => hmacSha2.importKeyRaw(route.variant, bytesOf(keyData, "keyData"), options());
    return await mintHmacKey(
      start,
      "sha1" in route ? "SHA-1" : SHA2_REGISTRY_NAMES[route.variant],
      alg.length === undefined ? undefined : Number(alg.length),
      !!extractable,
      usages,
    );
  } else {
    // The AES family (GCM through the aead kind; CBC/CTR through the
    // cipher kind). The WIT binds the AES variant at mint, so the shim
    // picks it from what the caller supplied: the raw material's length,
    // or the JWK's `alg` (falling back to `k`'s decoded length when `alg`
    // is absent — metadata arithmetic; the material itself parses behind
    // the WIT, which re-validates the pairing either way). A length with
    // no variant maps to `DataError`, the platform's own import error.
    const mode = CIPHER_MODES[alg.name];
    const jwkTag = mode === undefined ? "GCM" : mode.jwkTag;
    /** @type {string | Uint8Array} */
    let material;
    let variant;
    if (format === "jwk") {
      if (typeof keyData !== "object" || keyData === null) {
        throw new TypeError("JWK key data must be an object");
      }
      const jwk = /** @type {JsonWebKey} */ (keyData);
      let bits;
      if (
        typeof jwk.alg === "string" &&
        new RegExp(`^A(128|192|256)${jwkTag}$`).test(jwk.alg)
      ) {
        bits = Number(jwk.alg.slice(1, 4));
      } else if (typeof jwk.k === "string") {
        bits = Math.floor((jwk.k.length * 3) / 4) * 8;
      }
      if (bits !== 128 && bits !== 192 && bits !== 256) {
        throw dom("DataError", `JWK carries no ${alg.name} key of a known length`);
      }
      variant = aesVariantOf(bits);
      material = jwkForImport(keyData, "enc", usages);
    } else {
      const raw = bytesOf(keyData, "keyData");
      if (raw.length !== 16 && raw.length !== 24 && raw.length !== 32) {
        throw dom("DataError", `${alg.name} keys are 16, 24, or 32 bytes, got ${raw.length}`);
      }
      variant = aesVariantOf(raw.length * 8);
      material = raw;
    }
    if (mode !== undefined) {
      const options = () => cipherMintOptions(usages, !!extractable);
      return await mintCipherKey(
        () =>
          format === "jwk"
            ? mode.iface.importKeyJwk(variant, material, options())
            : mode.iface.importKeyRaw(variant, material, options()),
        alg.name,
        !!extractable,
        usages,
      );
    }
    return await mintAesGcmKey(
      () =>
        format === "jwk"
          ? aesGcm.importKeyJwk(variant, material, aesGcmMintOptions(usages, !!extractable))
          : aesGcm.importKeyRaw(variant, material, aesGcmMintOptions(usages, !!extractable)),
      !!extractable,
      usages,
    );
  }
}

/**
 * @param {AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams | HmacKeyGenParams | AesKeyGenParams | Pbkdf2Params} algorithm
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} keyUsages
 * @returns {Promise<CryptoKey | CryptoKeyPair>}
 */
async function generateKey(algorithm, extractable, keyUsages) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name === "HKDF" || alg.name === "PBKDF2") {
    // The spec defines no generate operation for either KDF.
    throw dom("NotSupportedError", `${alg.name} keys cannot be generated`);
  }
  const usages = normalizeUsages(keyUsages, alg.name);

  if (alg.name === "X25519") {
    requireNonEmptyUsages(usages);
    const pair = /** @type {[any, any]} */ (
      await callImport(x25519Iface.generateKey(agreementMintOptions(!!extractable)))
    );
    return {
      privateKey: mintKey(pair[0], "private", { name: "X25519" }, !!extractable, usages),
      // Public keys are always extractable and carry no usages, as the
      // platform's generate steps set them.
      publicKey: mintKey(pair[1], "public", { name: "X25519" }, true, []),
    };
  }

  if (alg.name === "Ed25519") {
    // The spec's pair rule: a generated private key with no usages is a
    // SyntaxError, and `sign` is the only private-key usage.
    if (!usages.includes("sign")) {
      throw dom("SyntaxError", "generating an Ed25519 pair requires the sign usage");
    }
    const options = new SigningKeyOptions();
    options.canSign(true);
    options.extractable(!!extractable);
    const pair = /** @type {[any, any]} */ (await callImport(ed25519Sign.generateKey(options)));
    return {
      privateKey: mintKey(pair[0], "private", { name: "Ed25519" }, !!extractable, ["sign"]),
      publicKey: mintKey(
        pair[1],
        "public",
        { name: "Ed25519" },
        true,
        usages.includes("verify") ? ["verify"] : [],
      ),
    };
  }

  if (alg.name === "ECDSA") {
    // Unserved by composition: `ecdsa-sign` is class D, withheld by the
    // in-guest provider this library composes with, so the world cannot
    // import it (see the header).
    throw dom("NotSupportedError", "ECDSA key generation is not served: ecdsa-sign is class D");
  }

  if (alg.name === "HMAC") {
    const route = hmacHashOf(alg.hash);
    // The spec's get-key-length: absent means the hash's block size (the
    // WIT default); zero is an `OperationError` before any key exists.
    if (alg.length === 0) {
      throw dom("OperationError", "HMAC length cannot be 0");
    }
    requireNonEmptyUsages(usages);
    const length = alg.length === undefined ? undefined : Number(alg.length);
    return await mintHmacKey(
      "sha1" in route
        ? () => hmacSha1Iface.generateKey(length, hmacMintOptions(usages, !!extractable))
        : () => hmacSha2.generateKey(route.variant, length, hmacMintOptions(usages, !!extractable)),
      "sha1" in route ? "SHA-1" : SHA2_REGISTRY_NAMES[route.variant],
      undefined,
      !!extractable,
      usages,
    );
  } else {
    const variant = aesVariantOf(Number(alg.length));
    requireNonEmptyUsages(usages);
    const mode = CIPHER_MODES[alg.name];
    if (mode !== undefined) {
      return await mintCipherKey(
        () => mode.iface.generateKey(variant, cipherMintOptions(usages, !!extractable)),
        alg.name,
        !!extractable,
        usages,
      );
    }
    return await mintAesGcmKey(
      () => aesGcm.generateKey(variant, aesGcmMintOptions(usages, !!extractable)),
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
  if (format !== "raw" && format !== "jwk" && format !== "spki" && format !== "pkcs8") {
    throw new TypeError(`${format} is not a KeyFormat`);
  }
  if (!(key instanceof CryptoKey)) {
    throw new TypeError("key must be a CryptoKey");
  }
  if (!key.extractable) {
    throw dom("InvalidAccessError", "key is not extractable");
  }
  if (format === "spki" || format === "pkcs8") {
    if (key.type === "secret") {
      // The spec defines neither DER format for the symmetric families.
      throw dom("NotSupportedError", `${key.algorithm.name} keys do not use the ${format} format`);
    }
    // Each DER format serves exactly one half of a pair, by spec.
    if (format === "spki" ? key.type !== "public" : key.type !== "private") {
      throw dom(
        "InvalidAccessError",
        format === "spki"
          ? "spki export serves public keys only"
          : "pkcs8 export serves private keys only",
      );
    }
    const der = /** @type {Uint8Array} */ (
      await callImport(
        format === "spki" ? handleOf(key).exportKeySpki() : handleOf(key).exportKeyPkcs8(),
      )
    );
    return toArrayBuffer(der);
  }
  if (format === "raw" && key.type === "private") {
    // The spec's raw export is public-only for every asymmetric family.
    throw dom("InvalidAccessError", "raw export serves public keys only");
  }
  if (format === "jwk") {
    const jwkText = /** @type {string} */ (await callImport(handleOf(key).exportKeyJwk()));
    return jwkForExport(jwkText, key);
  }
  return toArrayBuffer(/** @type {Uint8Array} */ (await callImport(handleOf(key).exportKeyRaw())));
}

/**
 * @param {AlgorithmIdentifier | RsaPssParams | EcdsaParams} algorithm
 * @param {globalThis.CryptoKey} key
 * @param {BufferSource} data
 * @returns {Promise<ArrayBuffer>}
 */
async function sign(algorithm, key, data) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name === "Ed25519") {
    requireKeyAlgorithm(key, "Ed25519");
    if (key.type !== "private") {
      throw dom("InvalidAccessError", "signing requires a private key");
    }
    requireUsage(key, "sign");
    const sig = await callFed((rx) => handleOf(key).sign(rx), bytesOf(data, "data"));
    return toArrayBuffer(sig);
  }
  if (alg.name !== "HMAC") {
    // ECDSA signing is unserved by composition (class D — see the header);
    // the other served algorithms define no sign operation.
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
  if (alg.name === "Ed25519" || alg.name === "ECDSA") {
    requireKeyAlgorithm(key, alg.name);
    if (key.type !== "public") {
      throw dom("InvalidAccessError", "verification requires a public key");
    }
    requireUsage(key, "verify");
    // The WIT binds curve and hash at mint, so ECDSA's per-operation hash
    // is served by minting the requested (curve, hash) binding from the
    // key's stored point (see `ecdsaHandleFor`).
    const handle =
      alg.name === "ECDSA" ? await ecdsaHandleFor(key, hashNameOf(alg.hash)) : handleOf(key);
    const sig = bytesOf(signature, "signature");
    try {
      await callFed((rx) => handle.verify(rx, sig), bytesOf(data, "data"));
      return true;
    } catch (e) {
      const cause = e instanceof DOMException ? /** @type {WitError | undefined} */ (e.cause) : undefined;
      if (cause?.tag === "authentication-failed") {
        return false;
      }
      throw e;
    }
  }
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
 * The per-operation parameters of the unauthenticated modes, validated as
 * the spec's encrypt/decrypt operations do: AES-CBC takes a 16-byte `iv`;
 * AES-CTR a 16-byte `counter` block and a 1–128-bit counter `length` —
 * violations are `OperationError`, the operations' own error.
 * @param {NormalizedAlgorithm} alg
 * @returns {{ iv: Uint8Array, counterLength: number | undefined }}
 */
function cipherOpParams(alg) {
  if (alg.name === "AES-CBC") {
    const iv = bytesOf(alg.iv, "iv");
    if (iv.length !== 16) {
      throw dom("OperationError", `AES-CBC requires a 16-byte iv, got ${iv.length} bytes`);
    }
    return { iv, counterLength: undefined };
  }
  const counter = bytesOf(/** @type {{ counter?: unknown }} */ (alg).counter, "counter");
  if (counter.length !== 16) {
    throw dom("OperationError", `AES-CTR requires a 16-byte counter, got ${counter.length} bytes`);
  }
  const length = Number(/** @type {{ length?: unknown }} */ (alg).length);
  if (!Number.isInteger(length) || length < 1 || length > 128) {
    throw dom("OperationError", `AES-CTR counter length must be 1 to 128 bits, got ${length}`);
  }
  return { iv: counter, counterLength: length };
}

/**
 * @param {NormalizedAlgorithm} alg
 * @returns {{ iv: Uint8Array, aad: Uint8Array, tagSize: number | undefined }}
 */
function gcmParams(alg) {
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
  const alg = normalizeAlgorithm(algorithm);
  if (CIPHER_MODES[alg.name] !== undefined) {
    const { iv, counterLength } = cipherOpParams(alg);
    requireKeyAlgorithm(key, alg.name);
    requireUsage(key, "encrypt");
    const handle = handleOf(key);
    const sealed = await callFedCollect(
      (rx) => handle.encrypt(iv, counterLength, rx),
      bytesOf(data, "data"),
    );
    return toArrayBuffer(sealed);
  }
  const { iv, aad, tagSize } = gcmParams(alg);
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
  const alg = normalizeAlgorithm(algorithm);
  if (CIPHER_MODES[alg.name] !== undefined) {
    const { iv, counterLength } = cipherOpParams(alg);
    requireKeyAlgorithm(key, alg.name);
    requireUsage(key, "decrypt");
    const handle = handleOf(key);
    const plaintext = await callFedCollect(
      (rx) => handle.decrypt(iv, counterLength, rx),
      bytesOf(data, "data"),
    );
    return toArrayBuffer(plaintext);
  }
  const { iv, aad, tagSize } = gcmParams(alg);
  requireKeyAlgorithm(key, "AES-GCM");
  requireUsage(key, "decrypt");
  const handle = handleOf(key);
  const plaintext = await callFedCollect(
    (rx) => handle.open(iv, aad, tagSize, rx),
    bytesOf(data, "data"),
  );
  return toArrayBuffer(plaintext);
}

/**
 * @param {AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params} algorithm
 * @param {globalThis.CryptoKey} baseKey
 * @param {number | null} [length]
 * @returns {Promise<ArrayBuffer>}
 */
async function deriveBits(algorithm, baseKey, length) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name === "HMAC" || alg.name.startsWith("AES-")) {
    throw dom("NotSupportedError", `${alg.name} supports no derive operation`);
  }
  requireKeyAlgorithm(baseKey, alg.name);
  requireUsage(baseKey, "deriveBits");
  const input = await prepareInput(alg, baseKey);
  const bits = length == null ? undefined : Number(length);
  if (bits === undefined) {
    // The null-length behavior is the source's: an agreement's natural
    // output length (the whole shared secret), or the KDFs' refusal
    // (`error.other`, the platform's own `OperationError`).
    return toArrayBuffer(/** @type {Uint8Array} */ (await callImport(input.deriveBits(undefined))));
  }
  if (bits === 0) {
    // The platform's zero-length derive is an empty output. The WIT
    // implementations decline zero-length requests, so the empty result is
    // produced here — after `prepareInput` validated the parameters.
    return new ArrayBuffer(0);
  }
  if (bits % 8 !== 0) {
    // Sub-byte lengths: the KDFs reject them (the platform's own rule),
    // and X25519 truncates with the trailing bits of the final byte
    // zeroed. The WIT serves byte multiples and documents truncation as
    // the consumer's (`derive-bits` doc), so the containing byte multiple
    // is derived and masked here.
    if (alg.name !== "X25519") {
      throw dom("OperationError", `derive length must be a multiple of 8 bits, got ${bits}`);
    }
    const bytes = /** @type {Uint8Array} */ (
      await callImport(input.deriveBits(Math.ceil(bits / 8) * 8))
    );
    bytes[bytes.length - 1] &= 0xff << (8 - (bits % 8));
    return toArrayBuffer(bytes);
  }
  return toArrayBuffer(/** @type {Uint8Array} */ (await callImport(input.deriveBits(bits))));
}

/**
 * @param {AlgorithmIdentifier | EcdhKeyDeriveParams | HkdfParams | Pbkdf2Params} algorithm
 * @param {globalThis.CryptoKey} baseKey
 * @param {AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams} derivedKeyType
 * @param {boolean} extractable
 * @param {readonly KeyUsage[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name === "HMAC" || alg.name.startsWith("AES-")) {
    throw dom("NotSupportedError", `${alg.name} supports no derive operation`);
  }
  const target = normalizeAlgorithm(derivedKeyType);
  if (target.name !== "HMAC" && !target.name.startsWith("AES-")) {
    // Deriving a KDF or agreement key is not among the WIT's `derive-key`
    // mints (chaining is `hkdf-sha2.prepare-from`'s, below the subtle surface).
    throw dom("NotSupportedError", `unsupported derived key type ${target.name}`);
  }
  // The sequence-and-emptiness usage check precedes the derivation, but
  // the *vocabulary* check belongs to the final import step (the spec's
  // order — WPT observes a derive failure outranking a bad usage name),
  // so `normalizeUsages` runs after `prepareInput`.
  if (normalizeUsageSequence(keyUsages).length === 0) {
    throw dom("SyntaxError", "usages cannot be empty for secret or private keys");
  }
  requireKeyAlgorithm(baseKey, alg.name);
  requireUsage(baseKey, "deriveKey");
  const input = await prepareInput(alg, baseKey);
  const usages = normalizeUsages(keyUsages, target.name);

  if (target.name === "HMAC") {
    const route = hmacHashOf(target.hash);
    if (target.length === 0) {
      throw dom("OperationError", "HMAC length cannot be 0");
    }
    const length = target.length === undefined ? undefined : Number(target.length);
    return await mintHmacKey(
      "sha1" in route
        ? () => hmacSha1Iface.deriveKey(input, length, hmacMintOptions(usages, !!extractable))
        : () =>
            hmacSha2.deriveKey(route.variant, input, length, hmacMintOptions(usages, !!extractable)),
      "sha1" in route ? "SHA-1" : SHA2_REGISTRY_NAMES[route.variant],
      undefined,
      !!extractable,
      usages,
    );
  }
  const variant = aesVariantOf(Number(target.length));
  const mode = CIPHER_MODES[target.name];
  if (mode !== undefined) {
    return await mintCipherKey(
      () => mode.iface.deriveKey(variant, input, cipherMintOptions(usages, !!extractable)),
      target.name,
      !!extractable,
      usages,
    );
  }
  return await mintAesGcmKey(
    () => aesGcm.deriveKey(variant, input, aesGcmMintOptions(usages, !!extractable)),
    !!extractable,
    usages,
  );
}

/**
 * The `digest.digest` resources, minted once per served variant (the
 * SHA-1 postures cache under their own keys): the WIT resource is
 * reusable and stateless per call, so one handle serves every
 * `subtle.digest` invocation of its hash.
 * @type {Map<string, any>}
 */
const DIGESTS = new Map();

/** @param {"sha256" | "sha384" | "sha512" | "sha1-mitigate" | "sha1-reject"} variant */
function digestFor(variant) {
  let handle = DIGESTS.get(variant);
  if (handle === undefined) {
    handle = callSync(() =>
      variant === "sha1-mitigate"
        ? sha1CheckedIface.makeMitigatingDigest()
        : variant === "sha1-reject"
          ? sha1CheckedIface.makeRejectingDigest()
          : sha2Iface.makeDigest(variant),
    );
    DIGESTS.set(variant, handle);
  }
  return handle;
}

/**
 * The collision posture `subtle.digest("SHA-1")` uses (the additive
 * surface documented in the header): the sha1dc default, mitigate.
 * @type {"mitigate" | "reject"}
 */
let sha1CollisionPolicy = "mitigate";

/**
 * Choose what `subtle.digest("SHA-1")` does with input carrying a SHA-1
 * collision attack: `"mitigate"` (the default) returns the deterministic
 * sha1dc safe hash; `"reject"` throws `OperationError`. Honest input
 * hashes identically either way. See the header's additive-surface note.
 * @param {"mitigate" | "reject"} policy
 */
export function setSha1CollisionPolicy(policy) {
  if (policy !== "mitigate" && policy !== "reject") {
    throw new TypeError(`SHA-1 collision policy must be "mitigate" or "reject", got ${policy}`);
  }
  sha1CollisionPolicy = policy;
}

/**
 * @param {AlgorithmIdentifier} algorithm
 * @param {BufferSource} data
 * @returns {Promise<ArrayBuffer>}
 */
async function digest(algorithm, data) {
  // Normalization reads the algorithm before the data is copied, the
  // spec's order (WPT's altered-buffer tests observe it through a `name`
  // getter that edits the buffer).
  const variant = digestVariantOf(algorithm);
  const bytes = bytesOf(data, "data");
  const out = await callFed((rx) => digestFor(variant).compute(rx), bytes);
  return toArrayBuffer(out);
}

/**
 * The digest handle key for a `subtle.digest` algorithm: the SHA-2 family,
 * plus SHA-1 under the current collision policy.
 * @param {AlgorithmIdentifier} algorithm
 * @returns {"sha256" | "sha384" | "sha512" | "sha1-mitigate" | "sha1-reject"}
 */
function digestVariantOf(algorithm) {
  if (typeof algorithm === "object" && algorithm !== null) {
    const named = /** @type {{ name?: unknown }} */ (algorithm).name;
    if (typeof named === "string") algorithm = named;
  }
  if (typeof algorithm === "string" && algorithm.toUpperCase() === "SHA-1") {
    return sha1CollisionPolicy === "reject" ? "sha1-reject" : "sha1-mitigate";
  }
  return sha2VariantOf(algorithm);
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
  deriveBits,
  deriveKey,
  digest,
});

/**
 * The integer TypedArray types `getRandomValues` fills (subclasses pass
 * `instanceof`); everything else — floats, `DataView`, non-views — is the
 * spec's `TypeMismatchError`.
 */
const INTEGER_ARRAY_TYPES = [
  Int8Array,
  Int16Array,
  Int32Array,
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  BigInt64Array,
  BigUint64Array,
];

/**
 * Fill an integer TypedArray with cryptographically secure random bytes
 * from the host's entropy (`wasi:random/random`), per the spec: the type
 * check precedes the 65536-byte quota, and the array itself is returned.
 * @template {ArrayBufferView} T
 * @param {T} array
 * @returns {T}
 */
function getRandomValues(array) {
  if (!INTEGER_ARRAY_TYPES.some((type) => array instanceof type)) {
    throw dom("TypeMismatchError", "getRandomValues fills integer TypedArrays only");
  }
  if (array.byteLength > 65536) {
    throw dom("QuotaExceededError", `getRandomValues fills at most 65536 bytes, not ${array.byteLength}`);
  }
  const bytes = /** @type {Uint8Array} */ (wasiRandom.getRandomBytes(BigInt(array.byteLength)));
  new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(bytes);
  return array;
}

/**
 * Generate a version 4 UUID from the host's entropy
 * (`wasi:random/random`), per the spec's "generate a random UUID"
 * algorithm (RFC 9562, section 5.4): 16 random bytes with the version and
 * variant bits set, rendered as lowercase hexadecimal.
 * @returns {`${string}-${string}-${string}-${string}-${string}`}
 */
function randomUUID() {
  const bytes = /** @type {Uint8Array} */ (wasiRandom.getRandomBytes(16n));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** A `crypto`-shaped namespace for code expecting `crypto.subtle`. */
export const crypto = Object.freeze({ subtle, getRandomValues, randomUUID });

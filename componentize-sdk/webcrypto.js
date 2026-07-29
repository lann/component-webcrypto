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
//   - Unserved: only the `"raw"` key format is served; others throw
//     `NotSupportedError`.
//   - WIT-forced (wit/aes.wit, `aead.tag-size`): AES-GCM nonces follow the
//     `lann:webcrypto` contract: 12-byte IVs and 128-bit tags only. Other
//     IV lengths throw `OperationError` (browsers accept them); a
//     legal-but-unserved `tagLength` (32–120) throws `NotSupportedError`,
//     while a value outside the registry's set throws `OperationError` as
//     the spec's AES-GCM operations define.
//   - Unserved: HMAC's `length` parameter must be omitted or name the
//     key's exact bit length; WebCrypto's sub-byte truncation is not
//     supported.
//   - Runtime gap, not a deviation of this library: there is no
//     `DOMException` in the componentize-js runtime, so this module exports
//     a minimal stand-in with the standard `.name` values
//     ("OperationError", "InvalidAccessError", "NotSupportedError",
//     "DataError", "SyntaxError").

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
  constructor(message, name = "Error", options = undefined) {
    super(message, options);
    this.name = name;
  }
}

function dom(name, message, cause = undefined) {
  return new DOMException(message, name, cause === undefined ? undefined : { cause });
}

/**
 * True for errors raised by the `lann:webcrypto` imports: componentize-js
 * surfaces an `err` result as a thrown `ComponentError` whose `payload` is
 * the WIT `types.error` variant, a `{ tag, val }` object.
 */
function isWitError(e) {
  return (
    e instanceof Error &&
    typeof e.payload === "object" &&
    e.payload !== null &&
    typeof e.payload.tag === "string"
  );
}

/** Map a WIT `types.error` variant onto the WebCrypto error vocabulary. */
function mapWitError(payload) {
  switch (payload.tag) {
    case "invalid-key":
      return dom("DataError", payload.val, payload);
    case "invalid-nonce":
      return dom("OperationError", payload.val, payload);
    case "authentication-failed":
      return dom("OperationError", "authentication failed", payload);
    case "not-extractable":
      return dom("InvalidAccessError", "key is not extractable", payload);
    case "unsupported":
      return dom("NotSupportedError", payload.val, payload);
    case "key-exhausted":
      return dom("OperationError", "key exhausted", payload);
    default:
      return dom("OperationError", String(payload.val ?? "operation failed"), payload);
  }
}

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
 */
async function callImport(promise) {
  let value;
  try {
    value = await promise;
  } catch (e) {
    rethrow(e);
  }
  if (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype &&
    (value.tag === "ok" || value.tag === "err")
  ) {
    if (value.tag === "err") {
      throw mapWitError(value.val);
    }
    return value.val;
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

function toArrayBuffer(u8) {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
}

/**
 * Write `bytes` to the writable end of a stream and drop it: writer drop is
 * the stream's only end-of-input signal.
 */
async function feedAll(tx, bytes) {
  try {
    await tx.writeAll(bytes);
  } finally {
    tx[Symbol.dispose]();
  }
}

/** Drain a `stream<u8>` readable end to a single Uint8Array. */
async function collectStream(rx) {
  using _rx = rx;
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
  #algorithm;
  #extractable;
  #usages;

  constructor(token, handle, algorithm, extractable, usages) {
    if (token !== MINT_TOKEN) {
      throw new TypeError("CryptoKey cannot be constructed directly");
    }
    this.#algorithm = Object.freeze(algorithm);
    this.#extractable = extractable;
    this.#usages = Object.freeze([...usages]);
    HANDLES.set(this, handle);
  }

  get type() {
    return "secret";
  }
  get algorithm() {
    return this.#algorithm;
  }
  get extractable() {
    return this.#extractable;
  }
  get usages() {
    return this.#usages;
  }
  get [Symbol.toStringTag]() {
    return "CryptoKey";
  }
}

function mintKey(handle, algorithm, extractable, usages) {
  return new CryptoKey(MINT_TOKEN, handle, algorithm, extractable, usages);
}

function handleOf(key) {
  const handle = HANDLES.get(key);
  if (handle === undefined) {
    throw new TypeError("not a CryptoKey minted by this library");
  }
  return handle;
}

// --- algorithm and usage normalization --------------------------------------------

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
  const alg = { ...algorithm };
  if (typeof alg.name !== "string") {
    throw new TypeError("algorithm must be a string or an object with a string `name`");
  }
  const name = alg.name.toUpperCase();
  if (name !== "HMAC" && name !== "AES-GCM") {
    throw dom("NotSupportedError", `unsupported algorithm ${alg.name}`);
  }
  alg.name = name;
  return alg;
}

function normalizeHash(hash) {
  if (typeof hash === "object" && hash !== null && typeof hash.name === "string") {
    hash = hash.name;
  }
  if (typeof hash !== "string") {
    throw new TypeError("HMAC requires a `hash` member (a string or { name })");
  }
  if (hash.toUpperCase() !== "SHA-256") {
    throw dom("NotSupportedError", `unsupported hash ${hash}; only SHA-256 is served`);
  }
  return "SHA-256";
}

const USAGES = {
  HMAC: ["sign", "verify"],
  "AES-GCM": ["encrypt", "decrypt"],
};

function normalizeUsages(keyUsages, name) {
  if (keyUsages == null || typeof keyUsages[Symbol.iterator] !== "function") {
    throw new TypeError("keyUsages must be a sequence");
  }
  const allowed = USAGES[name];
  const usages = [];
  for (const usage of keyUsages) {
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

function requireUsage(key, usage) {
  if (!key.usages.includes(usage)) {
    throw dom("InvalidAccessError", `key does not permit ${usage}`);
  }
}

function requireKeyAlgorithm(key, name) {
  if (!(key instanceof CryptoKey)) {
    throw new TypeError("key must be a CryptoKey");
  }
  if (key.algorithm.name !== name) {
    throw dom("InvalidAccessError", `key algorithm is ${key.algorithm.name}, not ${name}`);
  }
}

// --- minting ------------------------------------------------------------------------

async function mintHmacKey(start, algorithm, extractable, usages) {
  const handle = await callImport(start());
  const projected = {
    name: "HMAC",
    hash: Object.freeze({ name: "SHA-256" }),
    length: handle.algorithmLength(),
  };
  // `length`, when supplied, must name the key's exact bit length (see the
  // deviations note above).
  if (algorithm.length !== undefined && algorithm.length !== projected.length) {
    throw dom(
      "NotSupportedError",
      `HMAC length ${algorithm.length} does not match the key's ${projected.length} bits`,
    );
  }
  return mintKey(handle, projected, extractable, usages);
}

async function mintAesGcmKey(start, extractable, usages) {
  const handle = await callImport(start());
  return mintKey(handle, { name: "AES-GCM", length: 256 }, extractable, usages);
}

// --- subtle --------------------------------------------------------------------------

async function importKey(format, keyData, algorithm, extractable, keyUsages) {
  if (format !== "raw") {
    throw dom("NotSupportedError", `unsupported key format ${format}; only "raw" is served`);
  }
  const alg = normalizeAlgorithm(algorithm);
  const usages = normalizeUsages(keyUsages, alg.name);
  const raw = bytesOf(keyData, "keyData");

  if (alg.name === "HMAC") {
    normalizeHash(alg.hash);
    return await mintHmacKey(
      () => hmacSha2.importKey("sha256", raw, !!extractable),
      alg,
      !!extractable,
      usages,
    );
  } else {
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

async function generateKey(algorithm, extractable, keyUsages) {
  const alg = normalizeAlgorithm(algorithm);
  const usages = normalizeUsages(keyUsages, alg.name);

  if (alg.name === "HMAC") {
    normalizeHash(alg.hash);
    // The backing `generate-key` mints WebCrypto's default HMAC-SHA-256 key
    // length (the hash's 512-bit block size).
    if (alg.length !== undefined && alg.length !== 512) {
      throw dom(
        "NotSupportedError",
        `unsupported HMAC length ${alg.length}; only the default 512 is served`,
      );
    }
    return await mintHmacKey(
      () => hmacSha2.generateKey("sha256", !!extractable),
      alg,
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

async function exportKey(format, key) {
  if (format !== "raw") {
    throw dom("NotSupportedError", `unsupported key format ${format}; only "raw" is served`);
  }
  if (!(key instanceof CryptoKey)) {
    throw new TypeError("key must be a CryptoKey");
  }
  if (!key.extractable) {
    throw dom("InvalidAccessError", "key is not extractable");
  }
  return toArrayBuffer(await callImport(handleOf(key).exportKey()));
}

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
    if (e instanceof DOMException && e.cause?.tag === "authentication-failed") {
      return false;
    }
    throw e;
  }
}

// The tag lengths the AES-GCM registry entry permits. This library serves
// only 128 (the `lann:webcrypto` contract), but the distinction matters for
// errors: a value outside this set is *illegal* (`OperationError`, as the
// AES-GCM encrypt operation defines), while a legal value this library does
// not serve is `NotSupportedError`.
const GCM_LEGAL_TAG_LENGTHS = [32, 64, 96, 104, 112, 120, 128];

function gcmParams(algorithm) {
  const alg = normalizeAlgorithm(algorithm);
  if (alg.name !== "AES-GCM") {
    throw dom("NotSupportedError", `unsupported algorithm ${alg.name}`);
  }
  if (alg.tagLength !== undefined && alg.tagLength !== 128) {
    if (!GCM_LEGAL_TAG_LENGTHS.includes(alg.tagLength)) {
      throw dom("OperationError", `illegal AES-GCM tagLength ${alg.tagLength}`);
    }
    throw dom("NotSupportedError", `unsupported tagLength ${alg.tagLength}; only 128 is served`);
  }
  const iv = bytesOf(alg.iv, "iv");
  const aad =
    alg.additionalData === undefined
      ? new Uint8Array(0)
      : bytesOf(alg.additionalData, "additionalData");
  return { iv, aad };
}

async function encrypt(algorithm, key, data) {
  const { iv, aad } = gcmParams(algorithm);
  requireKeyAlgorithm(key, "AES-GCM");
  requireUsage(key, "encrypt");
  const handle = handleOf(key);
  // `seal` output is ciphertext ‖ tag: exactly `subtle.encrypt`'s format.
  const sealed = await callFedCollect((rx) => handle.seal(iv, aad, rx), bytesOf(data, "data"));
  return toArrayBuffer(sealed);
}

async function decrypt(algorithm, key, data) {
  const { iv, aad } = gcmParams(algorithm);
  requireKeyAlgorithm(key, "AES-GCM");
  requireUsage(key, "decrypt");
  const handle = handleOf(key);
  const plaintext = await callFedCollect((rx) => handle.open(iv, aad, rx), bytesOf(data, "data"));
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

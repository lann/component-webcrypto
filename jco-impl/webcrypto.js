// @ts-check
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
 * A guest-provided `stream<u8>`. The `read`-batching shape is jco's own
 * `Stream` object: this restates the convention documented above so the
 * collector's branches can be checked against *something*, and does not
 * verify it — only running against jco does that.
 * @typedef {{ read(options: { count: number }): Promise<{ value: unknown, done: boolean }> }} JcoStream
 * @typedef {AsyncIterable<unknown> | ReadableStream<unknown> | JcoStream} ByteStream
 */

/**
 * One operation's admitted share of the input-buffering pool. `release` is
 * idempotent.
 * @typedef {{ cap: number, release: () => void }} Reservation
 */

/**
 * The algorithm record bound to a signature key at mint. One shape for both
 * families: Ed25519 has no curve and no mint-bound hash (RFC 8032 fixes
 * SHA-512 internally).
 * @typedef {object} SignatureAlgorithm
 * @property {string} name
 * @property {string | undefined} namedCurve
 * @property {string | undefined} hash
 * @property {number} publicLength
 * @property {number} scalarLength
 * @property {number} signatureLength
 */

/**
 * An `ECDSA_VARIANTS` entry: a `SignatureAlgorithm` whose curve is fixed,
 * carrying the curve OID the PKCS#8 wrapping needs.
 * @typedef {SignatureAlgorithm & { namedCurve: string, hash: string }} EcdsaAlgorithm
 */

/**
 * Narrow a WIT-lifted byte list to the `ArrayBuffer`-backed view WebCrypto
 * takes. `BufferSource` excludes `SharedArrayBuffer`-backed views, which
 * cannot occur here: jco lifts a `list<u8>` by copying out of the
 * component's memory into a fresh array.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array<ArrayBuffer>}
 */
function asBufferSource(bytes) {
  return /** @type {Uint8Array<ArrayBuffer>} */ (bytes);
}

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

/**
 * `error.invalid-key` with a human-readable detail.
 * @param {string} val
 */
function errInvalidKey(val) {
  return witError("invalid-key", val);
}

/**
 * `error.invalid-nonce` with a human-readable detail.
 * @param {string} val
 */
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

/**
 * `error.unsupported` with a human-readable detail.
 * @param {string} val
 */
function errUnsupported(val) {
  return witError("unsupported", val);
}

/** `error.key-exhausted`. */
function errKeyExhausted() {
  return witError("key-exhausted");
}

/**
 * `error.not-permitted` with a human-readable detail.
 * @param {string} val
 */
function errNotPermitted(val) {
  return witError("not-permitted", val);
}

/**
 * The refusal an operation renders on a usage-denied key (the same string
 * the shared Rust core renders, so the implementations report identically).
 * @param {string} operation
 */
function notPermitted(operation) {
  return errNotPermitted(`this key does not permit ${operation}`);
}

/**
 * The WebCrypto usages granted by `pairs` (`[usage, granted]`), throwing
 * `{ tag: 'not-permitted' }` when nothing is granted — the package-wide
 * options contract's at-least-one-usage mint check, run before any other
 * validation like the shared Rust core.
 * @param {[KeyUsage, boolean][]} pairs
 * @returns {KeyUsage[]}
 */
function grantedUsages(pairs) {
  const usages = pairs.filter(([, granted]) => granted).map(([usage]) => usage);
  if (usages.length === 0) {
    throw errNotPermitted("a key with no enabled usage cannot be minted");
  }
  return usages;
}

/**
 * Lift a `subtle.decrypt` rejection. A failed tag check surfaces as
 * `OperationError`, which is `authentication-failed` and deliberately
 * carries no detail. Anything else — `DataError`, `InvalidAccessError`,
 * `QuotaExceededError` — is an operational condition: reporting those as
 * `authentication-failed` would render a local fault as an attack signal
 * and hide real bugs behind an expected-looking error.
 * @param {unknown} err
 */
function decryptFailure(err) {
  const failure = asPlatformError(err);
  if (failure.name === "OperationError") return errAuthenticationFailed();
  return errOther(`open: ${failure.detail}`);
}

/**
 * `error.other` with a human-readable detail.
 * @param {string} val
 */
function errOther(val) {
  return witError("other", val);
}

/**
 * Whether `value` is already a WIT error payload (`{ tag, val? }`).
 * @param {unknown} value
 * @returns {value is { tag: string, val?: string }}
 */
function isWitError(value) {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (/** @type {{ tag?: unknown }} */ (value).tag) === "string"
  );
}

/**
 * The `name` and human-readable detail of a caught platform rejection.
 * `catch` binds `unknown`, and a `DOMException`'s discriminating `name` is
 * the whole basis of the taxonomy mapping, so the read is done once here
 * rather than at each site.
 * @param {unknown} err
 * @returns {{ name: string | undefined, detail: string }}
 */
function asPlatformError(err) {
  const shape = /** @type {{ name?: unknown, message?: unknown } | null | undefined} */ (err);
  const name = typeof shape?.name === "string" ? shape.name : undefined;
  const message = typeof shape?.message === "string" ? shape.message : undefined;
  return { name, detail: message ?? String(err) };
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
    const failure = asPlatformError(err);
    if (failure.name === "NotSupportedError") {
      throw errUnsupported(`${what} is not served by this platform: ${failure.detail}`);
    }
    throw errOther(`${what} failed: ${failure.detail}`);
  }
}

/**
 * The hash name and block length for each served `sha2-variant` enum case
 * (jco lowers WIT enums as their kebab-case names). The truncated variants
 * (sha224, sha512-224, sha512-256) are absent: WebCrypto does not serve
 * them, so this implementation declines them (see the WIT `sha2-variant`
 * doc).
 */
/** @type {Readonly<Record<string, { hash: string, blockBytes: number } | undefined>>} */
const SHA2_VARIANTS = Object.assign(Object.create(null), {
  sha256: { hash: "SHA-256", blockBytes: 64 },
  sha384: { hash: "SHA-384", blockBytes: 128 },
  sha512: { hash: "SHA-512", blockBytes: 128 },
});

/**
 * The served entry for `variant` in a variant table, throwing
 * `{ tag: 'unsupported', val }` for a variant this implementation declines.
 * @template T
 * @param {Readonly<Record<string, T | undefined>>} table
 * @param {string} variant
 * @returns {T}
 */
function served(table, variant) {
  const entry = table[variant];
  if (entry === undefined) {
    throw errUnsupported(`${variant} is not served by this implementation`);
  }
  return entry;
}

/**
 * The served `sha2-variant` entry for `variant`.
 * @param {string} variant
 */
function sha2Variant(variant) {
  return served(SHA2_VARIANTS, variant);
}

/**
 * The `mac-key-options` resource: mint-time policy under construction. Per
 * the package-wide options contract the constructor grants nothing; the
 * setters are opt-in, and a mint consumes the accumulated policy through
 * `macPolicy`. The state lives in a module-private `WeakMap` rather than
 * private fields, so the class stays structurally compatible with the
 * generated interface types; the map lookup doubles as the same-provider
 * check the WIT requires (a foreign object is not a key).
 */
/** @type {WeakMap<MacKeyOptions, { sign: boolean, verify: boolean, extractable: boolean }>} */
const macPolicies = new WeakMap();

/**
 * The policy accumulated by `options`, read by the setters and at mint.
 * @param {MacKeyOptions} options
 */
function macPolicy(options) {
  const policy = macPolicies.get(options);
  if (policy === undefined) {
    throw errOther("mac-key-options minted by another provider");
  }
  return policy;
}

export class MacKeyOptions {
  constructor() {
    macPolicies.set(this, { sign: false, verify: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canSign(allowed) {
    macPolicy(this).sign = allowed;
  }

  /** @param {boolean} allowed */
  canVerify(allowed) {
    macPolicy(this).verify = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    macPolicy(this).extractable = allowed;
  }
}

/**
 * The `mac-key` resource: an HMAC key bound to a SHA-2 variant. Holds a
 * `CryptoKey` imported with exactly the usages its mint options granted and
 * the options' `extractable` flag, so the platform enforces the policy the
 * resource reports; instances are minted only by the `hmac-sha2`
 * interface functions below.
 * `sign`/`verify` are one-shot and stateless per call, matching
 * `subtle.sign`/`verify` exactly (WebCrypto has no incremental HMAC): each
 * call collects its entire input stream, then signs or verifies it whole.
 */
export class MacKey {
  #key;
  /**
   * The algorithm parameters, fixed at mint. The getters are declared
   * *total* in the WIT — they have no error case — so they must not depend
   * on `HmacKeyAlgorithm`'s `length` and `hash`, which an engine may omit
   * for an imported key: lowering `undefined` into a `u32` is
   * unrepresentable, and a missing hash would report the key as bound to no
   * digest.
   */
  #lengthBits;
  #hashName;

  /**
   * @param {CryptoKey} key
   * @param {number} lengthBits
   * @param {string} hashName
   */
  constructor(key, lengthBits, hashName) {
    this.#key = key;
    this.#lengthBits = lengthBits;
    this.#hashName = hashName;
  }

  /**
   * Compute the authentication tag over an entire byte stream, resolving
   * once the stream is fully drained. Throws `{ tag: 'not-permitted' }` on
   * a key minted without the `sign` usage.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async sign(data) {
    return withCollectedInput(data, async (message) => {
      if (!this.canSign()) throw notPermitted("sign");
      return new Uint8Array(
        await platformCall("HMAC sign", () => subtle.sign("HMAC", this.#key, message)),
      );
    });
  }

  /**
   * Verify `tag` against the tag computed over an entire byte stream; the
   * platform performs the constant-time comparison. Throws
   * `{ tag: 'authentication-failed' }` if the tag does not verify, and
   * `{ tag: 'not-permitted' }` on a key minted without the `verify` usage.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   * @param {Uint8Array} tag
   */
  async verify(data, tag) {
    await withCollectedInput(data, async (message) => {
      if (!this.canVerify()) throw notPermitted("verify");
      const ok = await platformCall("HMAC verify", () =>
        subtle.verify("HMAC", this.#key, asBufferSource(tag), message),
      );
      if (!ok) {
        throw errAuthenticationFailed();
      }
    });
  }

  /**
   * The algorithm getters. `name` projects the `CryptoKey`; `hash` and
   * `length` come from the mint instead (see `#lengthBits`).
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmHash() {
    return this.#hashName;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  /** Whether `exportKey` may return the material: the `CryptoKey`'s own flag. */
  extractable() {
    return this.#key.extractable;
  }

  /** The usage grants: projections of the `CryptoKey`'s own usage list. */
  canSign() {
    return this.#key.usages.includes("sign");
  }

  canVerify() {
    return this.#key.usages.includes("verify");
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the key
   * was created with `extractable` true (see `exportRawGated`).
   */
  async exportKey() {
    return exportRawGated(this.#key);
  }

  /**
   * The key as an `oct` JWK (JSON text; the `mac-key.export-key-jwk`
   * contract), behind the same extractability gate as `exportKey`.
   */
  async exportKeyJwk() {
    return exportJwkGated(this.#key);
  }
}

/**
 * The `aead-key-options` resource. See `MacKeyOptions` for the state and
 * same-provider mechanics; the wrap/unwrap usages map onto WebCrypto's
 * `wrapKey`/`unwrapKey` (recorded on the platform key; no operation in
 * this package consumes them yet).
 */
/** @type {WeakMap<AeadKeyOptions, { seal: boolean, open: boolean, wrap: boolean, unwrap: boolean, extractable: boolean }>} */
const aeadPolicies = new WeakMap();

/**
 * The policy accumulated by `options`, read by the setters and at mint.
 * @param {AeadKeyOptions} options
 */
function aeadPolicy(options) {
  const policy = aeadPolicies.get(options);
  if (policy === undefined) {
    throw errOther("aead-key-options minted by another provider");
  }
  return policy;
}

export class AeadKeyOptions {
  constructor() {
    aeadPolicies.set(this, {
      seal: false,
      open: false,
      wrap: false,
      unwrap: false,
      extractable: false,
    });
  }

  /** @param {boolean} allowed */
  canSeal(allowed) {
    aeadPolicy(this).seal = allowed;
  }

  /** @param {boolean} allowed */
  canOpen(allowed) {
    aeadPolicy(this).open = allowed;
  }

  /** @param {boolean} allowed */
  canWrap(allowed) {
    aeadPolicy(this).wrap = allowed;
  }

  /** @param {boolean} allowed */
  canUnwrap(allowed) {
    aeadPolicy(this).unwrap = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    aeadPolicy(this).extractable = allowed;
  }
}

/**
 * The `aead-key` resource: an AES-GCM key. Holds a `CryptoKey` imported
 * with exactly the usages its mint options granted and the options'
 * `extractable` flag, so the platform enforces the policy the resource
 * reports; instances are minted only by the `aes-gcm` interface functions
 * below.
 */
export class AeadKey {
  #key;
  /**
   * The key length in bits, fixed at mint. `aead-key.algorithm-length` is
   * declared *total* in the WIT, so it must not depend on
   * `AesKeyAlgorithm.length`, which an engine may omit for an imported key:
   * lowering `undefined` into a `u32` is unrepresentable.
   */
  #lengthBits;

  /**
   * @param {CryptoKey} key
   * @param {number} lengthBits
   */
  constructor(key, lengthBits) {
    this.#key = key;
    this.#lengthBits = lengthBits;
  }

  /**
   * Encrypt and authenticate the plaintext stream under `nonce` and `aad`,
   * with a `tagSize`-byte authentication tag (`undefined` = the 16-byte
   * default). Returns a `ReadableStream` carrying ciphertext followed by
   * the tag (the `crypto.subtle.encrypt` wire format). Throws
   * `{ tag: 'invalid-nonce', val }` for an empty nonce and
   * `{ tag: 'unsupported', val }` for a tag size outside the GCM set, per
   * the WIT contract. The plaintext stream is drained before any failure
   * is raised, so the guest's writer always completes rather than blocking
   * on an unread stream.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {number | undefined} tagSize
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async seal(nonce, aad, tagSize, plaintext) {
    return withCollectedInputToStream(plaintext, async (message) => {
      if (!this.canSeal()) throw notPermitted("seal");
      requireGcmNonce(nonce);
      const tagLength = gcmTagLengthBits(tagSize);
      let sealed;
      try {
        sealed = await platformCall("AES-GCM seal", () =>
          subtle.encrypt(
            {
              name: "AES-GCM",
              iv: asBufferSource(nonce),
              additionalData: asBufferSource(aad),
              tagLength,
            },
            this.#key,
            message,
          ),
        );
      } catch (err) {
        if (gcmNonceUnservable(nonce)) {
          throw errUnsupported(`a ${nonce.length}-byte nonce is not served by this platform`);
        }
        throw err;
      }
      return new Uint8Array(sealed);
    });
  }

  /**
   * Decrypt and verify the ciphertext‖tag stream under `nonce` and `aad`,
   * with a `tagSize`-byte tag (`undefined` = the 16-byte default).
   * Resolves only after the stream is fully drained and the tag verified
   * (`subtle.decrypt` releases no unverified plaintext); a verification
   * failure throws `{ tag: 'authentication-failed' }`. As with `seal`, the
   * ciphertext stream is drained before any failure is raised.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {number | undefined} tagSize
   * @param {AsyncIterable<unknown> | ReadableStream} ciphertext
   */
  async open(nonce, aad, tagSize, ciphertext) {
    return withCollectedInputToStream(ciphertext, async (message) => {
      if (!this.canOpen()) throw notPermitted("open");
      requireGcmNonce(nonce);
      const tagLength = gcmTagLengthBits(tagSize);
      let opened;
      try {
        opened = await subtle.decrypt(
          {
            name: "AES-GCM",
            iv: asBufferSource(nonce),
            additionalData: asBufferSource(aad),
            tagLength,
          },
          this.#key,
          message,
        );
      } catch (err) {
        if (gcmNonceUnservable(nonce)) {
          throw errUnsupported(`a ${nonce.length}-byte nonce is not served by this platform`);
        }
        throw decryptFailure(err);
      }
      return new Uint8Array(opened);
    });
  }

  /**
   * The algorithm getters: `name` projects the `CryptoKey`, `length` comes
   * from the mint (see `#lengthBits`), and the size getters report the
   * standard/default parameters — every AEAD this host serves is AES-GCM:
   * 12-byte nonces and 16-byte tags by default, with other sizes accepted
   * per call.
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  nonceSize() {
    return 12;
  }

  tagSize() {
    return 16;
  }

  /** Whether `exportKey` may return the material: the `CryptoKey`'s own flag. */
  extractable() {
    return this.#key.extractable;
  }

  /** The usage grants: projections of the `CryptoKey`'s own usage list. */
  canSeal() {
    return this.#key.usages.includes("encrypt");
  }

  canOpen() {
    return this.#key.usages.includes("decrypt");
  }

  canWrap() {
    return this.#key.usages.includes("wrapKey");
  }

  canUnwrap() {
    return this.#key.usages.includes("unwrapKey");
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the key
   * was created with `extractable` true (see `exportRawGated`).
   */
  async exportKey() {
    return exportRawGated(this.#key);
  }

  /**
   * The key as an `oct` JWK (JSON text; see `mac-key.export-key-jwk` for
   * the package-wide contract), behind the same extractability gate as
   * `exportKey`.
   */
  async exportKeyJwk() {
    return exportJwkGated(this.#key);
  }
}

/**
 * The WebCrypto usages granted by a MAC mint policy, throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant.
 * @param {{ sign: boolean, verify: boolean }} policy
 */
function macUsages(policy) {
  return grantedUsages([
    ["sign", policy.sign],
    ["verify", policy.verify],
  ]);
}

/**
 * Import raw key material as an HMAC key over the declared SHA-2 variant. A
 * variant this implementation declines throws `{ tag: 'unsupported', val }`.
 * Any non-empty length is accepted (RFC 2104); empty material throws
 * `{ tag: 'invalid-key', val }`.
 * @param {string} variant
 * @param {Uint8Array} raw
 * @param {MacKeyOptions} options
 */
async function importHmacKey(variant, raw, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash } = sha2Variant(variant);
  if (raw.length === 0) throw errInvalidKey("empty key");
  let key;
  try {
    key = await subtle.importKey(
      "raw",
      asBufferSource(raw),
      { name: "HMAC", hash },
      policy.extractable,
      usages,
    );
  } catch (err) {
    invalidKey(err, "HMAC key");
  }
  return new MacKey(key, raw.length * 8, hash);
}

/**
 * Generate a fresh random HMAC key over the declared SHA-2 variant.
 * `length` is the key length in bits, `undefined` meaning the underlying
 * hash's block size (WebCrypto's `generateKey` default). A zero length
 * throws `{ tag: 'invalid-key' }`; a length that is not a multiple of 8
 * throws `{ tag: 'unsupported', val }` (sub-byte lengths are not served),
 * as does a variant this implementation declines.
 * @param {string} variant
 * @param {number | undefined} length
 * @param {MacKeyOptions} options
 */
async function generateHmacKey(variant, length, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash, blockBytes } = sha2Variant(variant);
  if (length === 0) throw errInvalidKey("HMAC key length must be non-zero");
  if (length !== undefined && length % 8 !== 0) {
    throw errUnsupported(
      `HMAC key length ${length} is not a multiple of 8; sub-byte lengths are not served`,
    );
  }
  const bits = length ?? blockBytes * 8;
  const key = await platformCall(`HMAC-${hash} key generation`, () =>
    subtle.generateKey({ name: "HMAC", hash, length: bits }, policy.extractable, usages),
  );
  return new MacKey(key, bits, hash);
}

/**
 * Import an `oct` JWK as an HMAC key over the declared SHA-2 variant (the
 * `hmac-sha2.import-key-jwk` contract). The platform owns the JWK
 * validation: `kty`, strict base64url `k`, `alg` against the requested
 * hash, and `ext` against the options' extractability all fail there and
 * map to `{ tag: 'invalid-key', val }`.
 * @param {string} variant
 * @param {string} jwk
 * @param {MacKeyOptions} options
 */
async function importHmacKeyJwk(variant, jwk, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash } = sha2Variant(variant);
  const material = jwkMaterial(jwk);
  requireStrictBase64url(material.k);
  let key;
  try {
    key = await subtle.importKey(
      "jwk",
      material,
      { name: "HMAC", hash },
      policy.extractable,
      usages,
    );
  } catch (err) {
    invalidKey(err, "HMAC JWK");
  }
  // Length comes from `k`, not `key.algorithm.length`, which an engine may
  // omit for an imported key (see `MacKey`'s field doc).
  return new MacKey(key, jwkKeyBytes(material.k) * 8, hash);
}

/** The `lann:webcrypto/hmac-sha2` interface (`--map '…#hmacSha2'`). */
export const hmacSha2 = {
  importKey: importHmacKey,
  importKeyJwk: importHmacKeyJwk,
  generateKey: generateHmacKey,
};

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
    return withCollectedInput(data, async (message) => {
      return new Uint8Array(
        await platformCall(`${this.#hash} digest`, () => subtle.digest(this.#hash, message)),
      );
    });
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
/** @type {Readonly<Record<string, number | undefined>>} */
const AES_VARIANT_BYTES = Object.assign(Object.create(null), { aes128: 16, aes256: 32 });

/**
 * The raw key length in bytes declared by `variant`.
 * @param {string} variant
 */
function aesVariantByteLength(variant) {
  return served(AES_VARIANT_BYTES, variant);
}

/**
 * The WebCrypto usages granted by an AEAD mint policy (seal/open map onto
 * encrypt/decrypt; wrap/unwrap onto wrapKey/unwrapKey), throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant. The internal-nonce
 * vocabulary has no wrap usages, so its policies arrive without them.
 * @param {{ seal: boolean, open: boolean, wrap?: boolean, unwrap?: boolean }} policy
 */
function aeadUsages(policy) {
  return grantedUsages([
    ["encrypt", policy.seal],
    ["decrypt", policy.open],
    ["wrapKey", policy.wrap ?? false],
    ["unwrapKey", policy.unwrap ?? false],
  ]);
}

/**
 * The `aes-gcm` / `aes-gcm-internal-nonce` minting pair over `Ctor`: the
 * two interfaces share the whole import/generate contract and differ only
 * in the resource they mint and the options resource they consume
 * (`readPolicy` is the matching options kind's policy reader).
 * @template T
 * @template O
 * @param {new (key: CryptoKey, lengthBits: number) => T} Ctor
 * @param {(options: O) => { seal: boolean, open: boolean, wrap?: boolean, unwrap?: boolean, extractable: boolean }} readPolicy
 */
function aesMinting(Ctor, readPolicy) {
  return {
    /**
     * Import raw key material as the declared AES variant. A variant this
     * implementation declines throws `{ tag: 'unsupported', val }`;
     * material whose length disagrees with `variant` throws
     * `{ tag: 'invalid-key', val }`.
     * @param {string} variant
     * @param {Uint8Array} raw
     * @param {O} options
     */
    async importKey(variant, raw, options) {
      const policy = readPolicy(options);
      const usages = aeadUsages(policy);
      const expected = aesVariantByteLength(variant);
      if (raw.length !== expected) {
        throw errInvalidKey(`${variant} requires ${expected} key bytes, got ${raw.length}`);
      }
      let key;
      try {
        key = await subtle.importKey(
          "raw",
          asBufferSource(raw),
          { name: "AES-GCM" },
          policy.extractable,
          usages,
        );
      } catch (err) {
        invalidKey(err, `${variant} key`);
      }
      return new Ctor(key, expected * 8);
    },

    /**
     * Generate a fresh random AES key of the declared variant. A variant
     * this implementation declines throws `{ tag: 'unsupported', val }`.
     * @param {string} variant
     * @param {O} options
     */
    async generateKey(variant, options) {
      const policy = readPolicy(options);
      const usages = aeadUsages(policy);
      const length = aesVariantByteLength(variant) * 8;
      const key = await platformCall(`${variant} key generation`, () =>
        subtle.generateKey({ name: "AES-GCM", length }, policy.extractable, usages),
      );
      return new Ctor(key, length);
    },
  };
}

/**
 * Import an `oct` JWK as an AES-GCM key of the declared variant (the
 * `aes-gcm.import-key-jwk` contract). The platform validates the JWK's
 * internal consistency (`kty`, strict base64url `k`, `alg` against `k`'s
 * length, `ext` against the options' extractability); the variant check is
 * against the imported key's platform-computed length, since the platform
 * cannot know the declared variant.
 * @param {string} variant
 * @param {string} jwk
 * @param {AeadKeyOptions} options
 */
async function importAesKeyJwk(variant, jwk, options) {
  const policy = aeadPolicy(options);
  const usages = aeadUsages(policy);
  const lengthBits = aesVariantByteLength(variant) * 8;
  const material = jwkMaterial(jwk);
  requireStrictBase64url(material.k);
  let key;
  try {
    key = await subtle.importKey(
      "jwk",
      material,
      { name: "AES-GCM" },
      policy.extractable,
      usages,
    );
  } catch (err) {
    invalidKey(err, `${variant} JWK`);
  }
  // The variant check derives from `k` (exact once the platform accepted
  // the encoding), not `key.algorithm.length`, which an engine may omit
  // for an imported key (see `MacKey`'s field doc).
  const gotBits = jwkKeyBytes(material.k) * 8;
  if (gotBits !== lengthBits) {
    throw errInvalidKey(`JWK carries a ${gotBits}-bit key; ${variant} requires ${lengthBits}`);
  }
  return new AeadKey(key, lengthBits);
}

/** The `lann:webcrypto/aes-gcm` interface (`--map '…#aesGcm'`). */
export const aesGcm = {
  ...aesMinting(AeadKey, aeadPolicy),
  importKeyJwk: importAesKeyJwk,
};

/**
 * Throw `{ tag: 'unsupported', val }` for a ChaCha construction: browser
 * WebCrypto implements no ChaCha20-Poly1305 (the WICG proposal is
 * unimplemented), so this host declines these interfaces whole and a
 * composition needing them must supply another provider (the in-guest
 * provider serves both constructions).
 *
 * Annotated `never` for the same reason as `invalidKey`: the minting stubs
 * below delegate to it in place of returning a key, so a version that fell
 * through would resolve them with `undefined`.
 * @param {string} name
 * @returns {never}
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
 * The `internal-nonce-key-options` resource. See `MacKeyOptions` for the
 * state and same-provider mechanics; the vocabulary is seal/open only
 * (this kind has no WebCrypto usage vocabulary beyond its own operations).
 */
/** @type {WeakMap<InternalNonceKeyOptions, { seal: boolean, open: boolean, extractable: boolean }>} */
const internalNoncePolicies = new WeakMap();

/**
 * The policy accumulated by `options`, read by the setters and at mint.
 * @param {InternalNonceKeyOptions} options
 */
function internalNoncePolicy(options) {
  const policy = internalNoncePolicies.get(options);
  if (policy === undefined) {
    throw errOther("internal-nonce-key-options minted by another provider");
  }
  return policy;
}

export class InternalNonceKeyOptions {
  constructor() {
    internalNoncePolicies.set(this, { seal: false, open: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canSeal(allowed) {
    internalNoncePolicy(this).seal = allowed;
  }

  /** @param {boolean} allowed */
  canOpen(allowed) {
    internalNoncePolicy(this).open = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    internalNoncePolicy(this).extractable = allowed;
  }
}

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
  /** The key length in bits, fixed at mint. See `AeadKey`. */
  #lengthBits;
  #sealed = 0n;

  /** The 12-byte AES-GCM IV length. */
  static #IV_BYTES = 12;

  /** The WIT nonce budget for 12-byte nonces: 2^32 seal invocations. */
  static #NONCE_BUDGET = 1n << 32n;

  /**
   * @param {CryptoKey} key
   * @param {number} lengthBits
   */
  constructor(key, lengthBits) {
    this.#key = key;
    this.#lengthBits = lengthBits;
  }

  /**
   * Encrypt and authenticate the plaintext stream under a fresh random IV
   * with `aad`, returning `iv ‖ ciphertext ‖ tag`. The plaintext stream is
   * drained before any failure is raised, per the WIT drain rule.
   * @param {Uint8Array} aad
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async seal(aad, plaintext) {
    return withCollectedInputToStream(plaintext, async (message) => {
      if (!this.canSeal()) throw notPermitted("seal");
      if (this.#sealed >= InternalNonceKey.#NONCE_BUDGET) {
        throw errKeyExhausted();
      }
      this.#sealed += 1n;
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(InternalNonceKey.#IV_BYTES));
      const body = new Uint8Array(
        await platformCall("AES-GCM seal", () =>
          subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: asBufferSource(aad) },
            this.#key,
            message,
          ),
        ),
      );
      const sealed = new Uint8Array(iv.length + body.length);
      sealed.set(iv, 0);
      sealed.set(body, iv.length);
      return sealed;
    });
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
    return withCollectedInputToStream(sealed, async (message) => {
      if (!this.canOpen()) throw notPermitted("open");
      if (message.length < InternalNonceKey.#IV_BYTES) {
        throw errAuthenticationFailed();
      }
      const iv = message.subarray(0, InternalNonceKey.#IV_BYTES);
      const body = message.subarray(InternalNonceKey.#IV_BYTES);
      let opened;
      try {
        opened = await subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: asBufferSource(aad) },
          this.#key,
          body,
        );
      } catch (err) {
        throw decryptFailure(err);
      }
      return new Uint8Array(opened);
    });
  }

  /**
   * The algorithm getters: `name` projects the `CryptoKey`, `length` comes
   * from the mint (see `#lengthBits`).
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  /**
   * The remaining seal budget (the WIT 2^32 bound for 12-byte nonces minus
   * seals so far), as a rotation-scheduling hint.
   */
  sealsRemaining() {
    const remaining = InternalNonceKey.#NONCE_BUDGET - this.#sealed;
    return remaining > 0n ? remaining : 0n;
  }

  /** Whether `exportKey` may return the material: the `CryptoKey`'s own flag. */
  extractable() {
    return this.#key.extractable;
  }

  /** The usage grants: projections of the `CryptoKey`'s own usage list. */
  canSeal() {
    return this.#key.usages.includes("encrypt");
  }

  canOpen() {
    return this.#key.usages.includes("decrypt");
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the
   * key was created with `extractable` true (see `exportRawGated`).
   */
  async exportKey() {
    return exportRawGated(this.#key);
  }
}

/** The `lann:webcrypto/aes-gcm-internal-nonce` interface (`--map '…#aesGcmInternalNonce'`). */
export const aesGcmInternalNonce = aesMinting(InternalNonceKey, internalNoncePolicy);

/**
 * Throw `{ tag: 'invalid-nonce', val }` for an empty nonce. AES-GCM accepts
 * any non-empty length per the `aes-gcm` minting contract; how much of that
 * contract this host serves is the platform's window (see
 * `gcmNonceUnservable`).
 * @param {Uint8Array} nonce
 */
function requireGcmNonce(nonce) {
  if (nonce.length === 0) {
    throw errInvalidNonce("AES-GCM requires a non-empty nonce");
  }
}

/**
 * Reinterpret a platform failure as `{ tag: 'unsupported' }` when the nonce
 * sits outside the 12–128-byte window every known platform serves — the
 * `aes-gcm-any-iv` conformance feature. The check runs only on *failures*:
 * a platform that serves the full contract (nothing reaches this), and one
 * with a window (Node's WebCrypto) declines rather than misreporting. A
 * platform failing an outside-window call for some unrelated operational
 * reason is folded in — the nonce is overwhelmingly the cause.
 * @param {Uint8Array} nonce
 */
function gcmNonceUnservable(nonce) {
  return nonce.length < 12 || nonce.length > 128;
}

/** The GCM tag sizes in bytes (the registry's 32–128-bit set). */
const GCM_TAG_SIZES = [4, 8, 12, 13, 14, 15, 16];

/**
 * Resolve a per-call tag size to bits for `AesGcmParams.tagLength`,
 * defaulting `undefined` to the 16-byte default and throwing
 * `{ tag: 'unsupported', val }` outside the set, per the WIT contract.
 * @param {number | undefined} tagSize
 */
function gcmTagLengthBits(tagSize) {
  const size = tagSize ?? 16;
  if (!GCM_TAG_SIZES.includes(size)) {
    throw errUnsupported(
      `AES-GCM does not define ${size}-byte tags; the set is 4, 8, 12, 13, 14, 15, or 16`,
    );
  }
  return size * 8;
}

/**
 * Input-buffering limits. Every stream-taking operation buffers its whole
 * input (the single-message contract), and concurrent calls multiply — so
 * admission bounds aggregate retention: each operation reserves its
 * per-call cap from a shared pool before collecting, waiting FIFO when the
 * pool is full, and releases when its buffers are gone (including the
 * returned output stream). Inputs beyond the per-call cap are drained and
 * discarded (the WIT drain rule holds) and the operation throws a
 * recoverable `{ tag: 'other' }`.
 *
 * Two divergences from the Wasmtime host, both structural rather than
 * oversights:
 *
 * - **The defaults are constants here, not derived.** The Wasmtime host
 *   defaults its pool to the store's hostcall fuel, which has no analogue in
 *   a browser. 128 MiB with a per-call cap of a quarter is the same *shape*
 *   at a fixed figure, not the same number.
 * - **The pool is module-global, not per-instance.** `jco --map` binds an
 *   interface to a JS module, and a module has one instance per realm; no
 *   instance identity reaches these functions, so there is nothing to key a
 *   pool on. Two components transpiled against this file in one realm share
 *   one pool and one `configure`. The Wasmtime host scopes its pool to the
 *   context and does not have this property.
 *
 * Neither host can hold a call before it starts, which is what the component
 * model provides to a component callee (`backpressure.{inc,dec}`) and does
 * not expose to a host import: a host import's arguments are lifted by the
 * canonical ABI before the host function runs. Admission here therefore
 * happens *inside* the call, so a queued operation has already had its
 * `list<u8>` parameters lifted — they are retained but not counted.
 */
const DEFAULT_TOTAL_BUFFER_LIMIT = 128 * 1024 * 1024;

/** @type {{ perCall: number | undefined, total: number | undefined }} */
const bufferLimits = { perCall: undefined, total: undefined };

/**
 * Configure the input-buffering limits (bytes).
 *
 * A partial update: an absent member leaves that limit as it was. Passing an
 * explicit `undefined` restores that limit's default, which is why the
 * members are tested for presence rather than for being defined.
 *
 * Raising the pool admits whatever now fits: waiters are judged against the
 * ceiling in force, so without this the new capacity would go unused until
 * some unrelated operation happened to release.
 * @param {{ perCallBufferLimit?: number, totalBufferLimit?: number }} options
 */
export function configure(options = {}) {
  if ("perCallBufferLimit" in options) bufferLimits.perCall = options.perCallBufferLimit;
  if ("totalBufferLimit" in options) bufferLimits.total = options.totalBufferLimit;
  admitFromFront();
}

/** The effective `(perCall, total)` limits, clamped like the wasmtime host. */
function effectiveBufferLimits() {
  const total = Math.max(1, bufferLimits.total ?? DEFAULT_TOTAL_BUFFER_LIMIT);
  const perCall = Math.max(1, Math.min(bufferLimits.perCall ?? Math.floor(total / 4), total));
  return { perCall, total };
}

let reservedBytes = 0;
/**
 * Waiters, in arrival order. An entry carries only what it reserves: the
 * ceiling it is judged against is read at admission time, so a `configure`
 * between queueing and admission governs the whole queue rather than
 * splitting it into entries judged against different totals.
 * @type {{ amount: number, resolve: () => void }[]}
 */
const admitQueue = [];

/** Admit queued reservations from the front while they fit (FIFO). */
function admitFromFront() {
  for (;;) {
    const head = admitQueue[0];
    if (head === undefined) return;
    const { total } = effectiveBufferLimits();
    if (reservedBytes + head.amount > total) return;
    admitQueue.shift();
    reservedBytes += head.amount;
    head.resolve();
  }
}

/**
 * Reserve one operation's buffering capacity, waiting FIFO for the pool.
 * The returned reservation's `release` is idempotent.
 * @returns {Promise<Reservation>}
 */
async function admitInput() {
  const { perCall, total } = effectiveBufferLimits();
  const amount = Math.min(perCall, total);
  await /** @type {Promise<void>} */ (
    new Promise((resolve) => {
      admitQueue.push({ amount, resolve });
      admitFromFront();
    })
  );
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
 * A single-chunk byte `ReadableStream` over `bytes`, releasing `reservation`
 * (when given) once the caller has taken the bytes or dropped the stream.
 *
 * The reservation is held until then rather than released when the operation
 * returns: an unconsumed output is still retained here, and releasing early
 * would leave it invisible to the pool — the bound would cover the inputs and
 * silently not the outputs.
 *
 * `pull` is only called when the consumer asks for a chunk, so the queuing
 * strategy matters: the default would fill a chunk eagerly at construction
 * and release before the caller had read anything. A zero high-water mark
 * keeps the stream from producing until it is read.
 *
 * The package's making-progress rule is what makes this safe to hold: a
 * caller must drain each returned stream as it becomes available, so the
 * capacity an operation holds is always one its own consumer can free.
 * @param {Uint8Array} bytes
 * @param {Reservation} [reservation]
 */
function bytesToStream(bytes, reservation = undefined) {
  return new ReadableStream(
    {
      pull(controller) {
        if (bytes.length) controller.enqueue(bytes);
        controller.close();
        reservation?.release();
      },
      cancel() {
        reservation?.release();
      },
    },
    { highWaterMark: 0 },
  );
}

/**
 * Run `op` over the collected bytes of `stream` under one admission
 * reservation, releasing it when `op` settles — the shape of every
 * buffer-then-compute operation. The stream is collected *before* `op`
 * runs, so an operation's own validation can never precede the drain the
 * WIT requires.
 * @template T
 * @param {ByteStream} stream
 * @param {(message: Uint8Array<ArrayBuffer>) => Promise<T>} op
 * @returns {Promise<T>}
 */
async function withCollectedInput(stream, op) {
  const reservation = await admitInput();
  try {
    const message = await collectByteStream(stream, reservation.cap);
    return await op(message);
  } finally {
    reservation.release();
  }
}

/**
 * Like `withCollectedInput`, for the seal/open shape: `op`'s output bytes
 * are handed back as a stream whose producer carries the reservation
 * (releasing when the bytes are handed off), so pool capacity tracks the
 * bytes the host actually retains.
 *
 * The return is deliberately `ReadableStream<any>`-shaped: the generated
 * interface types spell `stream<u8>` as `ReadableStream<number>`, while
 * jco actually ingests `Uint8Array` chunks (batching is the runtime's).
 * @param {ByteStream} stream
 * @param {(message: Uint8Array<ArrayBuffer>) => Promise<Uint8Array>} op
 * @returns {Promise<ReadableStream>}
 */
async function withCollectedInputToStream(stream, op) {
  const reservation = await admitInput();
  let out;
  try {
    const message = await collectByteStream(stream, reservation.cap);
    out = await op(message);
  } catch (err) {
    reservation.release();
    throw err;
  }
  return bytesToStream(out, reservation);
}

/**
 * The shared raw `export-key` gate: throw `{ tag: 'not-extractable' }`
 * unless `key` was minted extractable (checked on the `CryptoKey` itself
 * rather than relying on the `DOMException` from `exportKey`), then export
 * the raw material.
 * @param {CryptoKey} key
 */
async function exportRawGated(key) {
  if (!key.extractable) throw errNotExtractable();
  return new Uint8Array(
    await platformCall("raw key export", () => subtle.exportKey("raw", key)),
  );
}

/**
 * The key as an `oct` JWK, per the WIT contract: exactly the
 * material-bearing members (`kty`, `k`, `alg`) — the platform's `key_ops`/
 * `ext` are the consumer's to stamp, so they are dropped here.
 * @param {CryptoKey} key
 */
async function exportJwkGated(key) {
  if (!key.extractable) throw errNotExtractable();
  const jwk = await platformCall("jwk key export", () => subtle.exportKey("jwk", key));
  return JSON.stringify({ kty: jwk.kty, k: jwk.k, alg: jwk.alg });
}

/**
 * Parse JWK JSON text and strip the members the WIT contract ignores.
 * `use`/`key_ops` are consumer policy — they must not reach the platform,
 * whose import would otherwise enforce them against the usages this host
 * passes. `ext` stays: the platform validates it against `extractable`,
 * which the WIT does model. Malformed JSON throws
 * `{ tag: 'invalid-key', val }`.
 * @param {string} jwkText
 * @returns {Record<string, unknown>}
 */
/**
 * The decoded byte length of a valid unpadded-base64url string — exact:
 * `floor(chars * 3 / 4)`. Only meaningful after the platform accepted the
 * JWK (which validates the encoding).
 * @param {unknown} k
 */
function jwkKeyBytes(k) {
  return typeof k === "string" ? Math.floor((k.length * 3) / 4) : 0;
}

const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Enforce the contract's strict unpadded base64url on a JWK `k` before the
 * platform sees it: some platforms are lenient here (Node accepts padding),
 * and the WIT contract pins strictness so implementations cannot diverge
 * on adversarial input. Non-string `k` passes through — the platform
 * rejects it with the right error shape.
 * @param {unknown} k
 */
function requireStrictBase64url(k) {
  if (typeof k !== "string") return;
  if (k.length % 4 === 1) {
    throw errInvalidKey("JWK `k` has an impossible base64url length");
  }
  for (const ch of k) {
    if (!B64URL_ALPHABET.includes(ch)) {
      throw errInvalidKey("JWK `k` is not unpadded base64url");
    }
  }
  const rem = k.length % 4;
  if (rem !== 0) {
    const last = B64URL_ALPHABET.indexOf(k[k.length - 1]);
    const mask = rem === 2 ? 0b1111 : 0b11;
    if ((last & mask) !== 0) {
      throw errInvalidKey("JWK `k` has non-zero trailing bits");
    }
  }
}

/**
 * @param {string} jwkText
 * @returns {Record<string, unknown>}
 */
function jwkMaterial(jwkText) {
  let jwk;
  try {
    jwk = JSON.parse(jwkText);
  } catch (err) {
    throw errInvalidKey(`JWK is not valid JSON: ${err}`);
  }
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
    throw errInvalidKey("JWK must be a JSON object");
  }
  const { use, key_ops, ...material } = /** @type {Record<string, unknown>} */ (jwk);
  void use;
  void key_ops;
  return material;
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
 * @param {unknown} value
 * @returns {Uint8Array}
 */
function toByteChunk(value) {
  if (typeof value === "number") return Uint8Array.of(value);
  if (value instanceof Uint8Array) return value.slice();
  return Uint8Array.from(/** @type {ArrayLike<number>} */ (value));
}

/**
 * Collect every byte of a WIT byte stream into one `Uint8Array`, retaining
 * at most `cap` bytes: past the cap the stream is still drained (the WIT
 * drain rule) but discarded, and a recoverable `{ tag: 'other' }` is thrown
 * once the stream ends.
 * @param {ByteStream} stream
 * @param {number} [cap]
 */
async function collectByteStream(stream, cap = Infinity) {
  /** @type {Uint8Array[]} */
  let chunks = [];
  let total = 0;
  let overflowed = false;
  /** @param {unknown} value */
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
  } else if (typeof (/** @type {JcoStream} */ (stream).read) === "function") {
    // jco's own Stream object: read in batches rather than per element.
    for (;;) {
      const { value, done } = await /** @type {JcoStream} */ (stream).read({ count: 65536 });
      push(value);
      if (done) break;
    }
  } else {
    for await (const value of /** @type {AsyncIterable<unknown>} */ (stream)) {
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

/**
 * Concatenate `chunks` (totalling `total` bytes) into one `Uint8Array`.
 * @param {readonly Uint8Array[]} chunks
 * @param {number} total
 */
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
/** @type {Readonly<Record<string, EcdsaAlgorithm | undefined>>} */
const ECDSA_VARIANTS = Object.assign(Object.create(null), {
  "p256-sha256": {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
    publicLength: 65,
    scalarLength: 32,
    signatureLength: 64,
  },
  "p384-sha384": {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-384",
    publicLength: 97,
    scalarLength: 48,
    signatureLength: 96,
  },
});

/**
 * The Ed25519 algorithm record, in the same shape as an `ECDSA_VARIANTS`
 * entry: no curve, no mint-bound hash (RFC 8032 fixes SHA-512 internally),
 * a 32-byte public key and a 64-byte `R ‖ S` signature.
 * @type {SignatureAlgorithm}
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
 * The served `ecdsa-variant` entry for `variant`.
 * @param {string} variant
 * @returns {EcdsaAlgorithm}
 */
function ecdsaVariant(variant) {
  return served(ECDSA_VARIANTS, variant);
}

/**
 * The WebCrypto sign/verify algorithm parameter for a key's mint binding.
 * @param {SignatureAlgorithm} algorithm
 * @returns {AlgorithmIdentifier | EcdsaParams}
 */
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
    await withCollectedInput(data, async (message) => {
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
        subtle.verify(params, this.#key, asBufferSource(sig), message),
      );
      if (!ok) {
        throw errAuthenticationFailed();
      }
    });
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
   * SEC1 point for ECDSA).
   *
   * There is no extractability gate on this resource — WebCrypto sets
   * `[[extractable]]` true on every generated public key, and the importers
   * below pass `true` — so `not-extractable` never occurs. The export can
   * still fail: each algorithm's export operation begins by throwing
   * `OperationError` when the key material behind the `CryptoKey` cannot be
   * accessed, which `platformCall` renders as `other`.
   */
  async exportKey() {
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }
}

/**
 * The `signing-key-options` resource. See `MacKeyOptions` for the state and
 * same-provider mechanics; the vocabulary is degenerate (`sign` is the sole
 * usage, and must be granted for a mint to succeed).
 */
/** @type {WeakMap<SigningKeyOptions, { sign: boolean, extractable: boolean }>} */
const signingPolicies = new WeakMap();

/**
 * The policy accumulated by `options`, read by the setters and at mint.
 * @param {SigningKeyOptions} options
 */
function signingPolicy(options) {
  const policy = signingPolicies.get(options);
  if (policy === undefined) {
    throw errOther("signing-key-options minted by another provider");
  }
  return policy;
}

export class SigningKeyOptions {
  constructor() {
    signingPolicies.set(this, { sign: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canSign(allowed) {
    signingPolicy(this).sign = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    signingPolicy(this).extractable = allowed;
  }
}

/**
 * The mint-time check on a signing policy: `sign` is the sole usage, so it
 * must be granted (the options contract's at-least-one-usage rule).
 * @param {{ sign: boolean, extractable: boolean }} policy
 */
function requireSigningGrant(policy) {
  grantedUsages([["sign", policy.sign]]);
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
   * Throws `{ tag: 'not-permitted' }` on a key without the `sign` usage.
   * @param {AsyncIterable<unknown> | ReadableStream} data
   */
  async sign(data) {
    return withCollectedInput(data, async (message) => {
      if (!this.canSign()) throw notPermitted("sign");
      const params = signParams(this.#algorithm);
      return new Uint8Array(
        await platformCall(`${this.#algorithm.name} sign`, () =>
          subtle.sign(params, this.#privateKey, message),
        ),
      );
    });
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

  /** The `sign` grant: a projection of the `CryptoKey`'s own usage list. */
  canSign() {
    return this.#privateKey.usages.includes("sign");
  }
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
].map(unhexFixed);

/**
 * Decode an even-length hex literal from this file. A malformed literal is
 * a source defect, not input: it must not silently yield a short array that
 * a byte compare would then never match.
 * @param {string} hex
 */
function unhexFixed(hex) {
  const pairs = hex.match(/../g);
  if (pairs === null || pairs.length * 2 !== hex.length) {
    throw new Error(`malformed hex literal: ${hex}`);
  }
  return Uint8Array.from(pairs, (byte) => parseInt(byte, 16));
}

/**
 * Whether little-endian `a` < `b` (equal-length).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
function ltLittleEndian(a, b) {
  for (let i = a.length - 1; i >= 0; i--) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

/**
 * Whether `a` and `b` are byte-equal (public data; early exit is fine).
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 */
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

/**
 * Rethrow a WebCrypto import failure as `{ tag: 'invalid-key', val }`.
 *
 * Annotated `never` deliberately: every call site relies on this throwing
 * and constructs a resource immediately afterwards, so a version that fell
 * through would mint a key over an `undefined` `CryptoKey`.
 * @param {unknown} err
 * @param {string} what
 * @returns {never}
 */
function invalidKey(err, what) {
  throw errInvalidKey(`invalid ${what}: ${asPlatformError(err).detail}`);
}

/**
 * Import a 32-byte raw Ed25519 public key. Non-canonical and small-order
 * encodings are rejected here (the WIT strict criterion; the platform's
 * import performs little validation of its own).
 * @param {Uint8Array} raw
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
    key = await subtle.importKey("raw", asBufferSource(raw), "Ed25519", true, ["verify"]);
  } catch (err) {
    invalidKey(err, "Ed25519 public key");
  }
  return new VerifyingKey(key, ED25519_ALGORITHM);
}

/** The `lann:webcrypto/ed25519-verify` interface (`--map '…#ed25519Verify'`). */
export const ed25519Verify = { importVerifyingKey: importEd25519VerifyingKey };

/**
 * Generate a fresh Ed25519 signing key, returning `[signing, verifying]`.
 * @param {SigningKeyOptions} options
 * @returns {Promise<[SigningKey, VerifyingKey]>}
 */
async function generateEd25519Key(options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const pair = /** @type {CryptoKeyPair} */ (
    await platformCall("Ed25519 key generation", () =>
      subtle.generateKey("Ed25519", policy.extractable, ["sign", "verify"]),
    )
  );
  return [
    new SigningKey(pair.privateKey, ED25519_ALGORITHM),
    new VerifyingKey(pair.publicKey, ED25519_ALGORITHM),
  ];
}

/** The `lann:webcrypto/ed25519-sign` interface (`--map '…#ed25519Sign'`). */
export const ed25519Sign = { generateKey: generateEd25519Key };

/**
 * Import an uncompressed-SEC1 ECDSA public key of the declared variant.
 * @param {string} variant
 * @param {Uint8Array} raw
 */
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
      asBufferSource(raw),
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

/**
 * Generate a fresh ECDSA signing key of the declared variant, returning
 * `[signing, verifying]`.
 * @param {string} variant
 * @param {SigningKeyOptions} options
 * @returns {Promise<[SigningKey, VerifyingKey]>}
 */
async function generateEcdsaKey(variant, options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = ecdsaVariant(variant);
  const pair = await platformCall(`${variant} key generation`, () =>
    subtle.generateKey({ name: "ECDSA", namedCurve: entry.namedCurve }, policy.extractable, [
      "sign",
      "verify",
    ]),
  );
  return [new SigningKey(pair.privateKey, entry), new VerifyingKey(pair.publicKey, entry)];
}

/** The `lann:webcrypto/ecdsa-sign` interface (`--map '…#ecdsaSign'`). */
export const ecdsaSign = { generateKey: generateEcdsaKey };

// @ts-check
// Host implementation of the `polymorph:webcrypto` imports for jco-transpiled
// components. The interfaces served are the ones `wit/world.wit` names;
// `interface-check.js` asserts this file against them.
//
// This is the "browser-first" host: it is written against the standard Web
// Crypto API only — `globalThis.crypto.subtle` and
// `globalThis.crypto.getRandomValues` — so the same file runs unchanged in a
// browser. No `node:crypto` imports and no Node-only APIs are used; Node
// provides the same globals natively.
//
// `jco --map` wires this module in as the component's imports with one
// wildcard — `--map 'polymorph:webcrypto/*@0.1.0=./webcrypto.js#*'` — so the
// export convention is fixed: every interface is served by the named export
// spelling its name in camelCase (`hmacSha2`, `aesGcm`, …), and the
// resource-bearing interfaces export objects holding their resource classes.
// Adding an interface to the host means adding its camelCased export here;
// no transpile flags change.
//
// ## jco conventions this host relies on
//
// Three aspects of the jco runtime's host-facing surface are conventions
// rather than documented API, so they are isolated and version-anchored
// here. Validated against jco-transpile 0.5.2 (the version pinned by this
// repo's npm consumers); revalidate when bumping it.
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
// - **Async detection**: which imports and exports are async is read from
//   the component itself (the WIT's `async func` markers and the async
//   canonical options wit-bindgen lowers them with), so the transpile
//   invocations pass `--async-mode jspi` — the generated code requires
//   JSPI — but no per-function `--async-imports`/`--async-exports`
//   enumerations. Verified against js-component-bindgen's `is_async_fn`
//   (`canon_opts.async_ || func.kind.is_async()`); the per-function flags
//   feed only the legacy `manuallyAsync` path for sync-ABI functions
//   forced async, which nothing here uses.

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
 * The algorithm record bound to a signature key at mint. One shape for all
 * families: Ed25519 has no curve and no mint-bound hash (RFC 8032 fixes
 * SHA-512 internally); the RSA families have no curve and no raw public
 * form (so no `publicLength`/`scalarLength`), and carry the imported key's
 * modulus length as `length` (bits) plus, for RSA-PSS, the mint-bound
 * `saltLength` (bytes).
 * @typedef {object} SignatureAlgorithm
 * @property {string} name
 * @property {string | undefined} namedCurve
 * @property {string | undefined} hash
 * @property {number | undefined} [length]
 * @property {number | undefined} [publicLength]
 * @property {number | undefined} [scalarLength]
 * @property {number} signatureLength
 * @property {number | undefined} [saltLength]
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
 * Lift a `subtle.decrypt` (or `subtle.unwrapKey`) rejection. A failed tag
 * check surfaces as `OperationError`, which is `authentication-failed` and
 * deliberately carries no detail. Anything else — `DataError`,
 * `InvalidAccessError`, `QuotaExceededError` — is an operational condition:
 * reporting those as `authentication-failed` would render a local fault as
 * an attack signal and hide real bugs behind an expected-looking error.
 * @param {unknown} err
 * @param {string} [operation]
 */
function decryptFailure(err, operation = "open") {
  const failure = asPlatformError(err);
  if (failure.name === "OperationError") return errAuthenticationFailed();
  return errOther(`${operation}: ${failure.detail}`);
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
 * The reader for a resource class's module-private `WeakMap` state (the
 * options classes' accumulated policies, read by the setters and at mint;
 * the parameter-position resources' platform keys): the map lookup doubles
 * as the same-provider check the WIT requires (a foreign object is not a
 * key).
 * @template {object} K
 * @template V
 * @param {WeakMap<K, V>} store
 * @param {string} what
 * @returns {(resource: K) => V}
 */
function stateReader(store, what) {
  return (resource) => {
    const state = store.get(resource);
    if (state === undefined) {
      throw errOther(`${what} minted by another provider`);
    }
    return state;
  };
}

/**
 * The platform `CryptoKey` behind every key resource built on
 * `keyResourceTail`. It lives in a module-private `WeakMap` rather than a
 * base-class private field because a `#`-private field is invisible to
 * subclasses: the tail methods and the key classes' own operations read
 * the same key through `platformKeyOf`.
 */
/** @type {WeakMap<object, CryptoKey>} */
const platformKeys = new WeakMap();

const platformKeyOf = stateReader(platformKeys, "key");

/**
 * One usage projection: whether the resource's platform key carries
 * `usage`. The key was imported or generated with exactly the usages its
 * mint options granted, so the `CryptoKey`'s own usage list is the
 * authority.
 * @param {KeyUsage} usage
 */
function usageProjection(usage) {
  /** @this {object} */
  function projection() {
    return platformKeyOf(this).usages.includes(usage);
  }
  return projection;
}

/**
 * The common tail of the key resource classes: a constructor storing the
 * platform key in `platformKeys`, `extractable()` — the `CryptoKey`'s own
 * flag, the gate `export-key-*` checks — and one usage projection per
 * `projections` entry, mapping the WIT getter name onto the WebCrypto
 * usage it reports (`canSeal` → `"encrypt"`, …).
 * @template {Record<string, KeyUsage>} P
 * @param {P} projections
 * @returns {new (key: CryptoKey) => { extractable(): boolean } & Record<keyof P, () => boolean>}
 */
function keyResourceTail(projections) {
  class Tail {
    /** @param {CryptoKey} key */
    constructor(key) {
      platformKeys.set(this, key);
    }

    extractable() {
      return platformKeyOf(this).extractable;
    }
  }
  for (const [method, usage] of Object.entries(projections)) {
    Object.defineProperty(Tail.prototype, method, {
      value: usageProjection(usage),
      writable: true,
      configurable: true,
    });
  }
  return /** @type {new (key: CryptoKey) => { extractable(): boolean } & Record<keyof P, () => boolean>} */ (
    /** @type {unknown} */ (Tail)
  );
}

/**
 * `keyResourceTail` plus the symmetric key classes' export pair:
 * `exportKeyRaw` and `exportKeyJwk` behind the shared extractability gates
 * (`exportRawGated`/`exportJwkGated`; the JWK is the WIT's `oct` form).
 * @template {Record<string, KeyUsage>} P
 * @param {P} projections
 * @returns {new (key: CryptoKey) => { extractable(): boolean, exportKeyRaw(): Promise<Uint8Array>, exportKeyJwk(): Promise<string> } & Record<keyof P, () => boolean>}
 */
function symmetricKeyTail(projections) {
  // The base is narrowed to its statically known members: a generic
  // `Record<keyof P, …>` cannot appear in an `extends` clause. The
  // projections re-enter through the return type.
  /** @type {new (key: CryptoKey) => { extractable(): boolean }} */
  const Base = keyResourceTail(projections);
  class Tail extends Base {
    async exportKeyRaw() {
      return exportRawGated(platformKeyOf(this));
    }

    async exportKeyJwk() {
      return exportJwkGated(platformKeyOf(this));
    }
  }
  return /** @type {new (key: CryptoKey) => { extractable(): boolean, exportKeyRaw(): Promise<Uint8Array>, exportKeyJwk(): Promise<string> } & Record<keyof P, () => boolean>} */ (
    /** @type {unknown} */ (Tail)
  );
}

/**
 * The `mac-key-options` resource: mint-time policy under construction. Per
 * the package-wide options contract the constructor grants nothing; the
 * setters are opt-in, and a mint consumes the accumulated policy through
 * `macPolicy`. The state lives in a module-private `WeakMap` rather than
 * private fields, so the class stays structurally compatible with the
 * generated interface types; its `stateReader` supplies the same-provider
 * check.
 */
/** @type {WeakMap<MacKeyOptions, { sign: boolean, verify: boolean, extractable: boolean }>} */
const macPolicies = new WeakMap();

const macPolicy = stateReader(macPolicies, "mac-key-options");

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
export class MacKey extends symmetricKeyTail({ canSign: "sign", canVerify: "verify" }) {
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
    super(key);
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
        await platformCall("HMAC sign", () => subtle.sign("HMAC", platformKeyOf(this), message)),
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
        subtle.verify("HMAC", platformKeyOf(this), asBufferSource(tag), message),
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
    return platformKeyOf(this).algorithm.name;
  }

  algorithmHash() {
    return this.#hashName;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  /**
   * This key's raw material as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyRaw`.
   */
  async toWrapInputRaw() {
    return new WrapInput(MINT, "raw", await exportRawGated(platformKeyOf(this)));
  }

  /**
   * The JWK serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputJwk() {
    const jwk = await exportJwkGated(platformKeyOf(this));
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(jwk));
  }
}

/**
 * The `aead-key-options` resource. See `MacKeyOptions` for the state and
 * same-provider mechanics; the wrap/unwrap grants gate `aead-key.wrap` and
 * `unwrap` (see `aeadKeyGrants` for how the grants reach the platform key).
 */
/** @type {WeakMap<AeadKeyOptions, { seal: boolean, open: boolean, wrap: boolean, unwrap: boolean, extractable: boolean }>} */
const aeadPolicies = new WeakMap();

const aeadPolicy = stateReader(aeadPolicies, "aead-key-options");

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
 * The usage grants recorded at mint for each `aead-key`. The platform
 * usages cannot carry the WIT grants one-to-one: `wrap` runs
 * `subtle.encrypt` and `unwrap` runs `subtle.decrypt` (WebCrypto's
 * `wrapKey`-with-an-encryption-algorithm model), so the platform key is
 * minted with `encrypt` if (seal or wrap) and `decrypt` if (open or
 * unwrap), and the WIT grants are enforced host-side against this record
 * (the `AGREEMENT_PLATFORM_USAGES` precedent).
 * @type {WeakMap<AeadKey, { seal: boolean, open: boolean, wrap: boolean, unwrap: boolean }>}
 */
const aeadKeyGrants = new WeakMap();

const aeadGrantsOf = stateReader(aeadKeyGrants, "aead-key");

/**
 * The `aead-key` resource: an AES-GCM key. Holds a `CryptoKey` whose
 * platform usages cover the operations its mint options granted (see
 * `aeadKeyGrants`) and the options' `extractable` flag; instances are
 * minted only by the `aes-gcm` interface functions below.
 */
export class AeadKey extends symmetricKeyTail({}) {
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
   * @param {{ seal: boolean, open: boolean, wrap: boolean, unwrap: boolean }} grants
   */
  constructor(key, lengthBits, grants) {
    super(key);
    this.#lengthBits = lengthBits;
    aeadKeyGrants.set(this, grants);
  }

  /**
   * Encrypt and authenticate the plaintext stream under `nonce` and `aad`,
   * with a `tagSize`-byte authentication tag (`undefined` = the 16-byte
   * default). Returns a `ReadableStream` carrying ciphertext followed by
   * the tag (the `crypto.subtle.encrypt` wire format). Throws
   * `{ tag: 'invalid-nonce', val }` for a nonce outside AES-GCM's portable
   * window, and `{ tag: 'unsupported', val }` for a tag size outside the
   * GCM set, per the WIT contracts. The plaintext stream is drained before any
   * failure is raised, so the guest's writer always completes rather than
   * blocking on an unread stream.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {number | undefined} tagSize
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async seal(nonce, aad, tagSize, plaintext) {
    return withCollectedInputToStream(plaintext, async (message) => {
      if (!this.canSeal()) throw notPermitted("seal");
      return aeadSealOpen("seal", platformKeyOf(this), nonce, aad, tagSize, message);
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
      return aeadSealOpen("open", platformKeyOf(this), nonce, aad, tagSize, message);
    });
  }

  /**
   * Encrypt and authenticate serialized key material under `nonce` and
   * `aad`, exactly as `seal` encrypts a message: the result is
   * ciphertext followed by tag, and the `nonce`/`tagSize` contracts (and
   * their error cases) are `seal`'s. `input` is consumed first, on
   * failure as on success. Throws `{ tag: 'not-permitted' }` on a key
   * minted without the `wrap` grant.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {number | undefined} tagSize
   * @param {WrapInput} input
   * @returns {Promise<Uint8Array>}
   */
  async wrap(nonce, aad, tagSize, input) {
    const { bytes } = consumeWrapInput(input);
    if (!this.canWrap()) throw notPermitted("wrap");
    return aeadSealOpen(
      "seal",
      platformKeyOf(this),
      nonce,
      aad,
      tagSize,
      asBufferSource(bytes),
      "wrap",
    );
  }

  /**
   * Decrypt and verify wrapped key material under `nonce` and `aad`,
   * eagerly (this host does not use the WIT's deferral latitude): a
   * verification failure throws `{ tag: 'authentication-failed' }` here,
   * and the minted `unwrap-input` holds verified plaintext. The
   * `nonce`/`tagSize` contracts (and their error cases) are `open`'s.
   * Throws `{ tag: 'not-permitted' }` on a key minted without the
   * `unwrap` grant.
   * @param {Uint8Array} nonce
   * @param {Uint8Array} aad
   * @param {number | undefined} tagSize
   * @param {Uint8Array} wrapped
   * @returns {Promise<UnwrapInput>}
   */
  async unwrap(nonce, aad, tagSize, wrapped) {
    if (!this.canUnwrap()) throw notPermitted("unwrap");
    return new UnwrapInput(
      MINT,
      await aeadSealOpen(
        "open",
        platformKeyOf(this),
        nonce,
        aad,
        tagSize,
        asBufferSource(wrapped),
        "unwrap",
      ),
    );
  }

  /**
   * The algorithm getters: `name` projects the `CryptoKey`, `length` comes
   * from the mint (see `#lengthBits`), and the size getters report the
   * standard/default parameters — AES-GCM uses 12-byte nonces and 16-byte
   * tags by default, with other GCM sizes accepted per call.
   */
  algorithmName() {
    return platformKeyOf(this).algorithm.name;
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

  /** The usage grants: the mint policy recorded in `aeadKeyGrants`. */
  canSeal() {
    return aeadGrantsOf(this).seal;
  }

  canOpen() {
    return aeadGrantsOf(this).open;
  }

  canWrap() {
    return aeadGrantsOf(this).wrap;
  }

  canUnwrap() {
    return aeadGrantsOf(this).unwrap;
  }

  /**
   * This key's raw material as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyRaw`.
   */
  async toWrapInputRaw() {
    return new WrapInput(MINT, "raw", await exportRawGated(platformKeyOf(this)));
  }

  /**
   * The JWK serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputJwk() {
    const jwk = await exportJwkGated(platformKeyOf(this));
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(jwk));
  }
}

/**
 * The shared `seal`/`open` body of `aead-key`, over the collected message:
 * validate the per-call nonce and tag size (AES-GCM takes 12–128-byte
 * nonces and the registry tag-size set), run the platform call, and lift
 * its failure by direction — a `seal` failure through `platformCall`'s
 * taxonomy, an `open` failure through `decryptFailure` (a failed tag check
 * is `open`'s expected outcome). `wrap`/`unwrap` share
 * the body too, naming themselves through `operation` so their failure
 * details carry the operation the caller invoked.
 * @param {"seal" | "open"} direction
 * @param {CryptoKey} key
 * @param {Uint8Array} nonce
 * @param {Uint8Array} aad
 * @param {number | undefined} tagSize
 * @param {Uint8Array<ArrayBuffer>} message
 * @param {string} [operation]
 */
async function aeadSealOpen(direction, key, nonce, aad, tagSize, message, operation = direction) {
  requireGcmNonce(nonce);
  /** @type {AesGcmParams} */
  const params = {
    name: "AES-GCM",
    iv: asBufferSource(nonce),
    additionalData: asBufferSource(aad),
    tagLength: gcmTagLengthBits(tagSize),
  };
  if (direction === "seal") {
    const result = await platformCall(`${params.name} ${operation}`, () =>
      subtle.encrypt(params, key, message),
    );
    return new Uint8Array(result);
  }
  let result;
  try {
    result = await subtle.decrypt(params, key, message);
  } catch (err) {
    throw decryptFailure(err, operation);
  }
  return new Uint8Array(result);
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
 * Import raw key material as an HMAC key over the resolved hash. Any
 * non-empty length is accepted (RFC 2104); empty material throws
 * `{ tag: 'invalid-key', val }`.
 * @param {{ hash: string, blockBytes: number }} resolved
 * @param {Uint8Array} raw
 * @param {MacKeyOptions} options
 */
async function importHmacKey(resolved, raw, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash } = resolved;
  if (raw.length === 0) throw errInvalidKey("empty key");
  const key = await importPlatformKey(
    "HMAC key",
    "raw",
    raw,
    { name: "HMAC", hash },
    policy.extractable,
    usages,
  );
  return new MacKey(key, raw.length * 8, hash);
}

/**
 * Generate a fresh random HMAC key over the declared SHA-2 variant.
 * `length` is the key length in bits, `undefined` meaning the underlying
 * hash's block size (WebCrypto's `generateKey` default). A zero length
 * throws `{ tag: 'invalid-key' }`; a length that is not a multiple of 8
 * throws `{ tag: 'unsupported', val }` (sub-byte lengths are not served).
 * @param {{ hash: string, blockBytes: number }} resolved
 * @param {number | undefined} length
 * @param {MacKeyOptions} options
 */
async function generateHmacKey(resolved, length, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash, blockBytes } = resolved;
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
 * `import-key-jwk` contract of both HMAC interfaces). The platform owns
 * the JWK validation: `kty`, strict base64url `k`, `alg` against the
 * requested hash, and `ext` against the options' extractability all fail
 * there and map to `{ tag: 'invalid-key', val }`.
 * @param {{ hash: string, blockBytes: number }} resolved
 * @param {string} jwk
 * @param {MacKeyOptions} options
 */
async function importHmacKeyJwk(resolved, jwk, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash } = resolved;
  const material = jwkMaterial(jwk);
  requireStrictBase64url(material.k);
  const key = await importPlatformKeyJwk(
    "HMAC JWK",
    material,
    { name: "HMAC", hash },
    policy.extractable,
    usages,
  );
  // Length comes from `k`, not `key.algorithm.length`, which an engine may
  // omit for an imported key (see `MacKey`'s field doc).
  return new MacKey(key, jwkKeyBytes(material.k) * 8, hash);
}

/** The `polymorph:webcrypto/mac` interface: its resource classes. */
export const mac = { MacKey, MacKeyOptions };

/**
 * The shared derive-key body of both HMAC interfaces (`length` semantics
 * as `generateHmacKey`).
 * @param {{ hash: string, blockBytes: number }} resolved
 * @param {DeriveInput} input
 * @param {number | undefined} length
 * @param {MacKeyOptions} options
 */
async function deriveHmacKey(resolved, input, length, options) {
  const policy = macPolicy(options);
  const usages = macUsages(policy);
  const { hash, blockBytes } = resolved;
  if (length === 0) throw errInvalidKey("HMAC key length must be non-zero");
  if (length !== undefined && length % 8 !== 0) {
    throw errUnsupported(
      `HMAC key length ${length} is not a multiple of 8; sub-byte lengths are not served`,
    );
  }
  const bits = length ?? blockBytes * 8;
  const key = await deriveKeyFrom(
    input,
    { name: "HMAC", hash, length: bits },
    policy.extractable,
    usages,
  );
  return new MacKey(key, bits, hash);
}

/** SHA-1's HMAC parameters (the `hmac-sha1` interface; 64-byte blocks). */
const SHA1_HMAC = { hash: "SHA-1", blockBytes: 64 };

/**
 * The shared unwrap-key-raw body of both HMAC interfaces (see the
 * `wrapping` interface): the `import-key-raw` path over the consumed
 * input's bytes, with `invalid-key` details redacted (see
 * `redactingInvalidKey`). `resolve` is a thunk so the input is consumed
 * before anything — a declined variant included — can fail (the WIT
 * consumes on failure as on success).
 * @param {() => { hash: string, blockBytes: number }} resolve
 * @param {UnwrapInput} input
 * @param {MacKeyOptions} options
 */
function unwrapHmacKeyRaw(resolve, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped HMAC key material", () =>
    importHmacKey(resolve(), bytes, options),
  );
}

/**
 * The shared unwrap-key-jwk body of both HMAC interfaces: the unwrap-path
 * `use`/`key_ops` checks (see `unwrappedJwk`; the MAC grants map onto the
 * platform's `sign`/`verify` names one-to-one), then the `import-key-jwk`
 * path. `resolve` as on `unwrapHmacKeyRaw`.
 * @param {() => { hash: string, blockBytes: number }} resolve
 * @param {UnwrapInput} input
 * @param {MacKeyOptions} options
 */
function unwrapHmacKeyJwk(resolve, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  const jwk = unwrappedJwk(bytes, "sig", macUsages(macPolicy(options)));
  return redactingInvalidKey("unwrapped HMAC JWK", () =>
    importHmacKeyJwk(resolve(), jwk, options),
  );
}

/**
 * The `polymorph:webcrypto/hmac-sha1` interface: the same platform paths as
 * `hmac-sha2` at `SHA-1` (the platform serves the hash; HMAC's security
 * rests on the PRF property, which SHA-1's collision breaks do not
 * reach — see the WIT doc).
 */
export const hmacSha1 = {
  /**
   * @param {Uint8Array} raw
   * @param {MacKeyOptions} options
   */
  importKeyRaw: (raw, options) => importHmacKey(SHA1_HMAC, raw, options),
  /**
   * @param {string} jwk
   * @param {MacKeyOptions} options
   */
  importKeyJwk: (jwk, options) => importHmacKeyJwk(SHA1_HMAC, jwk, options),
  /**
   * @param {number | undefined} length
   * @param {MacKeyOptions} options
   */
  generateKey: (length, options) => generateHmacKey(SHA1_HMAC, length, options),
  /**
   * @param {DeriveInput} input
   * @param {number | undefined} length
   * @param {MacKeyOptions} options
   */
  deriveKey: (input, length, options) => deriveHmacKey(SHA1_HMAC, input, length, options),
  /**
   * @param {UnwrapInput} input
   * @param {MacKeyOptions} options
   */
  unwrapKeyRaw: (input, options) => unwrapHmacKeyRaw(() => SHA1_HMAC, input, options),
  /**
   * @param {UnwrapInput} input
   * @param {MacKeyOptions} options
   */
  unwrapKeyJwk: (input, options) => unwrapHmacKeyJwk(() => SHA1_HMAC, input, options),
};

/** The `polymorph:webcrypto/hmac-sha2` interface. */
export const hmacSha2 = {
  /**
   * @param {string} variant
   * @param {Uint8Array} raw
   * @param {MacKeyOptions} options
   */
  importKeyRaw: (variant, raw, options) => importHmacKey(sha2Variant(variant), raw, options),
  /**
   * @param {string} variant
   * @param {string} jwk
   * @param {MacKeyOptions} options
   */
  importKeyJwk: (variant, jwk, options) => importHmacKeyJwk(sha2Variant(variant), jwk, options),
  /**
   * @param {string} variant
   * @param {number | undefined} length
   * @param {MacKeyOptions} options
   */
  generateKey: (variant, length, options) =>
    generateHmacKey(sha2Variant(variant), length, options),
  /**
   * Mint an HMAC key from a parameterized derivation (the
   * `hmac-sha2.derive-key` contract; length semantics as `generate-key`).
   * @param {string} variant
   * @param {DeriveInput} input
   * @param {number | undefined} length
   * @param {MacKeyOptions} options
   */
  deriveKey: (variant, input, length, options) =>
    deriveHmacKey(sha2Variant(variant), input, length, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {MacKeyOptions} options
   */
  unwrapKeyRaw: (variant, input, options) =>
    unwrapHmacKeyRaw(() => sha2Variant(variant), input, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {MacKeyOptions} options
   */
  unwrapKeyJwk: (variant, input, options) =>
    unwrapHmacKeyJwk(() => sha2Variant(variant), input, options),
};

/** @type {WeakMap<DeriveOptions, { deriveBits: boolean, deriveKey: boolean }>} */
const derivePolicies = new WeakMap();

const derivePolicy = stateReader(derivePolicies, "derive-options");

export class DeriveOptions {
  constructor() {
    derivePolicies.set(this, { deriveBits: false, deriveKey: false });
  }

  /** @param {boolean} allowed */
  canDeriveBits(allowed) {
    derivePolicy(this).deriveBits = allowed;
  }

  /** @param {boolean} allowed */
  canDeriveKey(allowed) {
    derivePolicy(this).deriveKey = allowed;
  }
}

/**
 * The platform usages for a derive policy, throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant (the options
 * contract). The WIT grants map one-to-one onto the platform's derive
 * usage pair.
 * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
 * @returns {KeyUsage[]}
 */
function deriveUsages(policy) {
  /** @type {KeyUsage[]} */
  const usages = [];
  if (policy.deriveBits) usages.push("deriveBits");
  if (policy.deriveKey) usages.push("deriveKey");
  if (usages.length === 0) {
    throw errNotPermitted("an options resource granting nothing cannot mint");
  }
  return usages;
}

/**
 * Per-instance state for the resources that appear as *parameters* of other
 * interfaces' functions (`prepare` takes an `ikm`, `derive-key` takes a
 * `derive-input`): state lives in WeakMaps rather than private fields, the
 * options-classes idiom, so the classes stay structurally compatible with
 * the interface definitions jco derives.
 * @type {WeakMap<Ikm, { key: CryptoKey, policy: { deriveBits: boolean, deriveKey: boolean } }>}
 */
const ikmState = new WeakMap();

const ikmOf = stateReader(ikmState, "ikm");

/** A mint token so the resource classes have no public constructor path. */
const MINT = Symbol("webcrypto mint");

const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Per-instance state of the wrapping intermediates. Both resources appear
 * as *parameters* of other interfaces' functions (`wrap` takes a
 * `wrap-input`, the unwrap mints take an `unwrap-input`), so state lives in
 * WeakMaps, the `ikm` idiom. Consumption is deletion: the consuming
 * operation removes the entry before anything else runs, on failure as on
 * success (the WIT contract), so a second use misses the map exactly like a
 * foreign resource does.
 * @type {WeakMap<WrapInput, { format: "raw" | "jwk" | "pkcs8", bytes: Uint8Array }>}
 */
const wrapInputState = new WeakMap();

/** @type {WeakMap<UnwrapInput, { bytes: Uint8Array }>} */
const unwrapInputState = new WeakMap();

/**
 * The `wrapping.wrap-input` resource: serialized key material awaiting
 * encryption under a wrapping key. The serialization format travels with
 * the resource — `kw-key.wrap`'s JWK padding keys on it — and the bytes
 * never reach the guest.
 */
export class WrapInput {
  /**
   * @param {symbol} token
   * @param {"raw" | "jwk" | "pkcs8"} format
   * @param {Uint8Array} bytes
   */
  constructor(token, format, bytes) {
    if (token !== MINT) throw new TypeError("wrap-input is minted by to-wrap-input-*");
    wrapInputState.set(this, { format, bytes });
  }
}

/**
 * The `wrapping.unwrap-input` resource: decrypted key material awaiting a
 * typed mint. This host's `unwrap` operations decrypt — and, on the
 * authenticated kinds, verify — eagerly, so the bytes here are already
 * verified; they never reach the guest.
 */
export class UnwrapInput {
  /**
   * @param {symbol} token
   * @param {Uint8Array} bytes
   */
  constructor(token, bytes) {
    if (token !== MINT) throw new TypeError("unwrap-input is minted by unwrap");
    unwrapInputState.set(this, { bytes });
  }
}

/** The `polymorph:webcrypto/wrapping` interface: its resource classes. */
export const wrapping = { WrapInput, UnwrapInput };

/**
 * Consume a `wrap-input`: the entry is removed before the operation does
 * anything else, on failure as on success (the WIT contract). A miss means
 * the resource was already consumed or belongs to another provider.
 * @param {WrapInput} input
 */
function consumeWrapInput(input) {
  const state = wrapInputState.get(input);
  wrapInputState.delete(input);
  if (state === undefined) {
    throw errOther("wrap-input already consumed or minted by another provider");
  }
  return state;
}

/**
 * Consume an `unwrap-input`. See `consumeWrapInput`.
 * @param {UnwrapInput} input
 */
function consumeUnwrapInput(input) {
  const state = unwrapInputState.get(input);
  unwrapInputState.delete(input);
  if (state === undefined) {
    throw errOther("unwrap-input already consumed or minted by another provider");
  }
  return state;
}

/**
 * Run an unwrap mint's import body, redacting the detail of any
 * `invalid-key` failure to the fixed message `invalid ${what}`: the parse
 * input is decrypted key material the caller does not hold, so the message
 * must not carry any of it (see `README.md`, "Error contract") — including
 * the platform failure details the import paths' messages interpolate.
 * @template T
 * @param {string} what
 * @param {() => Promise<T>} run
 * @returns {Promise<T>}
 */
async function redactingInvalidKey(what, run) {
  try {
    return await run();
  } catch (err) {
    if (isWitError(err) && err.tag === "invalid-key") {
      throw errInvalidKey(`invalid ${what}`);
    }
    throw err;
  }
}

/**
 * Parse an unwrap-input's bytes as JWK text and validate the two usage
 * members in the caller's stead (the unwrap-path JWK contract; on the
 * import path the caller holds the JWK, so they are its policy to check):
 * `key_ops`, when present, must include every usage granted in the mint's
 * options, under the granted operations' platform names; `use`, when
 * present, must match the key's family. Both members are then stripped, as
 * on the import path. Trailing whitespace after the JSON text — the
 * `kw-key.wrap` JWK padding — is accepted (`JSON.parse` ignores it). Every
 * failure carries a fixed message: the text is decrypted key material the
 * caller does not hold.
 * @param {Uint8Array} bytes
 * @param {"enc" | "sig"} family
 * @param {string[]} grantedOps
 * @returns {string} the validated JWK, re-serialized without `use`/`key_ops`
 */
function unwrappedJwk(bytes, family, grantedOps) {
  let text;
  try {
    text = utf8Decoder.decode(bytes);
  } catch {
    throw errInvalidKey("unwrapped JWK is not valid UTF-8");
  }
  let jwk;
  try {
    jwk = JSON.parse(text);
  } catch {
    throw errInvalidKey("unwrapped JWK is not valid JSON");
  }
  if (typeof jwk !== "object" || jwk === null || Array.isArray(jwk)) {
    throw errInvalidKey("unwrapped JWK must be a JSON object");
  }
  const { use, key_ops, ...material } = /** @type {Record<string, unknown>} */ (jwk);
  if (use !== undefined && use !== family) {
    throw errInvalidKey("unwrapped JWK `use` does not match the key's family");
  }
  if (key_ops !== undefined) {
    if (!Array.isArray(key_ops) || !grantedOps.every((op) => key_ops.includes(op))) {
      throw errInvalidKey("unwrapped JWK `key_ops` does not cover the granted usages");
    }
  }
  return JSON.stringify(material);
}

/**
 * The `hkdf.ikm` resource: input keying material as a platform `CryptoKey`
 * (`HKDF`-bound, non-extractable — the platform *forces* that at import,
 * which is the WIT contract's "never readable" made platform-enforced).
 * The WIT grants ride the key's usages, so the platform enforces them too.
 */
export class Ikm {
  /**
   * @param {symbol} token
   * @param {CryptoKey} key
   * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
   */
  constructor(token, key, policy) {
    if (token !== MINT) throw new TypeError("ikm is minted by import-ikm");
    ikmState.set(this, { key, policy });
  }

  canDeriveBits() {
    return ikmOf(this).policy.deriveBits;
  }

  canDeriveKey() {
    return ikmOf(this).policy.deriveKey;
  }
}

/**
 * The `derivation.derive-input` resource: the spec's (baseKey, params)
 * pair as an object — the platform `CryptoKey` plus the derivation
 * parameters (HKDF/PBKDF2, or an agreement's `{ name, public }`), with the
 * grants copied from the base secret at `prepare`/`agree`.
 *
 * The derivation runs lazily here, which keeps no base-secret bytes in
 * memory: the base secret lives behind the platform `CryptoKey`, and this
 * class holds no raw copy of anything secret.
 */
export class DeriveInput {
  /**
   * @param {symbol} token
   * @param {CryptoKey} key
   * @param {HkdfParams | Pbkdf2Params | EcdhKeyDeriveParams} params
   * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
   */
  constructor(token, key, params, policy) {
    if (token !== MINT) throw new TypeError("derive-input is minted by prepare");
    inputState.set(this, { key, params, policy });
  }

  canDeriveBits() {
    return inputOf(this).policy.deriveBits;
  }

  canDeriveKey() {
    return inputOf(this).policy.deriveKey;
  }

  /**
   * The derived bits at `length` (bits, a non-zero multiple of 8).
   * `undefined` means the source's natural output length: the whole shared
   * secret for an agreement input (the platform's own null-length X25519
   * behavior), and a failure for a KDF input, whose output length is a
   * caller choice. Fails `not-permitted` without the grant; the RFC 5869
   * output bound and the agreed secret's own length bound surface from the
   * platform as `{ tag: 'other' }`.
   * @param {number | undefined} length
   * @returns {Promise<Uint8Array>}
   */
  async deriveBits(length) {
    const state = inputOf(this);
    if (!state.policy.deriveBits) throw notPermitted("derive-bits");
    if (length === undefined) {
      if (!isAgreementParams(state.params)) {
        throw errOther(
          "a KDF's output length is a caller choice: it has no natural output length, which only agreement sources define",
        );
      }
      const secret = await platformCall("agreement derive", () =>
        subtle.deriveBits(state.params, state.key, null),
      );
      return new Uint8Array(secret);
    }
    if (length === 0 || length % 8 !== 0) {
      throw errOther(`derive length must be a non-zero multiple of 8 bits, got ${length}`);
    }
    const bits = await platformCall("KDF derive", () =>
      subtle.deriveBits(state.params, state.key, length),
    );
    return new Uint8Array(bits);
  }

}

/**
 * Mint a platform key from an input (the targets' `derive-key`), enforcing
 * the grant and the cap rule: an extractable key is bits disclosure by
 * other means, so it requires the `derive-bits` grant too. A free function
 * rather than a method so the resource class carries exactly the WIT
 * surface (it appears as a *parameter* of other interfaces' functions, so
 * the derived definitions must remain assignable to it).
 * @param {DeriveInput} input
 * @param {AesKeyGenParams | HmacKeyGenParams} derived
 * @param {boolean} extractable
 * @param {KeyUsage[]} usages
 */
async function deriveKeyFrom(input, derived, extractable, usages) {
  const state = inputOf(input);
  if (!state.policy.deriveKey) throw notPermitted("derive-key");
  if (extractable && !state.policy.deriveBits) {
    throw errNotPermitted(
      "minting an extractable key requires the derive-bits grant: an exportable key is bits disclosure by other means",
    );
  }
  return await platformCall("KDF derive-key", () =>
    subtle.deriveKey(state.params, state.key, derived, extractable, usages),
  );
}

/**
 * @type {WeakMap<DeriveInput, { key: CryptoKey, params: HkdfParams | Pbkdf2Params | EcdhKeyDeriveParams, policy: { deriveBits: boolean, deriveKey: boolean } }>}
 */
const inputState = new WeakMap();

const inputOf = stateReader(inputState, "derive-input");

/**
 * Whether a derive-input's params are an agreement's (a `{ name, public }`
 * pair) rather than a KDF's — the discriminant for natural-output-length
 * behavior.
 * @param {HkdfParams | Pbkdf2Params | EcdhKeyDeriveParams} params
 * @returns {params is EcdhKeyDeriveParams}
 */
function isAgreementParams(params) {
  return "public" in params;
}



/**
 * Import input keying material (the `hkdf.import-ikm` contract): empty
 * material is accepted, a grantless policy `not-permitted`. The
 * platform key is minted non-extractable — its own requirement, and the
 * WIT's.
 * @param {Uint8Array} raw
 * @param {DeriveOptions} options
 */
async function importIkm(raw, options) {
  const policy = derivePolicy(options);
  const usages = deriveUsages(policy);
  const key = await importPlatformKey(
    "HKDF input keying material",
    "raw",
    raw,
    "HKDF",
    false,
    usages,
  );
  return new Ikm(MINT, key, { ...policy });
}

/**
 * Parameterize a derivation (the `hkdf-sha2.prepare` contract): the input's
 * grants are copied; the salt and info are copied too, since the lifted
 * arrays are this call's, not the resource's.
 * @param {{ hash: string }} resolved
 * @param {Ikm} input
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 */
async function prepare(resolved, input, salt, info) {
  const { hash } = resolved;
  const { key, policy } = ikmOf(input);
  const params = {
    name: "HKDF",
    hash,
    salt: asBufferSource(salt.slice()),
    info: asBufferSource(info.slice()),
  };
  return new DeriveInput(MINT, key, params, { ...policy });
}

/**
 * Chain from another derivation's output (the `hkdf-sha2.prepare-from`
 * contract): the upstream runs at its natural output length, which only
 * agreement inputs have — the platform's `deriveKey(X25519 → "HKDF")`
 * turns the shared secret into an HKDF base key without the bytes
 * transiting this host. A KDF input has no natural length, so it fails
 * exactly as the platform's `deriveKey(… → "HKDF")` does.
 * @param {{ hash: string }} resolved
 * @param {DeriveInput} input
 * @param {Uint8Array} salt
 * @param {Uint8Array} info
 * @returns {Promise<DeriveInput>}
 */
async function prepareFrom(resolved, input, salt, info) {
  const { hash } = resolved;
  const state = inputOf(input);
  if (!state.policy.deriveKey) throw notPermitted("derive-key");
  if (!isAgreementParams(state.params)) {
    throw errOther(
      "a KDF's output length is a caller choice: it has no natural output length, which only agreement sources define",
    );
  }
  const upstream = state.params;
  const baseKey = await platformCall("agreement chaining", () =>
    subtle.deriveKey(upstream, state.key, "HKDF", false, deriveUsages(state.policy)),
  );
  const params = {
    name: "HKDF",
    hash,
    salt: asBufferSource(salt.slice()),
    info: asBufferSource(info.slice()),
  };
  return new DeriveInput(MINT, baseKey, params, { ...state.policy });
}

/**
 * Mint input keying material from unwrapped bytes (the `hkdf.unwrap-ikm`
 * contract; see the `wrapping` interface): `import-ikm`'s path over the
 * consumed input's bytes, with `invalid-key` details redacted (see
 * `redactingInvalidKey`).
 * @param {UnwrapInput} input
 * @param {DeriveOptions} options
 */
async function unwrapIkm(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped HKDF input keying material", () =>
    importIkm(bytes, options),
  );
}

/** The `polymorph:webcrypto/derivation` interface: its resource classes. */
export const derivation = { DeriveOptions, DeriveInput };

/** The `polymorph:webcrypto/hkdf` interface: the hash-independent half. */
export const hkdf = { Ikm, importIkm, unwrapIkm };

/** The `polymorph:webcrypto/hkdf-sha2` interface. */
export const hkdfSha2 = {
  /**
   * @param {string} variant
   * @param {Ikm} input
   * @param {Uint8Array} salt
   * @param {Uint8Array} info
   */
  prepare: (variant, input, salt, info) => prepare(sha2Variant(variant), input, salt, info),
  /**
   * @param {string} variant
   * @param {DeriveInput} input
   * @param {Uint8Array} salt
   * @param {Uint8Array} info
   */
  prepareFrom: (variant, input, salt, info) =>
    prepareFrom(sha2Variant(variant), input, salt, info),
};

/**
 * The `polymorph:webcrypto/hkdf-sha1` interface: `hkdf`'s prepare steps at
 * `SHA-1` (see `hmacSha1`'s note; the `ikm` resource is shared).
 */
export const hkdfSha1 = {
  /**
   * @param {Ikm} input
   * @param {Uint8Array} salt
   * @param {Uint8Array} info
   */
  prepare: (input, salt, info) => prepare(SHA1_HMAC, input, salt, info),
  /**
   * @param {DeriveInput} input
   * @param {Uint8Array} salt
   * @param {Uint8Array} info
   */
  prepareFrom: (input, salt, info) => prepareFrom(SHA1_HMAC, input, salt, info),
};

/**
 * @type {WeakMap<Password, { key: CryptoKey, policy: { deriveBits: boolean, deriveKey: boolean } }>}
 */
const passwordState = new WeakMap();

const passwordOf = stateReader(passwordState, "password");

/**
 * The `pbkdf2.password` resource: a password as a platform `CryptoKey`
 * (`PBKDF2`-bound, non-extractable — the platform *forces* that at import).
 * The WIT grants ride the key's usages, so the platform enforces them too.
 * Like `ikm`, state lives in a WeakMap: the resource appears as a
 * parameter of `prepare`.
 */
export class Password {
  /**
   * @param {symbol} token
   * @param {CryptoKey} key
   * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
   */
  constructor(token, key, policy) {
    if (token !== MINT) throw new TypeError("password is minted by import-password");
    passwordState.set(this, { key, policy });
  }

  canDeriveBits() {
    return passwordOf(this).policy.deriveBits;
  }

  canDeriveKey() {
    return passwordOf(this).policy.deriveKey;
  }
}

/**
 * Import a password (the `pbkdf2.import-password` contract): empty
 * passwords are accepted — the platform serves them, and the upstream
 * vectors exercise them as valid (the documented asymmetry with
 * `import-ikm`). A grantless policy is `not-permitted`.
 * @param {Uint8Array} raw
 * @param {DeriveOptions} options
 */
async function importPassword(raw, options) {
  const policy = derivePolicy(options);
  const usages = deriveUsages(policy);
  const key = await importPlatformKey("PBKDF2 password", "raw", raw, "PBKDF2", false, usages);
  return new Password(MINT, key, { ...policy });
}

/**
 * Parameterize a PBKDF2 derivation (the `pbkdf2-sha2.prepare` contract): salt
 * and iteration count bound now, output length per use. A zero iteration
 * count fails here — the platform's `OperationError`, checked early so a
 * misparameterized input cannot mint.
 * @param {{ hash: string }} resolved
 * @param {Password} input
 * @param {Uint8Array} salt
 * @param {number} iterations
 */
async function preparePbkdf2(resolved, input, salt, iterations) {
  const { hash } = resolved;
  if (iterations === 0) {
    throw errOther("PBKDF2 requires a positive iteration count");
  }
  const { key, policy } = passwordOf(input);
  const params = { name: "PBKDF2", hash, salt: asBufferSource(salt.slice()), iterations };
  return new DeriveInput(MINT, key, params, { ...policy });
}

/**
 * Mint a password from unwrapped bytes (the `pbkdf2.unwrap-password`
 * contract): `import-password`'s path over the consumed input's bytes,
 * with `invalid-key` details redacted (see `redactingInvalidKey`).
 * @param {UnwrapInput} input
 * @param {DeriveOptions} options
 */
async function unwrapPassword(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped PBKDF2 password", () =>
    importPassword(bytes, options),
  );
}

/** The `polymorph:webcrypto/pbkdf2` interface. */
export const pbkdf2 = { Password, importPassword, unwrapPassword };

/** The `polymorph:webcrypto/pbkdf2-sha2` interface. */
export const pbkdf2Sha2 = {
  /**
   * @param {string} variant
   * @param {Password} input
   * @param {Uint8Array} salt
   * @param {number} iterations
   */
  prepare: (variant, input, salt, iterations) =>
    preparePbkdf2(sha2Variant(variant), input, salt, iterations),
};

/**
 * The `polymorph:webcrypto/pbkdf2-sha1` interface: `pbkdf2`'s prepare step at
 * `SHA-1` (see `hmacSha1`'s note; the `password` resource is shared).
 */
export const pbkdf2Sha1 = {
  /**
   * @param {Password} input
   * @param {Uint8Array} salt
   * @param {number} iterations
   */
  prepare: (input, salt, iterations) => preparePbkdf2(SHA1_HMAC, input, salt, iterations),
};

/** @type {WeakMap<AgreementKeyOptions, { deriveBits: boolean, deriveKey: boolean, extractable: boolean }>} */
const agreementPolicies = new WeakMap();

const agreementPolicy = stateReader(agreementPolicies, "agreement-key-options");

export class AgreementKeyOptions {
  constructor() {
    agreementPolicies.set(this, { deriveBits: false, deriveKey: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canDeriveBits(allowed) {
    agreementPolicy(this).deriveBits = allowed;
  }

  /** @param {boolean} allowed */
  canDeriveKey(allowed) {
    agreementPolicy(this).deriveKey = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    agreementPolicy(this).extractable = allowed;
  }
}

/** @type {WeakMap<AgreementPublicKey, { key: CryptoKey }>} */
const agreementPublicState = new WeakMap();

const agreementPublicOf = stateReader(agreementPublicState, "public-key");

/**
 * The `key-agreement.public-key` resource: public material behind a
 * platform `CryptoKey` (always imported extractable — public keys have no
 * extractability gate; the WIT fallibility of the exports covers platform
 * keys that are handles). Like `ikm`, state lives in a WeakMap: the
 * resource appears as a parameter of `agree`.
 */
export class AgreementPublicKey {
  /**
   * @param {symbol} token
   * @param {CryptoKey} key
   */
  constructor(token, key) {
    if (token !== MINT) throw new TypeError("public-key is minted by import or generate");
    agreementPublicState.set(this, { key });
  }

  algorithmName() {
    return agreementPublicOf(this).key.algorithm.name;
  }

  /**
   * The public key material in the minting interface's public format
   * (X25519's raw u-coordinate; ECDH's uncompressed SEC1 point).
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyRaw() {
    const { key } = agreementPublicOf(this);
    return new Uint8Array(
      await platformCall("raw public-key export", () => subtle.exportKey("raw", key)),
    );
  }

  /**
   * The key as a public JWK (OKP for X25519, EC for ECDH), per the WIT
   * contract: exactly the material-bearing members.
   */
  async exportKeyJwk() {
    const { key } = agreementPublicOf(this);
    const jwk = await platformCall("jwk public-key export", () => subtle.exportKey("jwk", key));
    return JSON.stringify(
      jwk.kty === "OKP"
        ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x }
        : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    );
  }

  /**
   * The SubjectPublicKeyInfo form, with `exportKeyRaw`'s fallibility.
   * @returns {Promise<Uint8Array>}
   */
  async exportKeySpki() {
    const { key } = agreementPublicOf(this);
    return new Uint8Array(
      await platformCall("spki public-key export", () => subtle.exportKey("spki", key)),
    );
  }
}

/** @type {WeakMap<AgreementSecretKey, { key: CryptoKey, policy: { deriveBits: boolean, deriveKey: boolean, extractable: boolean } }>} */
const agreementSecretState = new WeakMap();

const agreementSecretOf = stateReader(agreementSecretState, "secret-key");

/**
 * The usages every platform agreement secret key is minted with. Unlike
 * the KDF base secrets, the WIT grants do not ride the platform usages:
 * `agree`'s contributory probe is a platform `deriveBits` call and
 * `prepare-from`'s chaining is a platform `deriveKey` call, and either
 * must work whichever single grant the mint carried. The grants are
 * enforced host-side instead (`derive-input`'s own checks).
 * @type {KeyUsage[]}
 */
const AGREEMENT_PLATFORM_USAGES = ["deriveBits", "deriveKey"];

/**
 * The `key-agreement.secret-key` resource: a platform `CryptoKey` plus the
 * mint policy its agreed inputs inherit.
 */
export class AgreementSecretKey {
  /**
   * @param {symbol} token
   * @param {CryptoKey} key
   * @param {{ deriveBits: boolean, deriveKey: boolean, extractable: boolean }} policy
   */
  constructor(token, key, policy) {
    if (token !== MINT) throw new TypeError("secret-key is minted by import or generate");
    agreementSecretState.set(this, { key, policy });
  }

  /**
   * The shared secret with `peer` as a `derive-input` (the
   * `secret-key.agree` contract). The input holds the (secret key, peer)
   * pair and derives lazily through the platform, so no secret bytes live
   * in this host; the WIT pins the contributory check *here*, so the
   * platform derivation runs once now as a probe — its all-zero check is
   * the W3C API's own — and its output is discarded. An algorithm-mismatched
   * peer surfaces from the same probe (`InvalidAccessError`).
   * @param {AgreementPublicKey} peer
   * @returns {Promise<DeriveInput>}
   */
  async agree(peer) {
    const state = agreementSecretOf(this);
    /** @type {EcdhKeyDeriveParams} */
    const params = { name: state.key.algorithm.name, public: agreementPublicOf(peer).key };
    try {
      await subtle.deriveBits(params, state.key, null);
    } catch (err) {
      const failure = asPlatformError(err);
      if (failure.name === "OperationError") {
        throw errInvalidKey(
          "the shared secret is all-zero: the peer public key is a small-order point",
        );
      }
      if (failure.name === "InvalidAccessError") {
        throw errInvalidKey(`peer key is not usable with this key: ${failure.detail}`);
      }
      throw errOther(`agreement failed: ${failure.detail}`);
    }
    const { deriveBits, deriveKey } = state.policy;
    return new DeriveInput(MINT, state.key, params, { deriveBits, deriveKey });
  }

  algorithmName() {
    return agreementSecretOf(this).key.algorithm.name;
  }

  canDeriveBits() {
    return agreementSecretOf(this).policy.deriveBits;
  }

  canDeriveKey() {
    return agreementSecretOf(this).policy.deriveKey;
  }

  extractable() {
    return agreementSecretOf(this).policy.extractable;
  }

  /**
   * The private JWK (OKP for X25519, EC for ECDH), material members only,
   * behind the extractability gate.
   */
  async exportKeyJwk() {
    const state = agreementSecretOf(this);
    if (!state.policy.extractable) throw errNotExtractable();
    const jwk = await platformCall("jwk secret-key export", () =>
      subtle.exportKey("jwk", state.key),
    );
    return JSON.stringify(
      jwk.kty === "OKP"
        ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }
        : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
    );
  }

  /**
   * The PKCS#8 form, behind the same gate.
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyPkcs8() {
    const state = agreementSecretOf(this);
    if (!state.policy.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("pkcs8 secret-key export", () => subtle.exportKey("pkcs8", state.key)),
    );
  }

  /**
   * The private JWK serialization as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyJwk`.
   */
  async toWrapInputJwk() {
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(await this.exportKeyJwk()));
  }

  /**
   * The PKCS#8 serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputPkcs8() {
    return new WrapInput(MINT, "pkcs8", await this.exportKeyPkcs8());
  }
}

/**
 * Require at least one derive grant (the package-wide options contract),
 * without projecting the grants onto platform usages (see
 * `AGREEMENT_PLATFORM_USAGES`).
 * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
 */
function requireAgreementGrant(policy) {
  if (!policy.deriveBits && !policy.deriveKey) {
    throw errNotPermitted("a key with no enabled usage cannot be minted");
  }
}

/**
 * Import a raw 32-byte u-coordinate (the `x25519.import-public-key-raw`
 * contract): deliberately permissive, as the platform's is — degenerate
 * keys surface at `agree`; a wrong length fails here.
 * @param {Uint8Array} raw
 */
async function importX25519PublicKey(raw) {
  const key = await importPlatformKey("X25519 public key", "raw", raw, "X25519", true, []);
  return new AgreementPublicKey(MINT, key);
}

/**
 * Import an RFC 8037 OKP private JWK (the `x25519.import-secret-key-jwk`
 * contract). The parse and validation are the platform's (`kty`, `crv`,
 * `d` presence, `ext` against extractability); `use`/`key_ops` are
 * stripped as the JWK contract requires, and strictness of the base64url
 * members is pinned host-side. This host cannot check `x` against `d`
 * (the WIT MAY) — the platform's import steps do not mandate it — and
 * per the MUST NOT it never trusts `x`: the platform derives operations
 * from `d`.
 * @param {string} jwkText
 * @param {AgreementKeyOptions} options
 */
async function importX25519SecretKeyJwk(jwkText, options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.d);
  const key = await importPlatformKeyJwk(
    "X25519 private JWK",
    jwk,
    "X25519",
    policy.extractable,
    AGREEMENT_PLATFORM_USAGES,
  );
  if (key.type !== "private") {
    throw errInvalidKey("OKP private JWK must carry `d` (base64url private key)");
  }
  return new AgreementSecretKey(MINT, key, { ...policy });
}

/**
 * Generate a fresh X25519 key pair, returning `[secret, public]`.
 * @param {AgreementKeyOptions} options
 * @returns {Promise<[AgreementSecretKey, AgreementPublicKey]>}
 */
async function generateX25519Key(options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const pair = /** @type {CryptoKeyPair} */ (
    await platformCall("X25519 key generation", () =>
      subtle.generateKey("X25519", policy.extractable, AGREEMENT_PLATFORM_USAGES),
    )
  );
  return [
    new AgreementSecretKey(MINT, pair.privateKey, { ...policy }),
    new AgreementPublicKey(MINT, pair.publicKey),
  ];
}

/** The `polymorph:webcrypto/key-agreement` interface: its resource classes. */
export const keyAgreement = { AgreementKeyOptions, PublicKey: AgreementPublicKey, SecretKey: AgreementSecretKey };

/**
 * Import an X25519 public key from a SubjectPublicKeyInfo — a platform
 * pass-through (the platform validates the DER); the embedded point is
 * admitted as permissively as the raw import's.
 * @param {Uint8Array} spki
 */
async function importX25519PublicKeySpki(spki) {
  const key = await importPlatformKey("X25519 spki", "spki", spki, "X25519", true, []);
  return new AgreementPublicKey(MINT, key);
}

/**
 * Import an X25519 public key from an OKP public JWK — a platform
 * pass-through of the material members; strictness of the base64url `x`
 * is pinned host-side.
 * @param {string} jwkText
 */
async function importX25519PublicKeyJwk(jwkText) {
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  const key = await importPlatformKeyJwk("X25519 public JWK", jwk, "X25519", true, []);
  return new AgreementPublicKey(MINT, key);
}

/**
 * Import an X25519 secret key from a PKCS#8 PrivateKeyInfo — a platform
 * pass-through; the platform owns the DER validation.
 * @param {Uint8Array} pkcs8
 * @param {AgreementKeyOptions} options
 */
async function importX25519SecretKeyPkcs8(pkcs8, options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const key = await importPlatformKey(
    "X25519 pkcs8",
    "pkcs8",
    pkcs8,
    "X25519",
    policy.extractable,
    AGREEMENT_PLATFORM_USAGES,
  );
  return new AgreementSecretKey(MINT, key, { ...policy });
}

/**
 * The granted operations' platform names for an agreement mint policy (the
 * unwrap-path `key_ops` rule; the derive grants map onto the platform's
 * names one-to-one).
 * @param {{ deriveBits: boolean, deriveKey: boolean }} policy
 */
function agreementGrantedOps(policy) {
  const ops = [];
  if (policy.deriveBits) ops.push("deriveBits");
  if (policy.deriveKey) ops.push("deriveKey");
  return ops;
}

/**
 * Mint a static secret key from unwrapped key material read as an OKP
 * private JWK (the `x25519.unwrap-secret-key-jwk` contract): the
 * unwrap-path `use`/`key_ops` checks, then `import-secret-key-jwk`'s path
 * with `invalid-key` details redacted (see `redactingInvalidKey`).
 * @param {UnwrapInput} input
 * @param {AgreementKeyOptions} options
 */
async function unwrapX25519SecretKeyJwk(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const jwk = unwrappedJwk(bytes, "enc", agreementGrantedOps(policy));
  return redactingInvalidKey("unwrapped X25519 private JWK", () =>
    importX25519SecretKeyJwk(jwk, options),
  );
}

/**
 * Mint a static secret key from unwrapped key material read as a PKCS#8
 * PrivateKeyInfo: `import-secret-key-pkcs8`'s path, redacted like the JWK
 * mint.
 * @param {UnwrapInput} input
 * @param {AgreementKeyOptions} options
 */
async function unwrapX25519SecretKeyPkcs8(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped X25519 pkcs8", () =>
    importX25519SecretKeyPkcs8(bytes, options),
  );
}

/** The `polymorph:webcrypto/x25519` interface. */
export const x25519 = {
  importPublicKeyRaw: importX25519PublicKey,
  importPublicKeySpki: importX25519PublicKeySpki,
  importPublicKeyJwk: importX25519PublicKeyJwk,
  importSecretKeyJwk: importX25519SecretKeyJwk,
  importSecretKeyPkcs8: importX25519SecretKeyPkcs8,
  generateKey: generateX25519Key,
  unwrapSecretKeyJwk: unwrapX25519SecretKeyJwk,
  unwrapSecretKeyPkcs8: unwrapX25519SecretKeyPkcs8,
};

/**
 * The per-curve ECDH parameters: WebCrypto's `namedCurve` (the platform
 * algorithm at every mint is `{ name: "ECDH", namedCurve }`) and the
 * uncompressed-SEC1 public key length the raw import enforces.
 */
/** @type {Readonly<Record<string, { namedCurve: string, publicLength: number } | undefined>>} */
const ECDH_CURVES = Object.assign(Object.create(null), {
  p256: { namedCurve: "P-256", publicLength: 65 },
  p384: { namedCurve: "P-384", publicLength: 97 },
});

/**
 * The served `ecdh-variant` entry for `variant`. `p521` — the enum's only
 * other case — is declared by the WIT and served by no implementation of
 * this package; the decline message matches the shared Rust core's
 * rendering.
 * @param {string} variant
 */
function ecdhCurve(variant) {
  const entry = ECDH_CURVES[variant];
  if (entry === undefined) {
    throw errUnsupported("ECDH P-521 is not served by this implementation");
  }
  return entry;
}

/**
 * Import an uncompressed-SEC1 ECDH public key of the declared variant (the
 * `ecdh.import-public-key-raw` contract): the length and leading-`0x04`
 * checks are enforced here — engines differ on compressed-point raw
 * imports, and the WIT pins their rejection — and the platform validates
 * the point is on the curve.
 * @param {string} variant
 * @param {Uint8Array} raw
 */
async function importEcdhPublicKey(variant, raw) {
  const entry = ecdhCurve(variant);
  if (raw.length !== entry.publicLength || raw[0] !== 0x04) {
    throw errInvalidKey(
      `${variant} public keys are uncompressed SEC1 points (${entry.publicLength} bytes, leading 0x04)`,
    );
  }
  const key = await importPlatformKey(
    `${variant} public key`,
    "raw",
    raw,
    { name: "ECDH", namedCurve: entry.namedCurve },
    true,
    [],
  );
  return new AgreementPublicKey(MINT, key);
}

/**
 * The DER AlgorithmIdentifier TLV an EC SubjectPublicKeyInfo must open
 * with, per served curve: `SEQUENCE { id-ecPublicKey, <named-curve OID> }`
 * (`1.2.840.10045.2.1` plus `1.2.840.10045.3.1.7` for P-256, `1.3.132.0.34`
 * for P-384).
 * @type {Readonly<Record<string, Uint8Array>>}
 */
const EC_SPKI_ALGORITHM_IDENTIFIERS = Object.assign(Object.create(null), {
  // 301306072a8648ce3d020106082a8648ce3d030107
  "P-256": Uint8Array.from([
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07,
  ]),
  // 301006072a8648ce3d020106052b81040022
  "P-384": Uint8Array.from([
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
    0x00, 0x22,
  ]),
});

/**
 * The offset of the AlgorithmIdentifier TLV inside a SubjectPublicKeyInfo —
 * one DER length decode of the outer SEQUENCE header (short and long form,
 * minimal-encoding checks included) — or 0 when the input does not open as
 * one.
 * @param {Uint8Array} spki
 */
function spkiAlgorithmOffset(spki) {
  if (spki.length >= 2 && spki[0] === 0x30) {
    const first = spki[1];
    if (first < 0x80) return 2;
    if (first === 0x81 && spki.length >= 3 && spki[2] >= 0x80) return 3;
    if (first === 0x82 && spki.length >= 4 && spki[2] !== 0) return 4;
  }
  return 0;
}

/**
 * Guard: rejects an EC SubjectPublicKeyInfo whose AlgorithmIdentifier is
 * not the declared curve's named-OID form before the platform sees it.
 * Platform engines split on explicit-ECParameters ("unnamed curve")
 * encodings — some admit equivalent groups under their own validation —
 * and the WIT pins their rejection as `invalid-key`, so this catches the
 * encodings the local platform would otherwise admit (it also enforces the
 * curve-matches-variant contract before the platform does). The check is
 * shallow and fail-closed: one DER length decode (`spkiAlgorithmOffset`),
 * then a byte-compare of the next TLV against the constant. It can only
 * over-reject — whatever it passes still gets the platform's full DER
 * validation, and it never admits or transforms material the platform
 * would refuse. The Wycheproof `UnnamedCurve` family (the conformance ECDH
 * suites) is its vector coverage.
 * @param {string} namedCurve
 * @param {Uint8Array} spki
 */
function requireNamedCurveSpki(namedCurve, spki) {
  const algorithm = EC_SPKI_ALGORITHM_IDENTIFIERS[namedCurve];
  const offset = spkiAlgorithmOffset(spki);
  if (offset === 0 || !algorithm.every((byte, i) => spki[offset + i] === byte)) {
    throw errInvalidKey(`${namedCurve} SPKI must name the curve by OID`);
  }
}

/**
 * The DER AlgorithmIdentifier TLV an RSA SubjectPublicKeyInfo must open
 * with: `SEQUENCE { rsaEncryption (1.2.840.113549.1.1.1), NULL }` — the
 * form the platform's own RSA SPKI exports carry, for RSASSA-PKCS1-v1_5
 * and RSA-PSS keys alike.
 */
// 300d06092a864886f70d0101010500
const RSA_SPKI_ALGORITHM_IDENTIFIER = Uint8Array.from([
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
]);

/**
 * Guard: rejects an RSA SubjectPublicKeyInfo whose AlgorithmIdentifier is
 * not the `rsaEncryption` form before the platform sees it. The RSA family
 * admission contract (see `wit/rsa.wit`) pins rejection of SPKIs carrying
 * `id-RSASSA-PSS` parameters as `invalid-key`, and this enforces it
 * uniformly regardless of engine behavior. The check is shallow and
 * fail-closed like `requireNamedCurveSpki`: one DER length decode, then a
 * byte-compare of the AlgorithmIdentifier TLV against the constant. It can
 * only over-reject — whatever it passes still gets the platform's full DER
 * validation.
 * @param {Uint8Array} spki
 */
function requireRsaEncryptionSpki(spki) {
  const offset = spkiAlgorithmOffset(spki);
  if (
    offset === 0 ||
    !RSA_SPKI_ALGORITHM_IDENTIFIER.every((byte, i) => spki[offset + i] === byte)
  ) {
    throw errInvalidKey("RSA SPKI must carry the rsaEncryption AlgorithmIdentifier");
  }
}

/**
 * Import an ECDH public key from a SubjectPublicKeyInfo. The
 * AlgorithmIdentifier must be the declared curve's named-OID form (see
 * `requireNamedCurveSpki`); past that check the import is a platform
 * pass-through — the platform validates the DER, rejects a curve that
 * disagrees with the declared variant's, and rejects a point not on the
 * curve.
 * @param {string} variant
 * @param {Uint8Array} spki
 */
async function importEcdhPublicKeySpki(variant, spki) {
  const entry = ecdhCurve(variant);
  requireNamedCurveSpki(entry.namedCurve, spki);
  const key = await importPlatformKey(
    `${variant} spki`,
    "spki",
    spki,
    { name: "ECDH", namedCurve: entry.namedCurve },
    true,
    [],
  );
  return new AgreementPublicKey(MINT, key);
}

/**
 * Import an ECDH public key from an EC public JWK — a platform
 * pass-through of the material members; the platform owns the
 * kty/crv/ext/coordinate validation (including crv-against-`namedCurve`
 * and on-curve). Strictness of the base64url coordinates is pinned
 * host-side.
 * @param {string} variant
 * @param {string} jwkText
 */
async function importEcdhPublicKeyJwk(variant, jwkText) {
  const entry = ecdhCurve(variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.y);
  const key = await importPlatformKeyJwk(
    `${variant} public JWK`,
    jwk,
    { name: "ECDH", namedCurve: entry.namedCurve },
    true,
    [],
  );
  return new AgreementPublicKey(MINT, key);
}

/**
 * Import an ECDH secret key from an EC private JWK (the
 * `ecdh.import-secret-key-jwk` contract). The parse and validation are the
 * platform's (`kty`, `crv` against the declared variant's curve, the
 * mandatory `x`/`y`, `d`-in-range, `ext` against extractability);
 * `use`/`key_ops` are stripped as the JWK contract requires, and
 * strictness of the base64url members is pinned host-side. This host
 * cannot promise the `x`/`y`-against-`d` consistency check (the WIT MAY)
 * — engines differ — and per the MUST NOT it never trusts `x`/`y`: the
 * platform derives operations from `d`.
 * @param {string} variant
 * @param {string} jwkText
 * @param {AgreementKeyOptions} options
 */
async function importEcdhSecretKeyJwk(variant, jwkText, options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const entry = ecdhCurve(variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.y);
  requireStrictBase64url(jwk.d);
  const key = await importPlatformKeyJwk(
    `${variant} private JWK`,
    jwk,
    { name: "ECDH", namedCurve: entry.namedCurve },
    policy.extractable,
    AGREEMENT_PLATFORM_USAGES,
  );
  if (key.type !== "private") {
    throw errInvalidKey("EC private JWK must carry `d` (base64url private scalar)");
  }
  return new AgreementSecretKey(MINT, key, { ...policy });
}

/**
 * Import an ECDH secret key from a PKCS#8 PrivateKeyInfo — a platform
 * pass-through; the platform owns the DER validation, including the
 * encoded-curve-against-variant check.
 * @param {string} variant
 * @param {Uint8Array} pkcs8
 * @param {AgreementKeyOptions} options
 */
async function importEcdhSecretKeyPkcs8(variant, pkcs8, options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const entry = ecdhCurve(variant);
  const key = await importPlatformKey(
    `${variant} pkcs8`,
    "pkcs8",
    pkcs8,
    { name: "ECDH", namedCurve: entry.namedCurve },
    policy.extractable,
    AGREEMENT_PLATFORM_USAGES,
  );
  return new AgreementSecretKey(MINT, key, { ...policy });
}

/**
 * Generate a fresh ECDH key pair on the declared variant's curve,
 * returning `[secret, public]`.
 * @param {string} variant
 * @param {AgreementKeyOptions} options
 * @returns {Promise<[AgreementSecretKey, AgreementPublicKey]>}
 */
async function generateEcdhKey(variant, options) {
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const entry = ecdhCurve(variant);
  const pair = /** @type {CryptoKeyPair} */ (
    await platformCall(`${variant} key generation`, () =>
      subtle.generateKey(
        { name: "ECDH", namedCurve: entry.namedCurve },
        policy.extractable,
        AGREEMENT_PLATFORM_USAGES,
      ),
    )
  );
  return [
    new AgreementSecretKey(MINT, pair.privateKey, { ...policy }),
    new AgreementPublicKey(MINT, pair.publicKey),
  ];
}

/**
 * Mint an ECDH secret key of the declared variant from unwrapped key
 * material read as an EC private JWK (the `ecdh.unwrap-secret-key-jwk`
 * contract): the unwrap-path `use`/`key_ops` checks, then
 * `import-secret-key-jwk`'s path with `invalid-key` details redacted (see
 * `redactingInvalidKey`).
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {AgreementKeyOptions} options
 */
async function unwrapEcdhSecretKeyJwk(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  const policy = agreementPolicy(options);
  requireAgreementGrant(policy);
  const jwk = unwrappedJwk(bytes, "enc", agreementGrantedOps(policy));
  return redactingInvalidKey(`unwrapped ${variant} private JWK`, () =>
    importEcdhSecretKeyJwk(variant, jwk, options),
  );
}

/**
 * Mint an ECDH secret key of the declared variant from unwrapped key
 * material read as a PKCS#8 PrivateKeyInfo: `import-secret-key-pkcs8`'s
 * path, redacted like the JWK mint.
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {AgreementKeyOptions} options
 */
async function unwrapEcdhSecretKeyPkcs8(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey(`unwrapped ${variant} pkcs8`, () =>
    importEcdhSecretKeyPkcs8(variant, bytes, options),
  );
}

/** The `polymorph:webcrypto/ecdh` interface. */
export const ecdh = {
  importPublicKeyRaw: importEcdhPublicKey,
  importPublicKeySpki: importEcdhPublicKeySpki,
  importPublicKeyJwk: importEcdhPublicKeyJwk,
  importSecretKeyJwk: importEcdhSecretKeyJwk,
  importSecretKeyPkcs8: importEcdhSecretKeyPkcs8,
  generateKey: generateEcdhKey,
  unwrapSecretKeyJwk: unwrapEcdhSecretKeyJwk,
  unwrapSecretKeyPkcs8: unwrapEcdhSecretKeyPkcs8,
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

/** The `polymorph:webcrypto/digest` interface: its resource class. */
export const digest = { Digest };

/** The `polymorph:webcrypto/sha2` interface. */
export const sha2 = { makeDigest };

/**
 * Throw `{ tag: 'unsupported', val }` for checked SHA-1: the platform's
 * SHA-1 carries no sha1dc collision detection, this host is constrained
 * to `crypto.subtle`, and implementing the counter-cryptanalysis in host
 * JS is against its platform-backed charter — so it declines the
 * interface whole, and a composition needing it must supply
 * another provider (the in-guest provider serves both postures).
 * @returns {never}
 */
function unsupportedSha1Checked() {
  throw errUnsupported("sha1-checked is not served by this implementation");
}

/** The `polymorph:webcrypto/sha1-checked` interface. */
export const sha1Checked = {
  makeRejectingDigest: () => unsupportedSha1Checked(),
  makeMitigatingDigest: () => unsupportedSha1Checked(),
};

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
 * The WebCrypto usages for an AEAD mint policy, throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant. The WIT grants do not
 * map onto the platform's usages one-to-one: `wrap` runs `subtle.encrypt`
 * and `unwrap` runs `subtle.decrypt` (see `aeadKeyGrants`), so the
 * platform key carries `encrypt` if (seal or wrap) and `decrypt` if (open
 * or unwrap), and every WIT grant is enforced host-side against the
 * recorded policy.
 * @param {{ seal: boolean, open: boolean, wrap: boolean, unwrap: boolean }} policy
 * @returns {KeyUsage[]}
 */
function aeadUsages(policy) {
  /** @type {KeyUsage[]} */
  const usages = [];
  if (policy.seal || policy.wrap) usages.push("encrypt");
  if (policy.open || policy.unwrap) usages.push("decrypt");
  if (usages.length === 0) {
    throw errNotPermitted("a key with no enabled usage cannot be minted");
  }
  return usages;
}

/**
 * The WIT-level grants of an AEAD mint policy, as recorded on the minted
 * key (see `aeadKeyGrants`).
 * @param {{ seal: boolean, open: boolean, wrap: boolean, unwrap: boolean }} policy
 */
function aeadGrants(policy) {
  return {
    seal: policy.seal,
    open: policy.open,
    wrap: policy.wrap,
    unwrap: policy.unwrap,
  };
}

/**
 * The granted operations' platform names for an AEAD mint policy (the
 * unwrap-path `key_ops` rule): the one-to-one names — `seal` →
 * `"encrypt"`, `open` → `"decrypt"`, `wrap`/`unwrap` →
 * `"wrapKey"`/`"unwrapKey"` — unlike `aeadUsages`, whose collapsed pairs
 * serve the platform key.
 * @param {{ seal: boolean, open: boolean, wrap: boolean, unwrap: boolean }} policy
 */
function aeadGrantedOps(policy) {
  const ops = [];
  if (policy.seal) ops.push("encrypt");
  if (policy.open) ops.push("decrypt");
  if (policy.wrap) ops.push("wrapKey");
  if (policy.unwrap) ops.push("unwrapKey");
  return ops;
}

/** The `polymorph:webcrypto/aead` interface: its resource classes. */
export const aead = { AeadKey, AeadKeyOptions };

/** The `polymorph:webcrypto/aes-gcm` interface. */
export const aesGcm = {
  /**
   * Import raw key material as the declared AES variant. A variant this
   * implementation declines throws `{ tag: 'unsupported', val }`;
   * material whose length disagrees with `variant` throws
   * `{ tag: 'invalid-key', val }`.
   * @param {string} variant
   * @param {Uint8Array} raw
   * @param {AeadKeyOptions} options
   */
  async importKeyRaw(variant, raw, options) {
    const policy = aeadPolicy(options);
    const usages = aeadUsages(policy);
    const expected = aesVariantByteLength(variant);
    if (raw.length !== expected) {
      throw errInvalidKey(`${variant} requires ${expected} key bytes, got ${raw.length}`);
    }
    const key = await importPlatformKey(
      `${variant} key`,
      "raw",
      raw,
      { name: "AES-GCM" },
      policy.extractable,
      usages,
    );
    return new AeadKey(key, expected * 8, aeadGrants(policy));
  },

  /**
   * Import an `oct` JWK as the declared AES variant (the
   * `import-key-jwk` contract). The platform
   * validates the JWK's internal consistency (`kty`, strict base64url
   * `k`, `alg` against `k`'s length, `ext` against the options'
   * extractability); the variant check is against the imported key's
   * platform-computed length, since the platform cannot know the
   * declared variant.
   * @param {string} variant
   * @param {string} jwk
   * @param {AeadKeyOptions} options
   */
  async importKeyJwk(variant, jwk, options) {
    const policy = aeadPolicy(options);
    const usages = aeadUsages(policy);
    const lengthBits = aesVariantByteLength(variant) * 8;
    const material = jwkMaterial(jwk);
    requireStrictBase64url(material.k);
    const key = await importPlatformKeyJwk(
      `${variant} JWK`,
      material,
      { name: "AES-GCM" },
      policy.extractable,
      usages,
    );
    // The variant check derives from `k` (exact once the platform
    // accepted the encoding), not `key.algorithm.length`, which an
    // engine may omit for an imported key (see `MacKey`'s field doc).
    const gotBits = jwkKeyBytes(material.k) * 8;
    if (gotBits !== lengthBits) {
      throw errInvalidKey(
        `JWK carries a ${gotBits}-bit key; ${variant} requires ${lengthBits}`,
      );
    }
    return new AeadKey(key, lengthBits, aeadGrants(policy));
  },

  /**
   * Generate a fresh random AES key of the declared variant. A variant
   * this implementation declines throws `{ tag: 'unsupported', val }`.
   * @param {string} variant
   * @param {AeadKeyOptions} options
   */
  async generateKey(variant, options) {
    const policy = aeadPolicy(options);
    const usages = aeadUsages(policy);
    const length = aesVariantByteLength(variant) * 8;
    const key = await platformCall(`${variant} key generation`, () =>
      subtle.generateKey({ name: "AES-GCM", length }, policy.extractable, usages),
    );
    return new AeadKey(key, length, aeadGrants(policy));
  },

  /**
   * Mint a key from unwrapped material read as raw bytes (see the
   * `wrapping` interface): the `import-key-raw` path over the consumed
   * input's bytes, with `invalid-key` details redacted (see
   * `redactingInvalidKey`).
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {AeadKeyOptions} options
   */
  async unwrapKeyRaw(variant, input, options) {
    const { bytes } = consumeUnwrapInput(input);
    return redactingInvalidKey(`unwrapped ${variant} key material`, () =>
      aesGcm.importKeyRaw(variant, bytes, options),
    );
  },

  /**
   * Mint a key from unwrapped material read as an `oct` JWK: the
   * unwrap-path `use`/`key_ops` checks (see `unwrappedJwk`), then the
   * `import-key-jwk` path, redacted like `unwrapKeyRaw`.
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {AeadKeyOptions} options
   */
  async unwrapKeyJwk(variant, input, options) {
    const { bytes } = consumeUnwrapInput(input);
    const policy = aeadPolicy(options);
    aeadUsages(policy);
    const jwk = unwrappedJwk(bytes, "enc", aeadGrantedOps(policy));
    return redactingInvalidKey(`unwrapped ${variant} JWK`, () =>
      aesGcm.importKeyJwk(variant, jwk, options),
    );
  },

  /**
   * Mint an AES-GCM key from a parameterized derivation (the
   * `aes-gcm.derive-key` contract): the platform's `deriveKey` chain, at
   * the variant's key length. A variant this implementation declines
   * throws `{ tag: 'unsupported', val }`.
   * @param {string} variant
   * @param {DeriveInput} input
   * @param {AeadKeyOptions} options
   */
  async deriveKey(variant, input, options) {
    const policy = aeadPolicy(options);
    const usages = aeadUsages(policy);
    const bits = aesVariantByteLength(variant) * 8;
    const key = await deriveKeyFrom(
      input,
      { name: "AES-GCM", length: bits },
      policy.extractable,
      usages,
    );
    return new AeadKey(key, bits, aeadGrants(policy));
  },
};

/** @type {WeakMap<CipherKeyOptions, { encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean, extractable: boolean }>} */
const cipherPolicies = new WeakMap();

const cipherPolicy = stateReader(cipherPolicies, "cipher-key-options");

export class CipherKeyOptions {
  constructor() {
    cipherPolicies.set(this, {
      encrypt: false,
      decrypt: false,
      wrap: false,
      unwrap: false,
      extractable: false,
    });
  }

  /** @param {boolean} allowed */
  canEncrypt(allowed) {
    cipherPolicy(this).encrypt = allowed;
  }

  /** @param {boolean} allowed */
  canDecrypt(allowed) {
    cipherPolicy(this).decrypt = allowed;
  }

  /** @param {boolean} allowed */
  canWrap(allowed) {
    cipherPolicy(this).wrap = allowed;
  }

  /** @param {boolean} allowed */
  canUnwrap(allowed) {
    cipherPolicy(this).unwrap = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    cipherPolicy(this).extractable = allowed;
  }
}

/**
 * The WebCrypto usages for a cipher mint policy, throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant. As on `aeadUsages`,
 * the WIT grants do not map onto the platform's usages one-to-one: `wrap`
 * runs `subtle.encrypt` and `unwrap` runs `subtle.decrypt` (see
 * `cipherKeyGrants`), so the platform key carries `encrypt` if (encrypt or
 * wrap) and `decrypt` if (decrypt or unwrap).
 * @param {{ encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean }} policy
 * @returns {KeyUsage[]}
 */
function cipherUsages(policy) {
  /** @type {KeyUsage[]} */
  const usages = [];
  if (policy.encrypt || policy.wrap) usages.push("encrypt");
  if (policy.decrypt || policy.unwrap) usages.push("decrypt");
  if (usages.length === 0) {
    throw errNotPermitted("a key with no enabled usage cannot be minted");
  }
  return usages;
}

/**
 * The WIT-level grants of a cipher mint policy, as recorded on the minted
 * key (see `cipherKeyGrants`).
 * @param {{ encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean }} policy
 */
function cipherGrants(policy) {
  return {
    encrypt: policy.encrypt,
    decrypt: policy.decrypt,
    wrap: policy.wrap,
    unwrap: policy.unwrap,
  };
}

/**
 * The granted operations' platform names for a cipher mint policy (the
 * unwrap-path `key_ops` rule; see `aeadGrantedOps`).
 * @param {{ encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean }} policy
 */
function cipherGrantedOps(policy) {
  const ops = [];
  if (policy.encrypt) ops.push("encrypt");
  if (policy.decrypt) ops.push("decrypt");
  if (policy.wrap) ops.push("wrapKey");
  if (policy.unwrap) ops.push("unwrapKey");
  return ops;
}

/**
 * Validate a `cipher-key` operation's per-call parameters against the
 * key's mode (the WIT `cipher-key.encrypt` contract) and build the
 * platform params object.
 * @param {"AES-CBC" | "AES-CTR"} name
 * @param {Uint8Array} iv
 * @param {number | undefined} counterLength
 * @returns {AesCbcParams | AesCtrParams}
 */
function cipherParams(name, iv, counterLength) {
  if (name === "AES-CBC" && counterLength !== undefined) {
    throw errInvalidNonce("AES-CBC takes no counter length");
  }
  if (name === "AES-CTR") {
    if (counterLength === undefined) {
      throw errInvalidNonce("AES-CTR requires a counter length");
    }
    if (counterLength === 0 || counterLength > 128) {
      throw errInvalidNonce(`the counter length must be 1 to 128 bits, got ${counterLength}`);
    }
  }
  if (iv.length !== 16) {
    throw errInvalidNonce(`${name} requires a 16-byte IV, got ${iv.length} bytes`);
  }
  return name === "AES-CBC"
    ? { name, iv: asBufferSource(iv) }
    : { name, counter: asBufferSource(iv), length: /** @type {number} */ (counterLength) };
}

/**
 * The usage grants recorded at mint for each `cipher-key` (the
 * `aeadKeyGrants` pattern: `wrap`/`unwrap` run through the platform's
 * `encrypt`/`decrypt`, so the WIT grants are enforced host-side).
 * @type {WeakMap<CipherKey, { encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean }>}
 */
const cipherKeyGrants = new WeakMap();

const cipherGrantsOf = stateReader(cipherKeyGrants, "cipher-key");

/**
 * The `cipher-key` resource: an unauthenticated AES-CBC or AES-CTR key
 * (see the WIT `cipher` interface's Security notes — nothing here
 * authenticates). Holds a `CryptoKey` whose platform usages cover the
 * operations its mint options granted (see `cipherKeyGrants`); instances
 * are minted only by the `aes-cbc` and `aes-ctr` interface functions
 * below.
 */
export class CipherKey extends symmetricKeyTail({}) {
  /** @type {"AES-CBC" | "AES-CTR"} */
  #name;
  /** The key length in bits, fixed at mint (see `AeadKey.#lengthBits`). */
  #lengthBits;

  /**
   * @param {CryptoKey} key
   * @param {"AES-CBC" | "AES-CTR"} name
   * @param {number} lengthBits
   * @param {{ encrypt: boolean, decrypt: boolean, wrap: boolean, unwrap: boolean }} grants
   */
  constructor(key, name, lengthBits, grants) {
    super(key);
    this.#name = name;
    this.#lengthBits = lengthBits;
    cipherKeyGrants.set(this, grants);
  }

  /**
   * Encrypt the plaintext stream under `iv` (the WIT
   * `cipher-key.encrypt` contract). The plaintext stream is drained
   * before any failure is raised.
   * @param {Uint8Array} iv
   * @param {number | undefined} counterLength
   * @param {AsyncIterable<unknown> | ReadableStream} plaintext
   */
  async encrypt(iv, counterLength, plaintext) {
    return withCollectedInputToStream(plaintext, async (message) => {
      if (!this.canEncrypt()) throw notPermitted("encrypt");
      const params = cipherParams(this.#name, iv, counterLength);
      const sealed = await platformCall(`${this.#name} encrypt`, () =>
        subtle.encrypt(params, platformKeyOf(this), message),
      );
      return new Uint8Array(sealed);
    });
  }

  /**
   * Decrypt the ciphertext stream under `iv`. Every malformed-input
   * failure is one uniform `{ tag: 'other' }` per the WIT contract: a
   * distinguishable padding verdict is a padding-oracle amplifier, so
   * nothing separates bad padding from any other malformation. The
   * ciphertext stream is drained before any failure is raised.
   * @param {Uint8Array} iv
   * @param {number | undefined} counterLength
   * @param {AsyncIterable<unknown> | ReadableStream} ciphertext
   */
  async decrypt(iv, counterLength, ciphertext) {
    return withCollectedInputToStream(ciphertext, async (message) => {
      if (!this.canDecrypt()) throw notPermitted("decrypt");
      const params = cipherParams(this.#name, iv, counterLength);
      let opened;
      try {
        opened = await subtle.decrypt(params, platformKeyOf(this), message);
      } catch {
        throw errOther(`${this.#name} decryption failed`);
      }
      return new Uint8Array(opened);
    });
  }

  /**
   * Encrypt serialized key material under `iv`, exactly as `encrypt`
   * encrypts a message (the `iv`/`counterLength` contracts and their
   * error cases are `encrypt`'s). `input` is consumed first, on failure
   * as on success. Throws `{ tag: 'not-permitted' }` on a key minted
   * without the `wrap` grant.
   * @param {Uint8Array} iv
   * @param {number | undefined} counterLength
   * @param {WrapInput} input
   * @returns {Promise<Uint8Array>}
   */
  async wrap(iv, counterLength, input) {
    const { bytes } = consumeWrapInput(input);
    if (!this.canWrap()) throw notPermitted("wrap");
    const params = cipherParams(this.#name, iv, counterLength);
    const sealed = await platformCall(`${this.#name} wrap`, () =>
      subtle.encrypt(params, platformKeyOf(this), asBufferSource(bytes)),
    );
    return new Uint8Array(sealed);
  }

  /**
   * Decrypt wrapped key material under `iv`, eagerly (this host does not
   * use the WIT's deferral latitude). The result is *unauthenticated*,
   * and every malformed-input failure is one uniform `{ tag: 'other' }`,
   * exactly as on `decrypt`. Throws `{ tag: 'not-permitted' }` on a key
   * minted without the `unwrap` grant.
   * @param {Uint8Array} iv
   * @param {number | undefined} counterLength
   * @param {Uint8Array} wrapped
   * @returns {Promise<UnwrapInput>}
   */
  async unwrap(iv, counterLength, wrapped) {
    if (!this.canUnwrap()) throw notPermitted("unwrap");
    const params = cipherParams(this.#name, iv, counterLength);
    let opened;
    try {
      opened = await subtle.decrypt(params, platformKeyOf(this), asBufferSource(wrapped));
    } catch {
      throw errOther(`${this.#name} decryption failed`);
    }
    return new UnwrapInput(MINT, new Uint8Array(opened));
  }

  algorithmName() {
    return this.#name;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  ivSize() {
    return 16;
  }

  /** The usage grants: the mint policy recorded in `cipherKeyGrants`. */
  canEncrypt() {
    return cipherGrantsOf(this).encrypt;
  }

  canDecrypt() {
    return cipherGrantsOf(this).decrypt;
  }

  canWrap() {
    return cipherGrantsOf(this).wrap;
  }

  canUnwrap() {
    return cipherGrantsOf(this).unwrap;
  }

  /**
   * This key's raw material as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyRaw`.
   */
  async toWrapInputRaw() {
    return new WrapInput(MINT, "raw", await exportRawGated(platformKeyOf(this)));
  }

  /**
   * The JWK serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputJwk() {
    const jwk = await exportJwkGated(platformKeyOf(this));
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(jwk));
  }
}

/**
 * The `aes-cbc` / `aes-ctr` minting pair over one mode name: the two
 * interfaces share the whole minting contract and differ only in the
 * algorithm the platform keys bind (the `aesGcm` pattern).
 * @param {"AES-CBC" | "AES-CTR"} name
 */
function cipherMinting(name) {
  const minting = {
    /**
     * Import raw key material as the declared AES variant (the shared
     * `import-key-raw` contract; see `aesGcm`'s).
     * @param {string} variant
     * @param {Uint8Array} raw
     * @param {CipherKeyOptions} options
     */
    async importKeyRaw(variant, raw, options) {
      const policy = cipherPolicy(options);
      const usages = cipherUsages(policy);
      const expected = aesVariantByteLength(variant);
      if (raw.length !== expected) {
        throw errInvalidKey(`${variant} requires ${expected} key bytes, got ${raw.length}`);
      }
      const key = await importPlatformKey(
        `${variant} key`,
        "raw",
        raw,
        { name },
        policy.extractable,
        usages,
      );
      return new CipherKey(key, name, expected * 8, cipherGrants(policy));
    },

    /**
     * Import an `oct` JWK as the declared AES variant (the shared
     * `import-key-jwk` contract; see `aesGcm`'s).
     * @param {string} variant
     * @param {string} jwk
     * @param {CipherKeyOptions} options
     */
    async importKeyJwk(variant, jwk, options) {
      const policy = cipherPolicy(options);
      const usages = cipherUsages(policy);
      const lengthBits = aesVariantByteLength(variant) * 8;
      const material = jwkMaterial(jwk);
      requireStrictBase64url(material.k);
      const key = await importPlatformKeyJwk(
        `${variant} JWK`,
        material,
        { name },
        policy.extractable,
        usages,
      );
      const gotBits = jwkKeyBytes(material.k) * 8;
      if (gotBits !== lengthBits) {
        throw errInvalidKey(`JWK carries a ${gotBits}-bit key; ${variant} requires ${lengthBits}`);
      }
      return new CipherKey(key, name, lengthBits, cipherGrants(policy));
    },

    /**
     * Generate a fresh random AES key of the declared variant.
     * @param {string} variant
     * @param {CipherKeyOptions} options
     */
    async generateKey(variant, options) {
      const policy = cipherPolicy(options);
      const usages = cipherUsages(policy);
      const bits = aesVariantByteLength(variant) * 8;
      const key = /** @type {CryptoKey} */ (
        await platformCall(`${variant} key generation`, () =>
          subtle.generateKey({ name, length: bits }, policy.extractable, usages),
        )
      );
      return new CipherKey(key, name, bits, cipherGrants(policy));
    },

    /**
     * Mint a key from a parameterized derivation (the shared `derive-key`
     * contract): the platform's `deriveKey` chain, at the variant's key
     * length.
     * @param {string} variant
     * @param {DeriveInput} input
     * @param {CipherKeyOptions} options
     */
    async deriveKey(variant, input, options) {
      const policy = cipherPolicy(options);
      const usages = cipherUsages(policy);
      const bits = aesVariantByteLength(variant) * 8;
      const key = await deriveKeyFrom(input, { name, length: bits }, policy.extractable, usages);
      return new CipherKey(key, name, bits, cipherGrants(policy));
    },

    /**
     * Mint a key from unwrapped material read as raw bytes (see
     * `aesGcm.unwrapKeyRaw`).
     * @param {string} variant
     * @param {UnwrapInput} input
     * @param {CipherKeyOptions} options
     */
    async unwrapKeyRaw(variant, input, options) {
      const { bytes } = consumeUnwrapInput(input);
      return redactingInvalidKey(`unwrapped ${variant} key material`, () =>
        minting.importKeyRaw(variant, bytes, options),
      );
    },

    /**
     * Mint a key from unwrapped material read as an `oct` JWK (see
     * `aesGcm.unwrapKeyJwk`).
     * @param {string} variant
     * @param {UnwrapInput} input
     * @param {CipherKeyOptions} options
     */
    async unwrapKeyJwk(variant, input, options) {
      const { bytes } = consumeUnwrapInput(input);
      const policy = cipherPolicy(options);
      cipherUsages(policy);
      const jwk = unwrappedJwk(bytes, "enc", cipherGrantedOps(policy));
      return redactingInvalidKey(`unwrapped ${variant} JWK`, () =>
        minting.importKeyJwk(variant, jwk, options),
      );
    },
  };
  return minting;
}

/** The `polymorph:webcrypto/cipher` interface: its resource classes. */
export const cipher = { CipherKey, CipherKeyOptions };

/** The `polymorph:webcrypto/aes-cbc` interface. */
export const aesCbc = cipherMinting("AES-CBC");

/** The `polymorph:webcrypto/aes-ctr` interface. */
export const aesCtr = cipherMinting("AES-CTR");

/** @type {WeakMap<KwKeyOptions, { wrap: boolean, unwrap: boolean, extractable: boolean }>} */
const kwPolicies = new WeakMap();

const kwPolicy = stateReader(kwPolicies, "kw-key-options");

export class KwKeyOptions {
  constructor() {
    kwPolicies.set(this, { wrap: false, unwrap: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canWrap(allowed) {
    kwPolicy(this).wrap = allowed;
  }

  /** @param {boolean} allowed */
  canUnwrap(allowed) {
    kwPolicy(this).unwrap = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    kwPolicy(this).extractable = allowed;
  }
}

/**
 * The WebCrypto usages for a KW mint policy — one-to-one, since
 * `wrapKey`/`unwrapKey` are exactly the operations an AES-KW platform key
 * serves — throwing `{ tag: 'not-permitted' }` for a zero-usage grant.
 * @param {{ wrap: boolean, unwrap: boolean }} policy
 */
function kwUsages(policy) {
  return grantedUsages([
    ["wrapKey", policy.wrap],
    ["unwrapKey", policy.unwrap],
  ]);
}

/**
 * The granted operations' platform names for a KW mint policy (the
 * unwrap-path `key_ops` rule): the same one-to-one names as `kwUsages`,
 * without the at-least-one-usage throw.
 * @param {{ wrap: boolean, unwrap: boolean }} policy
 */
function kwGrantedOps(policy) {
  const ops = [];
  if (policy.wrap) ops.push("wrapKey");
  if (policy.unwrap) ops.push("unwrapKey");
  return ops;
}

/**
 * The mint policy recorded for each `kw-key` (the `aeadKeyGrants`
 * pattern, stored whole for uniformity even though the platform usages
 * carry the same pair).
 * @type {WeakMap<KwKey, { wrap: boolean, unwrap: boolean, extractable: boolean }>}
 */
const kwKeyGrants = new WeakMap();

const kwGrantsOf = stateReader(kwKeyGrants, "kw-key");

/**
 * The `key-wrap.kw-key` resource: an AES-KW key (RFC 3394; NIST SP
 * 800-38F's KW). The platform's AES-KW operations wrap and unwrap
 * `CryptoKey`s, not bytes, so both directions run the material through a
 * throwaway HMAC-SHA-256 `CryptoKey`, whose "raw" import/export accepts
 * any non-empty length: `wrap` imports the serialized material and
 * `subtle.wrapKey`s it; `unwrap` `subtle.unwrapKey`s into one and exports
 * its raw bytes into the minted `unwrap-input`. The wrapped wire format is
 * RFC 3394's either way. Instances are minted only by the `aes-kw`
 * interface functions below.
 */
export class KwKey {
  #key;
  /** The key length in bits, fixed at mint (see `AeadKey.#lengthBits`). */
  #lengthBits;

  /**
   * @param {CryptoKey} key
   * @param {number} lengthBits
   * @param {{ wrap: boolean, unwrap: boolean, extractable: boolean }} grants
   */
  constructor(key, lengthBits, grants) {
    this.#key = key;
    this.#lengthBits = lengthBits;
    kwKeyGrants.set(this, grants);
  }

  /**
   * Encrypt serialized key material (RFC 3394). JWK-format material is
   * first padded with ASCII spaces (0x20) to a multiple of 8 bytes — the
   * `aes-kw` WIT contract; the JWK contract's trailing-space tolerance
   * carries the round trip. Material outside the algorithm's input
   * domain — not a multiple of 8 bytes, or shorter than 16 — throws
   * `{ tag: 'invalid-key' }` with a fixed message (the material is not
   * the caller's to see). `input` is consumed first, on failure as on
   * success; throws `{ tag: 'not-permitted' }` without the `wrap` grant.
   * @param {WrapInput} input
   * @returns {Promise<Uint8Array>}
   */
  async wrap(input) {
    const state = consumeWrapInput(input);
    if (!this.canWrap()) throw notPermitted("wrap");
    let bytes = state.bytes;
    if (state.format === "jwk" && bytes.length % 8 !== 0) {
      const padded = new Uint8Array(bytes.length + 8 - (bytes.length % 8));
      padded.set(bytes);
      padded.fill(0x20, bytes.length);
      bytes = padded;
    }
    if (bytes.length % 8 !== 0 || bytes.length < 16) {
      throw errInvalidKey("AES-KW wraps key material of at least 16 bytes, a multiple of 8");
    }
    const trampoline = await platformCall("AES-KW wrap", () =>
      subtle.importKey("raw", asBufferSource(bytes), { name: "HMAC", hash: "SHA-256" }, true, [
        "sign",
      ]),
    );
    const wrapped = await platformCall("AES-KW wrap", () =>
      subtle.wrapKey("raw", trampoline, this.#key, "AES-KW"),
    );
    return new Uint8Array(wrapped);
  }

  /**
   * Decrypt and integrity-check wrapped key material, eagerly (this host
   * does not use the WIT's deferral latitude). Input that cannot carry
   * the RFC 3394 wire format — not a multiple of 8 bytes, or shorter
   * than 24 — throws `{ tag: 'authentication-failed' }` with no detail,
   * indistinguishable from an ICV failure, before the platform is asked.
   * Throws `{ tag: 'not-permitted' }` without the `unwrap` grant.
   * @param {Uint8Array} wrapped
   * @returns {Promise<UnwrapInput>}
   */
  async unwrap(wrapped) {
    if (!this.canUnwrap()) throw notPermitted("unwrap");
    if (wrapped.length % 8 !== 0 || wrapped.length < 24) {
      throw errAuthenticationFailed();
    }
    let trampoline;
    try {
      trampoline = await subtle.unwrapKey(
        "raw",
        asBufferSource(wrapped),
        this.#key,
        "AES-KW",
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign"],
      );
    } catch (err) {
      throw decryptFailure(err, "unwrap");
    }
    const bytes = new Uint8Array(
      await platformCall("AES-KW unwrap", () => subtle.exportKey("raw", trampoline)),
    );
    return new UnwrapInput(MINT, bytes);
  }

  /**
   * The algorithm getters: `name` projects the `CryptoKey` (`"AES-KW"`),
   * `length` comes from the mint (see `AeadKey.#lengthBits`).
   */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmLength() {
    return this.#lengthBits;
  }

  /** The mint policy getters: the record in `kwKeyGrants`. */
  extractable() {
    return kwGrantsOf(this).extractable;
  }

  canWrap() {
    return kwGrantsOf(this).wrap;
  }

  canUnwrap() {
    return kwGrantsOf(this).unwrap;
  }

  /**
   * The raw key material. Throws `{ tag: 'not-extractable' }` unless the
   * key was created with `extractable` true (see `exportRawGated`).
   */
  async exportKeyRaw() {
    return exportRawGated(this.#key);
  }

  /**
   * The key as an `oct` JWK (`alg` `"A128KW"`/`"A256KW"`, the platform's),
   * behind the same extractability gate as `exportKeyRaw`.
   */
  async exportKeyJwk() {
    return exportJwkGated(this.#key);
  }

  /**
   * This key's raw material as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyRaw`.
   */
  async toWrapInputRaw() {
    return new WrapInput(MINT, "raw", await exportRawGated(this.#key));
  }

  /**
   * The JWK serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputJwk() {
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(await exportJwkGated(this.#key)));
  }
}

/** The `polymorph:webcrypto/key-wrap` interface: its resource classes. */
export const keyWrap = { KwKey, KwKeyOptions };

/**
 * The `polymorph:webcrypto/aes-kw` interface: the `aesGcm`/`cipherMinting`
 * minting contract at `AES-KW`.
 */
export const aesKw = {
  /**
   * Import raw key material as the declared AES variant (the shared
   * `import-key-raw` contract; see `aesGcm`'s).
   * @param {string} variant
   * @param {Uint8Array} raw
   * @param {KwKeyOptions} options
   */
  async importKeyRaw(variant, raw, options) {
    const policy = kwPolicy(options);
    const usages = kwUsages(policy);
    const expected = aesVariantByteLength(variant);
    if (raw.length !== expected) {
      throw errInvalidKey(`${variant} requires ${expected} key bytes, got ${raw.length}`);
    }
    const key = await importPlatformKey(
      `${variant} key`,
      "raw",
      raw,
      { name: "AES-KW" },
      policy.extractable,
      usages,
    );
    return new KwKey(key, expected * 8, { ...policy });
  },

  /**
   * Import an `oct` JWK as the declared AES variant (the shared
   * `import-key-jwk` contract; see `aesGcm`'s — here the platform
   * additionally validates `alg`, when present, against the `A___KW`
   * name `k`'s length selects).
   * @param {string} variant
   * @param {string} jwk
   * @param {KwKeyOptions} options
   */
  async importKeyJwk(variant, jwk, options) {
    const policy = kwPolicy(options);
    const usages = kwUsages(policy);
    const lengthBits = aesVariantByteLength(variant) * 8;
    const material = jwkMaterial(jwk);
    requireStrictBase64url(material.k);
    const key = await importPlatformKeyJwk(
      `${variant} JWK`,
      material,
      { name: "AES-KW" },
      policy.extractable,
      usages,
    );
    const gotBits = jwkKeyBytes(material.k) * 8;
    if (gotBits !== lengthBits) {
      throw errInvalidKey(`JWK carries a ${gotBits}-bit key; ${variant} requires ${lengthBits}`);
    }
    return new KwKey(key, lengthBits, { ...policy });
  },

  /**
   * Generate a fresh random AES-KW key of the declared variant.
   * @param {string} variant
   * @param {KwKeyOptions} options
   */
  async generateKey(variant, options) {
    const policy = kwPolicy(options);
    const usages = kwUsages(policy);
    const bits = aesVariantByteLength(variant) * 8;
    const key = /** @type {CryptoKey} */ (
      await platformCall(`${variant} key generation`, () =>
        subtle.generateKey({ name: "AES-KW", length: bits }, policy.extractable, usages),
      )
    );
    return new KwKey(key, bits, { ...policy });
  },

  /**
   * Mint a key from a parameterized derivation (the shared `derive-key`
   * contract; see `aesGcm.deriveKey`).
   * @param {string} variant
   * @param {DeriveInput} input
   * @param {KwKeyOptions} options
   */
  async deriveKey(variant, input, options) {
    const policy = kwPolicy(options);
    const usages = kwUsages(policy);
    const bits = aesVariantByteLength(variant) * 8;
    const key = await deriveKeyFrom(input, { name: "AES-KW", length: bits }, policy.extractable, usages);
    return new KwKey(key, bits, { ...policy });
  },

  /**
   * Mint a key from unwrapped material read as raw bytes (see
   * `aesGcm.unwrapKeyRaw`).
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {KwKeyOptions} options
   */
  async unwrapKeyRaw(variant, input, options) {
    const { bytes } = consumeUnwrapInput(input);
    return redactingInvalidKey(`unwrapped ${variant} key material`, () =>
      aesKw.importKeyRaw(variant, bytes, options),
    );
  },

  /**
   * Mint a key from unwrapped material read as an `oct` JWK (see
   * `aesGcm.unwrapKeyJwk`).
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {KwKeyOptions} options
   */
  async unwrapKeyJwk(variant, input, options) {
    const { bytes } = consumeUnwrapInput(input);
    const policy = kwPolicy(options);
    kwUsages(policy);
    const jwk = unwrappedJwk(bytes, "enc", kwGrantedOps(policy));
    return redactingInvalidKey(`unwrapped ${variant} JWK`, () =>
      aesKw.importKeyJwk(variant, jwk, options),
    );
  },
};

/**
 * Throw `{ tag: 'invalid-nonce', val }` unless the nonce is 12 to 128
 * bytes inclusive — the `aes-gcm` minting contract's portable window. The
 * check is this host's, ahead of the platform: platforms differ on what
 * they serve outside the window, and the contract rejects uniformly.
 * @param {Uint8Array} nonce
 */
function requireGcmNonce(nonce) {
  if (nonce.length < 12 || nonce.length > 128) {
    throw errInvalidNonce(`AES-GCM nonces are 12 to 128 bytes inclusive, got ${nonce.length}`);
  }
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
 * discarded (this host drains to completion rather than exercising the
 * streaming contract's early-close permission) and the operation throws a
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
 * members are tested for presence rather than for being defined. A limit is
 * a byte count: any other present value must be a non-negative finite
 * number, or the call throws `TypeError` with neither limit updated.
 *
 * Raising the pool admits whatever now fits: waiters are judged against the
 * ceiling in force, so without this the new capacity would go unused until
 * some unrelated operation happened to release.
 * @param {{ perCallBufferLimit?: number, totalBufferLimit?: number }} options
 */
export function configure(options = {}) {
  const perCall =
    "perCallBufferLimit" in options
      ? requireLimit("perCallBufferLimit", options.perCallBufferLimit)
      : bufferLimits.perCall;
  const total =
    "totalBufferLimit" in options
      ? requireLimit("totalBufferLimit", options.totalBufferLimit)
      : bufferLimits.total;
  bufferLimits.perCall = perCall;
  bufferLimits.total = total;
  admitFromFront();
}

/**
 * Validate one configured limit. The pool's arithmetic (reserve, compare,
 * release) is only sound over non-negative finite numbers — a `NaN` or
 * `Infinity` reaching `reservedBytes` sticks there and disables every later
 * comparison — so the states a `u64` budget cannot represent are rejected
 * at the boundary. Fractions floor: a reservation is a whole number of
 * bytes.
 * @param {string} name
 * @param {number | undefined} value
 */
function requireLimit(name, value) {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${name} must be a non-negative finite number of bytes`);
  }
  return Math.floor(value);
}

/** The effective `(perCall, total)` limits, clamped like the wasmtime host. */
function effectiveBufferLimits() {
  const total = Math.max(1, bufferLimits.total ?? DEFAULT_TOTAL_BUFFER_LIMIT);
  const perCall = Math.max(1, Math.min(bufferLimits.perCall ?? Math.floor(total / 4), total));
  return { perCall, total };
}

let reservedBytes = 0;
/**
 * Waiters, in arrival order. An entry's `amount` is set under the limits at
 * queue time and only ever clamps down: the ceiling it is judged against is
 * read at admission time, so a `configure` between queueing and admission
 * governs the whole queue rather than splitting it into entries judged
 * against different totals.
 * @type {{ amount: number, resolve: () => void }[]}
 */
const admitQueue = [];

/** Admit queued reservations from the front while they fit (FIFO). */
function admitFromFront() {
  for (;;) {
    const head = admitQueue[0];
    if (head === undefined) return;
    const { perCall, total } = effectiveBufferLimits();
    // The amount was clamped under the limits at queue time; admission
    // judges against the limits in force, and an amount above a since-
    // lowered total could never fit it — wedging the FIFO queue — so it
    // clamps again here.
    head.amount = Math.min(head.amount, perCall, total);
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
  const entry = { amount: Math.min(perCall, total), resolve: () => {} };
  await /** @type {Promise<void>} */ (
    new Promise((resolve) => {
      entry.resolve = resolve;
      admitQueue.push(entry);
      admitFromFront();
    })
  );
  // Admission may have clamped the entry under limits lowered since queue
  // time; what was reserved is what the release must return.
  const amount = entry.amount;
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
 * The shared raw `export-key-raw` gate: throw `{ tag: 'not-extractable' }`
 * unless `key` was minted extractable (checked on the `CryptoKey` itself
 * rather than relying on the `DOMException` from `exportKeyRaw`), then export
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
 * The decoded byte length of a valid unpadded-base64url string — exact:
 * `floor(chars * 3 / 4)`. Only meaningful after the platform accepted the
 * JWK (which validates the encoding).
 * @param {unknown} k
 */
function jwkKeyBytes(k) {
  return typeof k === "string" ? Math.floor((k.length * 3) / 4) : 0;
}

/**
 * The base64url value (0–63) of a UTF-16 code unit, or -1 outside the
 * alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`) — computed with sign-bit
 * arithmetic over range predicates: no alphabet string scan, no table
 * lookup, no branch on the character's value, so per-character work is
 * uniform. Secret JWK members (`k`, `d`, the RSA private set) pass
 * through here; uniformity is what licenses that (JS offers no
 * constant-time guarantee, but a value-independent instruction stream
 * removes the value-dependent component this can control).
 * @param {number} code
 */
function b64urlValue(code) {
  /**
   * 1 when `lo <= code <= hi`, else 0 (sign-bit arithmetic, branchless).
   * @param {number} lo
   * @param {number} hi
   */
  const inRange = (lo, hi) => ((lo - 1 - code) & (code - hi - 1)) >>> 31;
  const upper = inRange(0x41, 0x5a); // A-Z -> 0-25
  const lower = inRange(0x61, 0x7a); // a-z -> 26-51
  const digit = inRange(0x30, 0x39); // 0-9 -> 52-61
  const minus = inRange(0x2d, 0x2d); // '-' -> 62
  const under = inRange(0x5f, 0x5f); // '_' -> 63
  const valid = upper | lower | digit | minus | under;
  return (
    upper * (code - 0x41) +
    lower * (code - 0x61 + 26) +
    digit * (code - 0x30 + 52) +
    minus * 62 +
    under * 63 -
    (1 - valid)
  );
}

/**
 * Decode strict unpadded base64url (validated by
 * `requireStrictBase64url` first; an unvalidated string decodes to
 * garbage rather than throwing), for the JWK members whose bytes this
 * host's own predicates need (the Ed25519 strict point check). Per-char
 * work is uniform (see `b64urlValue`), so a future secret-member caller
 * inherits that.
 * @param {string} text
 * @returns {Uint8Array}
 */
function b64urlDecode(text) {
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let at = 0;
  for (let i = 0; i < text.length; i++) {
    buffer = (buffer << 6) | b64urlValue(text.charCodeAt(i));
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (buffer >> bits) & 0xff;
    }
  }
  return out;
}

/**
 * The fixed 12-byte SubjectPublicKeyInfo prefix of an RFC 8410 key
 * (SEQUENCE, algorithm OID, 33-byte BIT STRING with zero unused bits):
 * the whole structure is constant-shape, so extraction is a prefix
 * compare, not a DER parser. The last byte is the OID's — 0x6e X25519,
 * 0x70 Ed25519.
 * @param {number} oidTail
 * @param {Uint8Array} spki
 * @param {string} what
 * @returns {Uint8Array} the embedded 32-byte public key
 */
function rfc8410SpkiKey(oidTail, spki, what) {
  const prefix = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, oidTail, 0x03, 0x21, 0x00];
  const ok = spki.length === 44 && prefix.every((byte, i) => spki[i] === byte);
  if (!ok) {
    throw errInvalidKey(`${what}: not an RFC 8410 SubjectPublicKeyInfo`);
  }
  return spki.slice(12);
}

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
  // Fold the verdict across every character with no early exit, and take
  // the final character's value from the same pass: the members checked
  // here include secret material, so per-character work stays uniform
  // (see `b64urlValue`).
  let invalid = 0;
  let last = 0;
  for (let i = 0; i < k.length; i++) {
    const value = b64urlValue(k.charCodeAt(i));
    invalid |= value >> 31; // -1 spreads its sign bit; 0-63 contribute 0
    last = value;
  }
  if (invalid !== 0) {
    throw errInvalidKey("JWK `k` is not unpadded base64url");
  }
  const rem = k.length % 4;
  if (rem !== 0) {
    const mask = rem === 2 ? 0b1111 : 0b11;
    if ((last & mask) !== 0) {
      throw errInvalidKey("JWK `k` has non-zero trailing bits");
    }
  }
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
 * at most `cap` bytes: past the cap the stream is still drained but
 * discarded (this host drains to completion rather than closing early),
 * and a recoverable `{ tag: 'other' }` is thrown once the stream ends.
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
  "p256-sha384": {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-384",
    publicLength: 65,
    scalarLength: 32,
    signatureLength: 64,
  },
  "p256-sha512": {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-512",
    publicLength: 65,
    scalarLength: 32,
    signatureLength: 64,
  },
  "p384-sha256": {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-256",
    publicLength: 97,
    scalarLength: 48,
    signatureLength: 96,
  },
  "p384-sha384": {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-384",
    publicLength: 97,
    scalarLength: 48,
    signatureLength: 96,
  },
  "p384-sha512": {
    name: "ECDSA",
    namedCurve: "P-384",
    hash: "SHA-512",
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
 * The WebCrypto sign/verify algorithm parameter for a key's mint binding:
 * ECDSA passes its mint-bound hash per operation, RSA-PSS its mint-bound
 * salt length; every other family's binding is carried by the `CryptoKey`
 * itself.
 * @param {SignatureAlgorithm} algorithm
 * @returns {AlgorithmIdentifier | EcdsaParams | RsaPssParams}
 */
function signParams(algorithm) {
  if (algorithm.name === "ECDSA") return { name: "ECDSA", hash: algorithm.hash };
  if (algorithm.name === "RSA-PSS") {
    return { name: "RSA-PSS", saltLength: /** @type {number} */ (algorithm.saltLength) };
  }
  return algorithm.name;
}

/**
 * The `verifying-key` resource: a public `CryptoKey` plus the algorithm
 * record bound at mint (`ED25519_ALGORITHM`, an `ECDSA_VARIANTS` entry, or
 * a per-key RSA record from `rsaAlgorithm`). The record — not
 * `CryptoKey.algorithm` — is the authority for every algorithm fact this
 * class needs: the hash WebCrypto passes per-operation for ECDSA, the
 * PSS salt length, the signature width, and the getters' answers.
 * Instances are minted by the `ed25519-verify` / `ecdsa-verify` /
 * `rsassa-pkcs1-v15-verify` / `rsa-pss-verify` interface functions below,
 * or paired with a `SigningKey` by `generate-key`.
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
      // Each algorithm's signature width is fixed at mint (Ed25519's
      // 64-byte `R ‖ S`; ECDSA's P1363 `r ‖ s`; RSA's modulus-length
      // octet string, RFC 8017's `k`). Chromium's engine rejects
      // other lengths itself; Firefox zero-pads short halves and accepts
      // truncated encodings (observed accepting a 2-byte signature), so
      // enforce the width here — a pure length check on public data,
      // strictly monotone: it only adds rejections in front of the engine.
      // The message stream is drained first (this host drains to
      // completion rather than closing early).
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

  algorithmLength() {
    return this.#algorithm.length;
  }

  /**
   * The RSA public exponent's big-endian bytes, from the platform key's
   * own `RsaKeyAlgorithm.publicExponent`; `undefined` for Ed25519 and
   * ECDSA, whose algorithms have no such member.
   * @returns {Uint8Array | undefined}
   */
  algorithmPublicExponent() {
    const e = /** @type {RsaHashedKeyAlgorithm} */ (this.#key.algorithm).publicExponent;
    return e === undefined ? undefined : new Uint8Array(e);
  }

  /**
   * The public key material (`raw`: 32 bytes for Ed25519, an uncompressed
   * SEC1 point for ECDSA). The RSA family has no raw public form (the
   * platform serves `spki` and `jwk` only), so its keys fail `unsupported`
   * here, as the WIT pins.
   *
   * There is no extractability gate on this resource — WebCrypto sets
   * `[[extractable]]` true on every generated public key, and the importers
   * below pass `true` — so `not-extractable` never occurs. The export can
   * still fail: each algorithm's export operation begins by throwing
   * `OperationError` when the key material behind the `CryptoKey` cannot be
   * accessed, which `platformCall` renders as `other`.
   */
  async exportKeyRaw() {
    if (this.#algorithm.name === "RSASSA-PKCS1-v1_5" || this.#algorithm.name === "RSA-PSS") {
      throw errUnsupported("RSA public keys have no raw form");
    }
    return new Uint8Array(
      await platformCall("raw key export", () => subtle.exportKey("raw", this.#key)),
    );
  }

  /**
   * The SubjectPublicKeyInfo form, with `exportKeyRaw`'s fallibility (less
   * the RSA refusal: every family has an SPKI form).
   * @returns {Promise<Uint8Array>}
   */
  async exportKeySpki() {
    return new Uint8Array(
      await platformCall("spki key export", () => subtle.exportKey("spki", this.#key)),
    );
  }

  /**
   * The public JWK (OKP for Ed25519, EC for ECDSA, RSA for the RSA
   * family), material members only per the package-wide JWK contract.
   */
  async exportKeyJwk() {
    const jwk = await platformCall("jwk key export", () => subtle.exportKey("jwk", this.#key));
    if (jwk.kty === "OKP") return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x });
    if (jwk.kty === "RSA") return JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e });
    return JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y });
  }
}

/**
 * The `signing-key-options` resource. See `MacKeyOptions` for the state and
 * same-provider mechanics; the vocabulary is degenerate (`sign` is the sole
 * usage, and must be granted for a mint to succeed).
 */
/** @type {WeakMap<SigningKeyOptions, { sign: boolean, extractable: boolean }>} */
const signingPolicies = new WeakMap();

const signingPolicy = stateReader(signingPolicies, "signing-key-options");

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
 * enforces non-extractability; the JS check in `exportKeyRaw` only lifts the
 * WIT error shape. There is no stored public half: the WIT surface has no
 * derive — `generate-key` returns the pair, and importers mint the
 * verifying key from the public bytes they hold.
 */
export class SigningKey extends keyResourceTail({ canSign: "sign" }) {
  #algorithm;

  /**
   * @param {CryptoKey} privateKey
   * @param {typeof ED25519_ALGORITHM} algorithm the mint-bound algorithm record
   */
  constructor(privateKey, algorithm) {
    super(privateKey);
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
          subtle.sign(params, platformKeyOf(this), message),
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

  algorithmLength() {
    return this.#algorithm.length;
  }

  /**
   * See `VerifyingKey.algorithmPublicExponent`.
   * @returns {Uint8Array | undefined}
   */
  algorithmPublicExponent() {
    const e = /** @type {RsaHashedKeyAlgorithm} */ (platformKeyOf(this).algorithm).publicExponent;
    return e === undefined ? undefined : new Uint8Array(e);
  }

  /**
   * The private JWK (OKP for Ed25519, EC for ECDSA, full-CRT RSA for the
   * RSA family), material members only, behind the extractability gate
   * (checked on the `CryptoKey` itself, like `exportRawGated`).
   */
  async exportKeyJwk() {
    const privateKey = platformKeyOf(this);
    if (!privateKey.extractable) throw errNotExtractable();
    const jwk = await platformCall("jwk key export", () => subtle.exportKey("jwk", privateKey));
    if (jwk.kty === "RSA") {
      return JSON.stringify({
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        d: jwk.d,
        p: jwk.p,
        q: jwk.q,
        dp: jwk.dp,
        dq: jwk.dq,
        qi: jwk.qi,
      });
    }
    return JSON.stringify(
      jwk.kty === "OKP"
        ? { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d }
        : { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
    );
  }

  /**
   * The PKCS#8 form, behind the same gate.
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyPkcs8() {
    const privateKey = platformKeyOf(this);
    if (!privateKey.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("pkcs8 key export", () => subtle.exportKey("pkcs8", privateKey)),
    );
  }

  /**
   * The private JWK serialization as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyJwk`.
   */
  async toWrapInputJwk() {
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(await this.exportKeyJwk()));
  }

  /**
   * The PKCS#8 serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputPkcs8() {
    return new WrapInput(MINT, "pkcs8", await this.exportKeyPkcs8());
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
 * Annotated `never` deliberately: the `importPlatformKey*` helpers rely on
 * this throwing to make their catch arms non-completing, so a version that
 * fell through would resolve them with an `undefined` `CryptoKey`.
 * @param {unknown} err
 * @param {string} what
 * @returns {never}
 */
function invalidKey(err, what) {
  throw errInvalidKey(`invalid ${what}: ${asPlatformError(err).detail}`);
}

/**
 * Import binary key material via the platform. An import failure throws
 * `{ tag: 'invalid-key', val }` naming `what`; every other validation
 * (length checks, strict-point predicates, post-import shape checks)
 * stays at the call site.
 * @param {string} what
 * @param {Exclude<KeyFormat, "jwk">} format
 * @param {Uint8Array} bytes
 * @param {AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm
 * @param {boolean} extractable
 * @param {KeyUsage[]} usages
 * @returns {Promise<CryptoKey>}
 */
async function importPlatformKey(what, format, bytes, algorithm, extractable, usages) {
  try {
    return await subtle.importKey(format, asBufferSource(bytes), algorithm, extractable, usages);
  } catch (err) {
    invalidKey(err, what);
  }
}

/**
 * Import a parsed JWK (a `jwkMaterial` result) via the platform. An import
 * failure throws `{ tag: 'invalid-key', val }` naming `what`; member
 * strictness and post-import shape checks stay at the call site.
 * @param {string} what
 * @param {Record<string, unknown>} jwk
 * @param {AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm
 * @param {boolean} extractable
 * @param {KeyUsage[]} usages
 * @returns {Promise<CryptoKey>}
 */
async function importPlatformKeyJwk(what, jwk, algorithm, extractable, usages) {
  try {
    return await subtle.importKey(
      "jwk",
      /** @type {JsonWebKey} */ (jwk),
      algorithm,
      extractable,
      usages,
    );
  } catch (err) {
    invalidKey(err, what);
  }
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
  const key = await importPlatformKey("Ed25519 public key", "raw", raw, "Ed25519", true, [
    "verify",
  ]);
  return new VerifyingKey(key, ED25519_ALGORITHM);
}

/** The `polymorph:webcrypto/signature` interface: its resource classes. */
export const signature = { VerifyingKey, SigningKey, SigningKeyOptions };

/**
 * Import an Ed25519 public key from a SubjectPublicKeyInfo: the embedded
 * point runs the same strict predicate as the raw import, then the
 * original DER goes to the platform verbatim.
 * @param {Uint8Array} spki
 */
async function importEd25519VerifyingKeySpki(spki) {
  const point = rfc8410SpkiKey(0x70, spki, "Ed25519");
  if (!ed25519PointStrict(point)) {
    throw errInvalidKey("non-canonical or small-order Ed25519 public key");
  }
  const key = await importPlatformKey("Ed25519 spki", "spki", spki, "Ed25519", true, ["verify"]);
  return new VerifyingKey(key, ED25519_ALGORITHM);
}

/**
 * Import an Ed25519 public key from an OKP public JWK: `x` is decoded for
 * the strict predicate; the JWK itself goes to the platform (which owns
 * the kty/crv/ext validation), stripped of the consumer-policy members.
 * @param {string} jwkText
 */
async function importEd25519VerifyingKeyJwk(jwkText) {
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  if (typeof jwk.x !== "string" || !ed25519PointStrict(b64urlDecode(jwk.x))) {
    throw errInvalidKey("non-canonical or small-order Ed25519 public key");
  }
  const key = await importPlatformKeyJwk("Ed25519 public JWK", jwk, "Ed25519", true, ["verify"]);
  return new VerifyingKey(key, ED25519_ALGORITHM);
}

/** The `polymorph:webcrypto/ed25519-verify` interface. */
export const ed25519Verify = {
  importVerifyingKeyRaw: importEd25519VerifyingKey,
  importVerifyingKeySpki: importEd25519VerifyingKeySpki,
  importVerifyingKeyJwk: importEd25519VerifyingKeyJwk,
};

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

/**
 * Import an Ed25519 signing key from a PKCS#8 PrivateKeyInfo — a platform
 * pass-through; the platform owns the DER validation.
 * @param {Uint8Array} pkcs8
 * @param {SigningKeyOptions} options
 */
async function importEd25519SigningKeyPkcs8(pkcs8, options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const key = await importPlatformKey(
    "Ed25519 pkcs8",
    "pkcs8",
    pkcs8,
    "Ed25519",
    policy.extractable,
    ["sign"],
  );
  return new SigningKey(key, ED25519_ALGORITHM);
}

/**
 * Import an Ed25519 signing key from an OKP private JWK. The platform
 * cannot promise the `x`-matches-`d` consistency check (the WIT MAY);
 * strictness of the base64url members is pinned host-side.
 * @param {string} jwkText
 * @param {SigningKeyOptions} options
 */
async function importEd25519SigningKeyJwk(jwkText, options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.d);
  const key = await importPlatformKeyJwk(
    "Ed25519 private JWK",
    jwk,
    "Ed25519",
    policy.extractable,
    ["sign"],
  );
  if (key.type !== "private") {
    throw errInvalidKey("OKP private JWK must carry `d` (base64url private key)");
  }
  return new SigningKey(key, ED25519_ALGORITHM);
}

/**
 * Mint an Ed25519 signing key from unwrapped key material read as a PKCS#8
 * PrivateKeyInfo (see the `wrapping` interface): the
 * `import-signing-key-pkcs8` path over the consumed input's bytes, with
 * `invalid-key` details redacted (see `redactingInvalidKey`).
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapEd25519SigningKeyPkcs8(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped Ed25519 pkcs8", () =>
    importEd25519SigningKeyPkcs8(bytes, options),
  );
}

/**
 * Mint an Ed25519 signing key from unwrapped key material read as an OKP
 * private JWK: the unwrap-path `use`/`key_ops` checks (`sign` is the sole
 * grantable usage, and the mint requires it), then the
 * `import-signing-key-jwk` path, redacted like the PKCS#8 mint.
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapEd25519SigningKeyJwk(input, options) {
  const { bytes } = consumeUnwrapInput(input);
  requireSigningGrant(signingPolicy(options));
  const jwk = unwrappedJwk(bytes, "sig", ["sign"]);
  return redactingInvalidKey("unwrapped Ed25519 private JWK", () =>
    importEd25519SigningKeyJwk(jwk, options),
  );
}

/** The `polymorph:webcrypto/ed25519-sign` interface. */
export const ed25519Sign = {
  generateKey: generateEd25519Key,
  importSigningKeyPkcs8: importEd25519SigningKeyPkcs8,
  importSigningKeyJwk: importEd25519SigningKeyJwk,
  unwrapSigningKeyPkcs8: unwrapEd25519SigningKeyPkcs8,
  unwrapSigningKeyJwk: unwrapEd25519SigningKeyJwk,
};

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
  const key = await importPlatformKey(
    `${variant} public key`,
    "raw",
    raw,
    { name: "ECDSA", namedCurve: entry.namedCurve },
    true,
    ["verify"],
  );
  return new VerifyingKey(key, entry);
}

/**
 * Import an ECDSA public key from a SubjectPublicKeyInfo. The
 * AlgorithmIdentifier must be the declared curve's named-OID form (see
 * `requireNamedCurveSpki`); past that check the import is a platform
 * pass-through — the platform validates the DER and rejects a curve that
 * disagrees with the declared variant's.
 * @param {string} variant
 * @param {Uint8Array} spki
 */
async function importEcdsaVerifyingKeySpki(variant, spki) {
  const entry = ecdsaVariant(variant);
  requireNamedCurveSpki(entry.namedCurve, spki);
  const key = await importPlatformKey(
    `${variant} spki`,
    "spki",
    spki,
    { name: "ECDSA", namedCurve: entry.namedCurve },
    true,
    ["verify"],
  );
  return new VerifyingKey(key, entry);
}

/**
 * Import an ECDSA public key from an EC public JWK — a platform
 * pass-through of the material members; the platform owns the kty/crv/
 * coordinate validation (including on-curve).
 * @param {string} variant
 * @param {string} jwkText
 */
async function importEcdsaVerifyingKeyJwk(variant, jwkText) {
  const entry = ecdsaVariant(variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.y);
  const key = await importPlatformKeyJwk(
    `${variant} public JWK`,
    jwk,
    { name: "ECDSA", namedCurve: entry.namedCurve },
    true,
    ["verify"],
  );
  return new VerifyingKey(key, entry);
}

/** The `polymorph:webcrypto/ecdsa-verify` interface. */
export const ecdsaVerify = {
  importVerifyingKeyRaw: importEcdsaVerifyingKey,
  importVerifyingKeySpki: importEcdsaVerifyingKeySpki,
  importVerifyingKeyJwk: importEcdsaVerifyingKeyJwk,
};

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

/**
 * Import an ECDSA signing key from a PKCS#8 PrivateKeyInfo of the declared
 * variant's curve — a platform pass-through.
 * @param {string} variant
 * @param {Uint8Array} pkcs8
 * @param {SigningKeyOptions} options
 */
async function importEcdsaSigningKeyPkcs8(variant, pkcs8, options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = ecdsaVariant(variant);
  const key = await importPlatformKey(
    `${variant} pkcs8`,
    "pkcs8",
    pkcs8,
    { name: "ECDSA", namedCurve: entry.namedCurve },
    policy.extractable,
    ["sign"],
  );
  return new SigningKey(key, entry);
}

/**
 * Import an ECDSA signing key from an EC private JWK — a platform
 * pass-through; the platform owns the d-in-range and point-consistency
 * validation the WIT requires of EC private JWKs.
 * @param {string} variant
 * @param {string} jwkText
 * @param {SigningKeyOptions} options
 */
async function importEcdsaSigningKeyJwk(variant, jwkText, options) {
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = ecdsaVariant(variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.x);
  requireStrictBase64url(jwk.y);
  requireStrictBase64url(jwk.d);
  const key = await importPlatformKeyJwk(
    `${variant} private JWK`,
    jwk,
    { name: "ECDSA", namedCurve: entry.namedCurve },
    policy.extractable,
    ["sign"],
  );
  if (key.type !== "private") {
    throw errInvalidKey("EC private JWK must carry `d` (base64url private scalar)");
  }
  return new SigningKey(key, entry);
}

/**
 * Mint an ECDSA signing key of the declared variant from unwrapped key
 * material read as a PKCS#8 PrivateKeyInfo (see
 * `unwrapEd25519SigningKeyPkcs8`).
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapEcdsaSigningKeyPkcs8(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey(`unwrapped ${variant} pkcs8`, () =>
    importEcdsaSigningKeyPkcs8(variant, bytes, options),
  );
}

/**
 * Mint an ECDSA signing key of the declared variant from unwrapped key
 * material read as an EC private JWK (see `unwrapEd25519SigningKeyJwk`).
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapEcdsaSigningKeyJwk(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  requireSigningGrant(signingPolicy(options));
  const jwk = unwrappedJwk(bytes, "sig", ["sign"]);
  return redactingInvalidKey(`unwrapped ${variant} private JWK`, () =>
    importEcdsaSigningKeyJwk(variant, jwk, options),
  );
}

/** The `polymorph:webcrypto/ecdsa-sign` interface. */
export const ecdsaSign = {
  generateKey: generateEcdsaKey,
  importSigningKeyPkcs8: importEcdsaSigningKeyPkcs8,
  importSigningKeyJwk: importEcdsaSigningKeyJwk,
  unwrapSigningKeyPkcs8: unwrapEcdsaSigningKeyPkcs8,
  unwrapSigningKeyJwk: unwrapEcdsaSigningKeyJwk,
};

/**
 * The mint-bound digest for each served `rsa-variant` enum case (the
 * `rsa` interface's one variant set, shared by the four RSA signature
 * interfaces), with the digest output length the PSS signing mints fix
 * their salt length to (the JOSE `PS*` profile).
 */
/** @type {Readonly<Record<string, { hash: string, digestBytes: number } | undefined>>} */
const RSA_VARIANTS = Object.assign(Object.create(null), {
  sha256: { hash: "SHA-256", digestBytes: 32 },
  sha384: { hash: "SHA-384", digestBytes: 48 },
  sha512: { hash: "SHA-512", digestBytes: 64 },
});

/** The RSA family's modulus admission window, in bits (inclusive). */
const RSA_MODULUS_MIN_BITS = 1024;
const RSA_MODULUS_MAX_BITS = 16384;

/** The signing interfaces' tightened modulus window, in bits (inclusive). */
const RSA_SIGNING_MIN_BITS = 2048;
const RSA_SIGNING_MAX_BITS = 8192;

/**
 * The generated modulus length for each `rsa-modulus` enum case.
 */
/** @type {Readonly<Record<string, number | undefined>>} */
const RSA_MODULUS_BITS = Object.assign(Object.create(null), {
  m2048: 2048,
  m3072: 3072,
  m4096: 4096,
  m8192: 8192,
});

/**
 * The admission checks the platform does not enforce, run after a
 * platform RSA import on the imported key's metadata (`RsaKeyAlgorithm`) —
 * no DER or JWK parsing; a rejected key is simply discarded. Node 24
 * admits keys the family contract rejects on both counts — 512-bit moduli
 * via SPKI, and even or < 3 exponents via JWK (`e = 4` and `e = 1` both
 * import) — so both rules live here:
 * - the modulus length must be within the caller's admission window (the
 *   family window for verification imports, the tightened 2048–8192
 *   window for the signing and RSA-OAEP imports; the platform admits
 *   either way — a 1024-bit PKCS#8 imports on Node 24);
 * - the public exponent must be odd and at least 3.
 * @param {CryptoKey} key
 * @param {string} what
 * @param {number} minBits
 * @param {number} maxBits
 * @returns {number} the admitted modulus length, in bits
 */
function rsaAdmittedModulusLength(
  key,
  what,
  minBits = RSA_MODULUS_MIN_BITS,
  maxBits = RSA_MODULUS_MAX_BITS,
) {
  const { modulusLength, publicExponent } = /** @type {RsaHashedKeyAlgorithm} */ (key.algorithm);
  if (modulusLength < minBits || modulusLength > maxBits) {
    throw errInvalidKey(
      `invalid ${what}: RSA modulus must be ${minBits}-${maxBits} bits, got ${modulusLength}`,
    );
  }
  // `publicExponent` is the big-endian magnitude; leading zeros only make
  // the value's octet count larger, never its value.
  let first = 0;
  while (first < publicExponent.length && publicExponent[first] === 0) first++;
  const octets = publicExponent.length - first;
  const low = octets === 0 ? 0 : publicExponent[publicExponent.length - 1];
  if ((low & 1) === 0 || (octets === 1 && low < 3)) {
    throw errInvalidKey(`invalid ${what}: RSA public exponent must be odd and at least 3`);
  }
  return modulusLength;
}

/**
 * The mint-bound algorithm record for an admitted RSA verification key:
 * the modulus length is the imported key's, and the signature width is
 * the modulus length in octets (RFC 8017's `k`).
 * @param {string} name `"RSASSA-PKCS1-v1_5"` or `"RSA-PSS"`
 * @param {string} hash
 * @param {number} modulusLength in bits
 * @param {number | undefined} saltLength RSA-PSS's mint-bound salt length, in bytes
 * @returns {SignatureAlgorithm}
 */
function rsaAlgorithm(name, hash, modulusLength, saltLength) {
  return {
    name,
    namedCurve: undefined,
    hash,
    length: modulusLength,
    signatureLength: Math.ceil(modulusLength / 8),
    saltLength,
  };
}

/**
 * Import an RSA public key of the declared variant from a
 * SubjectPublicKeyInfo, for `name` (`"RSASSA-PKCS1-v1_5"` or `"RSA-PSS"`).
 * The AlgorithmIdentifier must be the `rsaEncryption` form (see
 * `requireRsaEncryptionSpki`); the platform validates the DER, and the
 * family admission checks run on the imported key's metadata
 * (`rsaAdmittedModulusLength`).
 * @param {string} name
 * @param {string} variant
 * @param {Uint8Array} spki
 * @param {number | undefined} saltLength
 */
async function importRsaVerifyingKeySpki(name, variant, spki, saltLength) {
  const { hash } = served(RSA_VARIANTS, variant);
  requireRsaEncryptionSpki(spki);
  const key = await importPlatformKey(`${name} spki`, "spki", spki, { name, hash }, true, [
    "verify",
  ]);
  const modulusLength = rsaAdmittedModulusLength(key, `${name} spki`);
  return new VerifyingKey(key, rsaAlgorithm(name, hash, modulusLength, saltLength));
}

/**
 * Import an RSA public key of the declared variant from an RSA public JWK,
 * for `name` — a platform pass-through of the material members; the
 * platform owns the kty/alg/ext validation, including the
 * alg-against-variant rule the WIT pins (an `alg` member that disagrees
 * with the requested hash fails the platform import with `DataError`).
 * Strictness of the base64url members is pinned host-side, and the family
 * admission checks run on the imported key's metadata.
 * @param {string} name
 * @param {string} variant
 * @param {string} jwkText
 * @param {number | undefined} saltLength
 */
async function importRsaVerifyingKeyJwk(name, variant, jwkText, saltLength) {
  const { hash } = served(RSA_VARIANTS, variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.n);
  requireStrictBase64url(jwk.e);
  const key = await importPlatformKeyJwk(`${name} public JWK`, jwk, { name, hash }, true, [
    "verify",
  ]);
  const modulusLength = rsaAdmittedModulusLength(key, `${name} public JWK`);
  return new VerifyingKey(key, rsaAlgorithm(name, hash, modulusLength, saltLength));
}

/** The `polymorph:webcrypto/rsassa-pkcs1-v15-verify` interface. */
export const rsassaPkcs1V15Verify = {
  /**
   * @param {string} variant
   * @param {Uint8Array} spki
   */
  importVerifyingKeySpki: (variant, spki) =>
    importRsaVerifyingKeySpki("RSASSA-PKCS1-v1_5", variant, spki, undefined),
  /**
   * @param {string} variant
   * @param {string} jwk
   */
  importVerifyingKeyJwk: (variant, jwk) =>
    importRsaVerifyingKeyJwk("RSASSA-PKCS1-v1_5", variant, jwk, undefined),
};

/** The `polymorph:webcrypto/rsa-pss-verify` interface. */
export const rsaPssVerify = {
  /**
   * @param {string} variant
   * @param {number} saltLength
   * @param {Uint8Array} spki
   */
  importVerifyingKeySpki: (variant, saltLength, spki) =>
    importRsaVerifyingKeySpki("RSA-PSS", variant, spki, saltLength),
  /**
   * @param {string} variant
   * @param {number} saltLength
   * @param {string} jwk
   */
  importVerifyingKeyJwk: (variant, saltLength, jwk) =>
    importRsaVerifyingKeyJwk("RSA-PSS", variant, jwk, saltLength),
};

/**
 * The RSA private-key posture: whether this host serves the gated
 * RSA private-key minting interfaces (`rsassa-pkcs1-v15-sign`,
 * `rsa-pss-sign`, `rsa-oaep-decrypt`). `undefined` means the environment
 * default, evaluated per minting call (see `requireRsaPrivateKeysServed`).
 * @type {"serve" | "decline" | undefined}
 */
let rsaPrivateKeyPolicy;

/**
 * Choose whether the gated RSA private-key minting functions — the two
 * signing interfaces' and `rsa-oaep-decrypt`'s — are served (`"serve"`),
 * declined with `{ tag: 'unsupported' }` (`"decline"`), or left to the
 * environment default (`undefined`): serve under Node, decline everywhere
 * else — browsers and unknown runtimes fail closed.
 *
 * The default encodes the WIT gates' recorded ruling (`wit/rsa.wit`;
 * `wit/README.md`, "Stability gates"): RSA private-key operations leak key
 * material through execution timing unless the implementation is
 * constant-time end to end, and a browser is the archetypal
 * attacker-observable timing domain — scripts, workers, and cross-origin
 * frames share the machine and a clock with the private-key operation, and
 * the one WebCrypto RSA private-op key-recovery CVE to date was a browser's
 * (CVE-2023-5388, Firefox NSS). Node deployments choose their co-tenants,
 * so Node serves by default. Opting a browser in is the deployer's
 * assertion that its timing domain is not attacker-observable.
 *
 * One posture governs signing and decryption alike: the timing judgment is
 * about the RSA private-key operation, not the interface reaching it.
 * `rsa-oaep-encrypt` is outside the posture — public-key operations are
 * secret-free, so encryption minting is served everywhere.
 * @param {"serve" | "decline" | undefined} policy
 */
export function setRsaPrivateKeyPolicy(policy) {
  if (policy !== "serve" && policy !== "decline" && policy !== undefined) {
    throw new TypeError(
      `RSA private-key policy must be "serve", "decline", or undefined, got ${policy}`,
    );
  }
  rsaPrivateKeyPolicy = policy;
}

/**
 * The posture check every RSA private-key mint runs first. Per minting
 * call rather than at module load, so a `setRsaPrivateKeyPolicy` call
 * takes effect immediately, and the environment default reads the
 * environment as the mint sees it. The environment probe goes through a
 * structural cast: this file type-checks against the DOM lib alone (the
 * browser-compatibility charter), which does not declare `process`.
 */
function requireRsaPrivateKeysServed() {
  const environment = /** @type {{ process?: { versions?: { node?: unknown } } }} */ (globalThis);
  const policy =
    rsaPrivateKeyPolicy ?? (environment.process?.versions?.node ? "serve" : "decline");
  if (policy !== "serve") {
    throw errUnsupported(
      "RSA private-key operations are declined in this environment; see setRsaPrivateKeyPolicy",
    );
  }
}

/**
 * The mint-bound algorithm record for an RSA signing mint: `rsaAlgorithm`
 * with the salt length the signing interfaces fix — the digest length for
 * RSA-PSS (the JOSE `PS*` and RFC 8017 default profile; `rsa-pss-sign`
 * takes no salt parameter), none for RSASSA-PKCS1-v1_5.
 * @param {string} name `"RSASSA-PKCS1-v1_5"` or `"RSA-PSS"`
 * @param {{ hash: string, digestBytes: number }} entry
 * @param {number} modulusLength in bits
 */
function rsaSigningAlgorithm(name, entry, modulusLength) {
  return rsaAlgorithm(
    name,
    entry.hash,
    modulusLength,
    name === "RSA-PSS" ? entry.digestBytes : undefined,
  );
}

/**
 * Generate a fresh RSA signing key pair of the declared variant and modulus
 * length for `name`, returning `[signing, verifying]`. The public exponent
 * is 65537 (the WIT fixes it; not a parameter).
 * @param {string} name
 * @param {string} variant
 * @param {string} modulus
 * @param {SigningKeyOptions} options
 * @returns {Promise<[SigningKey, VerifyingKey]>}
 */
async function generateRsaSigningKey(name, variant, modulus, options) {
  requireRsaPrivateKeysServed();
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = served(RSA_VARIANTS, variant);
  const modulusLength = served(RSA_MODULUS_BITS, modulus);
  const pair = await platformCall(`${name} key generation`, () =>
    subtle.generateKey(
      {
        name,
        hash: entry.hash,
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      policy.extractable,
      ["sign", "verify"],
    ),
  );
  const algorithm = rsaSigningAlgorithm(name, entry, modulusLength);
  return [new SigningKey(pair.privateKey, algorithm), new VerifyingKey(pair.publicKey, algorithm)];
}

/**
 * Import an RSA signing key of the declared variant from a PKCS#8
 * PrivateKeyInfo, for `name`. The platform validates the DER — including
 * the rsaEncryption-only algorithm rule, which the WebCrypto import steps
 * mandate (an `id-RSASSA-PSS` PKCS#8 fails the platform import with
 * `DataError`) — and the signing window runs on the imported key's
 * metadata (`rsaAdmittedModulusLength`; the platform admits wider).
 * @param {string} name
 * @param {string} variant
 * @param {Uint8Array} pkcs8
 * @param {SigningKeyOptions} options
 */
async function importRsaSigningKeyPkcs8(name, variant, pkcs8, options) {
  requireRsaPrivateKeysServed();
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = served(RSA_VARIANTS, variant);
  const key = await importPlatformKey(
    `${name} pkcs8`,
    "pkcs8",
    pkcs8,
    { name, hash: entry.hash },
    policy.extractable,
    ["sign"],
  );
  const modulusLength = rsaAdmittedModulusLength(
    key,
    `${name} pkcs8`,
    RSA_SIGNING_MIN_BITS,
    RSA_SIGNING_MAX_BITS,
  );
  return new SigningKey(key, rsaSigningAlgorithm(name, entry, modulusLength));
}

/**
 * Import an RSA signing key of the declared variant from an RSA private
 * JWK, for `name` — a platform pass-through of the material members. The
 * platform owns the kty/alg/ext validation (including the
 * alg-against-variant rule, as on the `-verify` path) and the full-CRT
 * requirement the WIT pins: a `d`-only or partial-CRT private JWK fails
 * the platform import with `DataError`. Strictness of the base64url
 * members is pinned host-side, and the signing window runs on the imported
 * key's metadata.
 * @param {string} name
 * @param {string} variant
 * @param {string} jwkText
 * @param {SigningKeyOptions} options
 */
async function importRsaSigningKeyJwk(name, variant, jwkText, options) {
  requireRsaPrivateKeysServed();
  const policy = signingPolicy(options);
  requireSigningGrant(policy);
  const entry = served(RSA_VARIANTS, variant);
  const jwk = jwkMaterial(jwkText);
  for (const member of ["n", "e", "d", "p", "q", "dp", "dq", "qi"]) {
    requireStrictBase64url(jwk[member]);
  }
  const key = await importPlatformKeyJwk(
    `${name} private JWK`,
    jwk,
    { name, hash: entry.hash },
    policy.extractable,
    ["sign"],
  );
  if (key.type !== "private") {
    throw errInvalidKey("RSA private JWK must carry `d` and the CRT members");
  }
  const modulusLength = rsaAdmittedModulusLength(
    key,
    `${name} private JWK`,
    RSA_SIGNING_MIN_BITS,
    RSA_SIGNING_MAX_BITS,
  );
  return new SigningKey(key, rsaSigningAlgorithm(name, entry, modulusLength));
}

/**
 * Mint an RSA signing key of the declared variant from unwrapped key
 * material read as a PKCS#8 PrivateKeyInfo (see
 * `unwrapEd25519SigningKeyPkcs8`).
 * @param {string} name
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapRsaSigningKeyPkcs8(name, variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey(`unwrapped ${name} pkcs8`, () =>
    importRsaSigningKeyPkcs8(name, variant, bytes, options),
  );
}

/**
 * Mint an RSA signing key of the declared variant from unwrapped key
 * material read as an RSA private JWK (see `unwrapEd25519SigningKeyJwk`).
 * @param {string} name
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {SigningKeyOptions} options
 */
async function unwrapRsaSigningKeyJwk(name, variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  requireSigningGrant(signingPolicy(options));
  const jwk = unwrappedJwk(bytes, "sig", ["sign"]);
  return redactingInvalidKey(`unwrapped ${name} private JWK`, () =>
    importRsaSigningKeyJwk(name, variant, jwk, options),
  );
}

/** The `polymorph:webcrypto/rsassa-pkcs1-v15-sign` interface. */
export const rsassaPkcs1V15Sign = {
  /**
   * @param {string} variant
   * @param {string} modulus
   * @param {SigningKeyOptions} options
   */
  generateKey: (variant, modulus, options) =>
    generateRsaSigningKey("RSASSA-PKCS1-v1_5", variant, modulus, options),
  /**
   * @param {string} variant
   * @param {Uint8Array} pkcs8
   * @param {SigningKeyOptions} options
   */
  importSigningKeyPkcs8: (variant, pkcs8, options) =>
    importRsaSigningKeyPkcs8("RSASSA-PKCS1-v1_5", variant, pkcs8, options),
  /**
   * @param {string} variant
   * @param {string} jwk
   * @param {SigningKeyOptions} options
   */
  importSigningKeyJwk: (variant, jwk, options) =>
    importRsaSigningKeyJwk("RSASSA-PKCS1-v1_5", variant, jwk, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {SigningKeyOptions} options
   */
  unwrapSigningKeyPkcs8: (variant, input, options) =>
    unwrapRsaSigningKeyPkcs8("RSASSA-PKCS1-v1_5", variant, input, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {SigningKeyOptions} options
   */
  unwrapSigningKeyJwk: (variant, input, options) =>
    unwrapRsaSigningKeyJwk("RSASSA-PKCS1-v1_5", variant, input, options),
};

/** The `polymorph:webcrypto/rsa-pss-sign` interface. */
export const rsaPssSign = {
  /**
   * @param {string} variant
   * @param {string} modulus
   * @param {SigningKeyOptions} options
   */
  generateKey: (variant, modulus, options) =>
    generateRsaSigningKey("RSA-PSS", variant, modulus, options),
  /**
   * @param {string} variant
   * @param {Uint8Array} pkcs8
   * @param {SigningKeyOptions} options
   */
  importSigningKeyPkcs8: (variant, pkcs8, options) =>
    importRsaSigningKeyPkcs8("RSA-PSS", variant, pkcs8, options),
  /**
   * @param {string} variant
   * @param {string} jwk
   * @param {SigningKeyOptions} options
   */
  importSigningKeyJwk: (variant, jwk, options) =>
    importRsaSigningKeyJwk("RSA-PSS", variant, jwk, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {SigningKeyOptions} options
   */
  unwrapSigningKeyPkcs8: (variant, input, options) =>
    unwrapRsaSigningKeyPkcs8("RSA-PSS", variant, input, options),
  /**
   * @param {string} variant
   * @param {UnwrapInput} input
   * @param {SigningKeyOptions} options
   */
  unwrapSigningKeyJwk: (variant, input, options) =>
    unwrapRsaSigningKeyJwk("RSA-PSS", variant, input, options),
};

/**
 * The `decryption-key-options` resource. See `MacKeyOptions` for the state
 * and same-provider mechanics; the decrypt/unwrap grants separate
 * disclosure (`decrypt` returns plaintext) from minting (`unwrap` mints
 * keys whose material the caller never sees) — see the WIT doc.
 */
/** @type {WeakMap<DecryptionKeyOptions, { decrypt: boolean, unwrap: boolean, extractable: boolean }>} */
const decryptionPolicies = new WeakMap();

const decryptionPolicy = stateReader(decryptionPolicies, "decryption-key-options");

export class DecryptionKeyOptions {
  constructor() {
    decryptionPolicies.set(this, { decrypt: false, unwrap: false, extractable: false });
  }

  /** @param {boolean} allowed */
  canDecrypt(allowed) {
    decryptionPolicy(this).decrypt = allowed;
  }

  /** @param {boolean} allowed */
  canUnwrap(allowed) {
    decryptionPolicy(this).unwrap = allowed;
  }

  /** @param {boolean} allowed */
  extractable(allowed) {
    decryptionPolicy(this).extractable = allowed;
  }
}

/**
 * The WebCrypto usages for a decryption-key mint policy, throwing
 * `{ tag: 'not-permitted' }` for a zero-usage grant. As with AEAD keys
 * (`aeadUsages`), the WIT grants do not map onto the platform's usages
 * one-to-one: `unwrap` runs `subtle.decrypt` over the wrapped bytes (the
 * `wrapping` intermediates carry serialized material host-side), so the
 * platform key carries `decrypt` if (decrypt or unwrap) and both WIT
 * grants are enforced host-side against the recorded policy
 * (`decryptionKeyGrants`).
 * @param {{ decrypt: boolean, unwrap: boolean }} policy
 * @returns {KeyUsage[]}
 */
function oaepPrivateUsages(policy) {
  return grantedUsages([["decrypt", policy.decrypt || policy.unwrap]]);
}

/**
 * The WIT-level grants of a decryption-key mint policy, as recorded on
 * the minted key (see `decryptionKeyGrants`).
 * @param {{ decrypt: boolean, unwrap: boolean }} policy
 */
function oaepGrants(policy) {
  return { decrypt: policy.decrypt, unwrap: policy.unwrap };
}

/**
 * The granted operations' platform names for a decryption-key mint policy
 * (the unwrap-path `key_ops` rule): the one-to-one names — `decrypt` →
 * `"decrypt"`, `unwrap` → `"unwrapKey"` — like `aeadGrantedOps`, unlike
 * `oaepPrivateUsages`, whose collapsed grant serves the platform key.
 * @param {{ decrypt: boolean, unwrap: boolean }} policy
 */
function oaepGrantedOps(policy) {
  const ops = [];
  if (policy.decrypt) ops.push("decrypt");
  if (policy.unwrap) ops.push("unwrapKey");
  return ops;
}

/**
 * The algorithm record bound to a public-encryption key at mint: the
 * mint-bound digest, the modulus length in bits, and the RFC 8017 §7.1.1
 * plaintext bound in bytes (`k − 2·hLen − 2`), which `encrypt`/`wrap`
 * enforce host-side (the platform's own oversize failure is an
 * unbranchable `OperationError`; the WIT names the condition).
 * @typedef {object} OaepAlgorithm
 * @property {string} hash
 * @property {number} modulusLength
 * @property {number} plaintextBound
 */

/**
 * The `OaepAlgorithm` for an admitted mint.
 * @param {{ hash: string, digestBytes: number }} entry the `RSA_VARIANTS` entry
 * @param {number} modulusLength in bits
 * @returns {OaepAlgorithm}
 */
function oaepAlgorithm(entry, modulusLength) {
  return {
    hash: entry.hash,
    modulusLength,
    plaintextBound: Math.ceil(modulusLength / 8) - 2 * entry.digestBytes - 2,
  };
}

/**
 * `error.extension` — origin `"polymorph:webcrypto"`, name `"message-too-long"`
 * — the public-encryption kind's named plaintext-bound condition (see
 * `wit/encryption.wit`): the signal to switch to hybrid wrapping.
 * @param {string} what
 * @param {number} length in bytes
 * @param {OaepAlgorithm} algorithm
 */
function errMessageTooLong(what, length, algorithm) {
  return {
    tag: "extension",
    val: {
      origin: "polymorph:webcrypto",
      name: "message-too-long",
      message: `${what} is ${length} bytes; this key's RSA-OAEP bound is ${algorithm.plaintextBound}`,
    },
  };
}

/**
 * The WebCrypto `RsaOaepParams` for a per-call label (`undefined` = none;
 * OAEP's default label is the empty string, so an absent label and an
 * empty one produce interchangeable ciphertexts).
 * @param {Uint8Array | undefined} label
 * @returns {RsaOaepParams}
 */
function oaepParams(label) {
  return label === undefined
    ? { name: "RSA-OAEP" }
    : { name: "RSA-OAEP", label: asBufferSource(label) };
}

/**
 * The shared `decrypt`/`unwrap` body: run `subtle.decrypt` and collapse
 * *every* platform failure to the detail-free
 * `{ tag: 'authentication-failed' }`. This is RFC 8017's single-verdict
 * rule, which the WIT pins (`wit/encryption.wit`): a wrong-length
 * ciphertext, damaged padding, and a mismatched label must be
 * indistinguishable — deliberately not the AEAD kinds' `decryptFailure`,
 * whose classification of non-`OperationError` failures is exactly the
 * verdict distinction this kind's contract closes off.
 * @param {CryptoKey} key
 * @param {Uint8Array | undefined} label
 * @param {Uint8Array} ciphertext
 */
async function oaepDecrypt(key, label, ciphertext) {
  let result;
  try {
    result = await subtle.decrypt(oaepParams(label), key, asBufferSource(ciphertext));
  } catch {
    throw errAuthenticationFailed();
  }
  return new Uint8Array(result);
}

/**
 * The `encryption-key` resource: a public RSA-OAEP `CryptoKey` plus the
 * algorithm record bound at mint. Secret-free to hold: `encrypt` and
 * `wrap` are unconditional (no grants), and the exports have no
 * extractability gate. Instances are minted by the `rsa-oaep-encrypt`
 * interface functions below, or paired with a `DecryptionKey` by
 * `generate-key`.
 */
export class EncryptionKey {
  #key;
  #algorithm;

  /**
   * @param {CryptoKey} key
   * @param {OaepAlgorithm} algorithm the mint-bound algorithm record
   */
  constructor(key, algorithm) {
    this.#key = key;
    this.#algorithm = algorithm;
  }

  /**
   * Encrypt `plaintext` under this key, binding `label` into the OAEP
   * padding (WebCrypto's `RsaOaepParams.label`; `undefined` = none). A
   * plaintext above the key's bound throws the named
   * `{ tag: 'extension' }` condition (`errMessageTooLong`) before the
   * platform is asked.
   * @param {Uint8Array | undefined} label
   * @param {Uint8Array} plaintext
   */
  async encrypt(label, plaintext) {
    if (plaintext.length > this.#algorithm.plaintextBound) {
      throw errMessageTooLong("plaintext", plaintext.length, this.#algorithm);
    }
    return new Uint8Array(
      await platformCall("RSA-OAEP encrypt", () =>
        subtle.encrypt(oaepParams(label), this.#key, asBufferSource(plaintext)),
      ),
    );
  }

  /**
   * Encrypt serialized key material, exactly as `encrypt` encrypts a
   * plaintext: the serialized bytes must fit the key's bound, else the
   * same named `{ tag: 'extension' }` condition. `input` is consumed
   * first, on failure as on success (the WIT contract).
   * @param {Uint8Array | undefined} label
   * @param {WrapInput} input
   * @returns {Promise<Uint8Array>}
   */
  async wrap(label, input) {
    const { bytes } = consumeWrapInput(input);
    if (bytes.length > this.#algorithm.plaintextBound) {
      throw errMessageTooLong("wrapped key material", bytes.length, this.#algorithm);
    }
    return new Uint8Array(
      await platformCall("RSA-OAEP wrap", () =>
        subtle.encrypt(oaepParams(label), this.#key, asBufferSource(bytes)),
      ),
    );
  }

  /** Projections of the platform key and the mint-bound record. */
  algorithmName() {
    return this.#key.algorithm.name;
  }

  algorithmHash() {
    return this.#algorithm.hash;
  }

  algorithmLength() {
    return this.#algorithm.modulusLength;
  }

  /**
   * The public exponent's big-endian bytes, from the platform key's own
   * `RsaKeyAlgorithm.publicExponent`.
   * @returns {Uint8Array | undefined}
   */
  algorithmPublicExponent() {
    const e = /** @type {RsaHashedKeyAlgorithm} */ (this.#key.algorithm).publicExponent;
    return e === undefined ? undefined : new Uint8Array(e);
  }

  /**
   * RSA public keys have no raw form (see `VerifyingKey.exportKeyRaw`).
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyRaw() {
    throw errUnsupported("RSA public keys have no raw form");
  }

  /**
   * The SubjectPublicKeyInfo form. No extractability gate (see
   * `VerifyingKey.exportKeySpki` for the residual fallibility).
   * @returns {Promise<Uint8Array>}
   */
  async exportKeySpki() {
    return new Uint8Array(
      await platformCall("spki key export", () => subtle.exportKey("spki", this.#key)),
    );
  }

  /**
   * The public RSA JWK, material members only (`kty`, `n`, `e`) per the
   * package-wide JWK contract.
   */
  async exportKeyJwk() {
    const jwk = await platformCall("jwk key export", () => subtle.exportKey("jwk", this.#key));
    return JSON.stringify({ kty: jwk.kty, n: jwk.n, e: jwk.e });
  }
}

/**
 * The usage grants recorded at mint for each `decryption-key` (the
 * `aeadKeyGrants` pattern: both `decrypt` and `unwrap` run
 * `subtle.decrypt`, so the platform usages cannot carry the WIT grants
 * one-to-one — see `oaepPrivateUsages` — and they are enforced host-side
 * against this record).
 * @type {WeakMap<DecryptionKey, { decrypt: boolean, unwrap: boolean }>}
 */
const decryptionKeyGrants = new WeakMap();

const decryptionGrantsOf = stateReader(decryptionKeyGrants, "decryption-key");

/**
 * The `decryption-key` resource: a private RSA-OAEP `CryptoKey`, the
 * mint-bound algorithm record, and the recorded WIT grants. The WIT
 * `extractable` flag is carried by the platform key itself (passed
 * through at import/generation), so the platform enforces
 * non-extractability; instances are minted only by the `rsa-oaep-decrypt`
 * interface functions below.
 */
export class DecryptionKey extends keyResourceTail({}) {
  #algorithm;

  /**
   * @param {CryptoKey} privateKey
   * @param {OaepAlgorithm} algorithm the mint-bound algorithm record
   * @param {{ decrypt: boolean, unwrap: boolean }} grants
   */
  constructor(privateKey, algorithm, grants) {
    super(privateKey);
    this.#algorithm = algorithm;
    decryptionKeyGrants.set(this, grants);
  }

  /**
   * Decrypt a ciphertext produced by the matching public key under the
   * same `label`. Throws `{ tag: 'not-permitted' }` without the `decrypt`
   * grant; every decryption failure is the one detail-free
   * `{ tag: 'authentication-failed' }` (see `oaepDecrypt`).
   * @param {Uint8Array | undefined} label
   * @param {Uint8Array} ciphertext
   */
  async decrypt(label, ciphertext) {
    if (!this.canDecrypt()) throw notPermitted("decrypt");
    return oaepDecrypt(platformKeyOf(this), label, ciphertext);
  }

  /**
   * Decrypt wrapped key material into an `unwrap-input` for a typed
   * unwrap mint, eagerly (the bytes never reach the guest). Throws
   * `{ tag: 'not-permitted' }` without the `unwrap` grant; failures are
   * otherwise `decrypt`'s.
   * @param {Uint8Array | undefined} label
   * @param {Uint8Array} ciphertext
   * @returns {Promise<UnwrapInput>}
   */
  async unwrap(label, ciphertext) {
    if (!this.canUnwrap()) throw notPermitted("unwrap");
    return new UnwrapInput(MINT, await oaepDecrypt(platformKeyOf(this), label, ciphertext));
  }

  /** Projections of the platform key and the mint-bound record. */
  algorithmName() {
    return platformKeyOf(this).algorithm.name;
  }

  algorithmHash() {
    return this.#algorithm.hash;
  }

  algorithmLength() {
    return this.#algorithm.modulusLength;
  }

  /**
   * See `EncryptionKey.algorithmPublicExponent`.
   * @returns {Uint8Array | undefined}
   */
  algorithmPublicExponent() {
    const e = /** @type {RsaHashedKeyAlgorithm} */ (platformKeyOf(this).algorithm).publicExponent;
    return e === undefined ? undefined : new Uint8Array(e);
  }

  /** The usage grants: the mint policy recorded in `decryptionKeyGrants`. */
  canDecrypt() {
    return decryptionGrantsOf(this).decrypt;
  }

  canUnwrap() {
    return decryptionGrantsOf(this).unwrap;
  }

  /**
   * The private key as a full-CRT RSA JWK, material members only, behind
   * the extractability gate (checked on the `CryptoKey` itself, like
   * `exportRawGated`).
   */
  async exportKeyJwk() {
    const privateKey = platformKeyOf(this);
    if (!privateKey.extractable) throw errNotExtractable();
    const jwk = await platformCall("jwk key export", () => subtle.exportKey("jwk", privateKey));
    return JSON.stringify({
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
      d: jwk.d,
      p: jwk.p,
      q: jwk.q,
      dp: jwk.dp,
      dq: jwk.dq,
      qi: jwk.qi,
    });
  }

  /**
   * The PKCS#8 form, behind the same gate.
   * @returns {Promise<Uint8Array>}
   */
  async exportKeyPkcs8() {
    const privateKey = platformKeyOf(this);
    if (!privateKey.extractable) throw errNotExtractable();
    return new Uint8Array(
      await platformCall("pkcs8 key export", () => subtle.exportKey("pkcs8", privateKey)),
    );
  }

  /**
   * The private JWK serialization as a `wrap-input` (see the `wrapping`
   * interface), behind the same extractability gate as `exportKeyJwk`.
   */
  async toWrapInputJwk() {
    return new WrapInput(MINT, "jwk", utf8Encoder.encode(await this.exportKeyJwk()));
  }

  /**
   * The PKCS#8 serialization as a `wrap-input`, behind the same gate.
   */
  async toWrapInputPkcs8() {
    return new WrapInput(MINT, "pkcs8", await this.exportKeyPkcs8());
  }
}

/** The `polymorph:webcrypto/public-encryption` interface: its resource classes. */
export const publicEncryption = { EncryptionKey, DecryptionKey, DecryptionKeyOptions };

/**
 * The RSA-OAEP interfaces' modulus admission window, in bits (inclusive),
 * on both halves: encryption creates *future* artifacts, so unlike
 * signature verification there is no legacy tier below 2048 (see
 * `wit/rsa.wit`).
 */
const RSA_OAEP_MIN_BITS = 2048;
const RSA_OAEP_MAX_BITS = 8192;

/**
 * Import an RSA-OAEP public key of the declared variant from a
 * SubjectPublicKeyInfo. The AlgorithmIdentifier must be the
 * `rsaEncryption` form (see `requireRsaEncryptionSpki`); the platform
 * validates the DER, and the family admission checks run on the imported
 * key's metadata at the OAEP window (`rsaAdmittedModulusLength`; the
 * platform admits wider — a 1024-bit SPKI imports on Node 24).
 * @param {string} variant
 * @param {Uint8Array} spki
 */
async function importOaepEncryptionKeySpki(variant, spki) {
  const entry = served(RSA_VARIANTS, variant);
  requireRsaEncryptionSpki(spki);
  const key = await importPlatformKey(
    "RSA-OAEP spki",
    "spki",
    spki,
    { name: "RSA-OAEP", hash: entry.hash },
    true,
    ["encrypt"],
  );
  const modulusLength = rsaAdmittedModulusLength(
    key,
    "RSA-OAEP spki",
    RSA_OAEP_MIN_BITS,
    RSA_OAEP_MAX_BITS,
  );
  return new EncryptionKey(key, oaepAlgorithm(entry, modulusLength));
}

/**
 * Import an RSA-OAEP public key of the declared variant from an RSA
 * public JWK — a platform pass-through of the material members; the
 * platform owns the kty/alg/ext validation, including the
 * alg-against-variant rule the WIT pins (`"RSA-OAEP-256"`/`-384`/`-512`;
 * an `alg` that disagrees with the requested hash fails the platform
 * import with `DataError`). Strictness of the base64url members is pinned
 * host-side, and the OAEP window runs on the imported key's metadata.
 * @param {string} variant
 * @param {string} jwkText
 */
async function importOaepEncryptionKeyJwk(variant, jwkText) {
  const entry = served(RSA_VARIANTS, variant);
  const jwk = jwkMaterial(jwkText);
  requireStrictBase64url(jwk.n);
  requireStrictBase64url(jwk.e);
  const key = await importPlatformKeyJwk(
    "RSA-OAEP public JWK",
    jwk,
    { name: "RSA-OAEP", hash: entry.hash },
    true,
    ["encrypt"],
  );
  const modulusLength = rsaAdmittedModulusLength(
    key,
    "RSA-OAEP public JWK",
    RSA_OAEP_MIN_BITS,
    RSA_OAEP_MAX_BITS,
  );
  return new EncryptionKey(key, oaepAlgorithm(entry, modulusLength));
}

/** The `polymorph:webcrypto/rsa-oaep-encrypt` interface. */
export const rsaOaepEncrypt = {
  importEncryptionKeySpki: importOaepEncryptionKeySpki,
  importEncryptionKeyJwk: importOaepEncryptionKeyJwk,
};

/**
 * Generate a fresh RSA-OAEP key pair of the declared variant and modulus
 * length, returning `[decryption, encryption]`. The public exponent is
 * 65537 (the WIT fixes it; not a parameter). The platform pair is
 * generated with `["encrypt", "decrypt"]` — WebCrypto splits them so the
 * public key carries `encrypt` and the private key `decrypt` — and the
 * WIT grants are enforced host-side (see `oaepPrivateUsages`).
 * @param {string} variant
 * @param {string} modulus
 * @param {DecryptionKeyOptions} options
 * @returns {Promise<[DecryptionKey, EncryptionKey]>}
 */
async function generateOaepKey(variant, modulus, options) {
  requireRsaPrivateKeysServed();
  const policy = decryptionPolicy(options);
  oaepPrivateUsages(policy);
  const entry = served(RSA_VARIANTS, variant);
  const modulusLength = served(RSA_MODULUS_BITS, modulus);
  const pair = await platformCall("RSA-OAEP key generation", () =>
    subtle.generateKey(
      {
        name: "RSA-OAEP",
        hash: entry.hash,
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
      },
      policy.extractable,
      ["encrypt", "decrypt"],
    ),
  );
  const algorithm = oaepAlgorithm(entry, modulusLength);
  return [
    new DecryptionKey(pair.privateKey, algorithm, oaepGrants(policy)),
    new EncryptionKey(pair.publicKey, algorithm),
  ];
}

/**
 * Import an RSA-OAEP decryption key of the declared variant from a PKCS#8
 * PrivateKeyInfo. The platform validates the DER — including the
 * rsaEncryption-only algorithm rule the WebCrypto import steps mandate —
 * and the OAEP window runs on the imported key's metadata
 * (`rsaAdmittedModulusLength`; the platform admits wider).
 * @param {string} variant
 * @param {Uint8Array} pkcs8
 * @param {DecryptionKeyOptions} options
 */
async function importOaepDecryptionKeyPkcs8(variant, pkcs8, options) {
  requireRsaPrivateKeysServed();
  const policy = decryptionPolicy(options);
  const usages = oaepPrivateUsages(policy);
  const entry = served(RSA_VARIANTS, variant);
  const key = await importPlatformKey(
    "RSA-OAEP pkcs8",
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: entry.hash },
    policy.extractable,
    usages,
  );
  const modulusLength = rsaAdmittedModulusLength(
    key,
    "RSA-OAEP pkcs8",
    RSA_OAEP_MIN_BITS,
    RSA_OAEP_MAX_BITS,
  );
  return new DecryptionKey(key, oaepAlgorithm(entry, modulusLength), oaepGrants(policy));
}

/**
 * Import an RSA-OAEP decryption key of the declared variant from an RSA
 * private JWK — a platform pass-through of the material members. The
 * platform owns the kty/alg/ext validation (including the
 * alg-against-variant rule, as on the `-encrypt` path) and the full-CRT
 * requirement the WIT pins: a `d`-only or partial-CRT private JWK fails
 * the platform import with `DataError`. Strictness of the base64url
 * members is pinned host-side, and the OAEP window runs on the imported
 * key's metadata.
 * @param {string} variant
 * @param {string} jwkText
 * @param {DecryptionKeyOptions} options
 */
async function importOaepDecryptionKeyJwk(variant, jwkText, options) {
  requireRsaPrivateKeysServed();
  const policy = decryptionPolicy(options);
  const usages = oaepPrivateUsages(policy);
  const entry = served(RSA_VARIANTS, variant);
  const jwk = jwkMaterial(jwkText);
  for (const member of ["n", "e", "d", "p", "q", "dp", "dq", "qi"]) {
    requireStrictBase64url(jwk[member]);
  }
  const key = await importPlatformKeyJwk(
    "RSA-OAEP private JWK",
    jwk,
    { name: "RSA-OAEP", hash: entry.hash },
    policy.extractable,
    usages,
  );
  if (key.type !== "private") {
    throw errInvalidKey("RSA private JWK must carry `d` and the CRT members");
  }
  const modulusLength = rsaAdmittedModulusLength(
    key,
    "RSA-OAEP private JWK",
    RSA_OAEP_MIN_BITS,
    RSA_OAEP_MAX_BITS,
  );
  return new DecryptionKey(key, oaepAlgorithm(entry, modulusLength), oaepGrants(policy));
}

/**
 * Mint an RSA-OAEP decryption key of the declared variant from unwrapped
 * key material read as a PKCS#8 PrivateKeyInfo (see
 * `unwrapEd25519SigningKeyPkcs8` for the consume-first and redaction
 * mechanics).
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {DecryptionKeyOptions} options
 */
async function unwrapOaepDecryptionKeyPkcs8(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  return redactingInvalidKey("unwrapped RSA-OAEP pkcs8", () =>
    importOaepDecryptionKeyPkcs8(variant, bytes, options),
  );
}

/**
 * Mint an RSA-OAEP decryption key of the declared variant from unwrapped
 * key material read as an RSA private JWK: the unwrap-path
 * `use`/`key_ops` checks (see `unwrappedJwk`; the granted operations'
 * platform names come from `oaepGrantedOps`), then the import path.
 * @param {string} variant
 * @param {UnwrapInput} input
 * @param {DecryptionKeyOptions} options
 */
async function unwrapOaepDecryptionKeyJwk(variant, input, options) {
  const { bytes } = consumeUnwrapInput(input);
  const policy = decryptionPolicy(options);
  oaepPrivateUsages(policy);
  const jwk = unwrappedJwk(bytes, "enc", oaepGrantedOps(policy));
  return redactingInvalidKey("unwrapped RSA-OAEP private JWK", () =>
    importOaepDecryptionKeyJwk(variant, jwk, options),
  );
}

/** The `polymorph:webcrypto/rsa-oaep-decrypt` interface. */
export const rsaOaepDecrypt = {
  generateKey: generateOaepKey,
  importDecryptionKeyPkcs8: importOaepDecryptionKeyPkcs8,
  importDecryptionKeyJwk: importOaepDecryptionKeyJwk,
  unwrapDecryptionKeyPkcs8: unwrapOaepDecryptionKeyPkcs8,
  unwrapDecryptionKeyJwk: unwrapOaepDecryptionKeyJwk,
};

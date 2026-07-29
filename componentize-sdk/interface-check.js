// @ts-check
//
// The Web Cryptography API conformance assertions: this library's exported
// surface against the definitions TypeScript ships.
//
// This module is never imported at runtime; nothing here has an effect. It
// exists so that `tsc --noEmit` reports a surface that has drifted off the
// API it claims to mirror. Nothing is generated to check against — the
// reference is `lib.dom.d.ts` — so there is no staleness question.
//
// What this does *not* check is the library's documented deviations, which
// are runtime restrictions on values, not on shapes: HMAC-SHA-256 and
// AES-256-GCM only, `"raw"` format only, the `tagLength` rules. Those are
// the WPT suite's job (`just test-webcrypto-componentize-wpt`). The split is
// deliberate: types pin the shape, the vendored web-platform-tests pin the
// behaviour, and both describe the same surface.

import { CryptoKey, crypto, subtle } from "./webcrypto.js";

/**
 * The `SubtleCrypto` methods this library serves with the standard's own
 * signature. Naming them here is what makes the subset a checked claim: a
 * method added to the module without being added to this list is unasserted,
 * and one listed but unimplemented fails the assignment below.
 *
 * `generateKey` and `exportKey` are absent deliberately — see below.
 * @typedef {"importKey" | "sign" | "verify" | "encrypt" | "decrypt"} ServedMethods
 */

/** @type {Pick<SubtleCrypto, ServedMethods>} */
const subtleServesWebCrypto = subtle;

/** @type {{ subtle: Pick<SubtleCrypto, ServedMethods> }} */
const cryptoServesWebCrypto = crypto;

/**
 * Two methods are asserted against the single overload they serve rather
 * than against the whole set. The standard uses those overloads to
 * distinguish algorithm families and key formats this library does not span,
 * so the narrower assertions are the true ones — and each puts a documented
 * deviation into the type rather than leaving it only in the README.
 *
 * `generateKey` returns a `CryptoKeyPair` for the asymmetric families and a
 * `CryptoKey` for the secret-key ones; this library serves HMAC and AES-GCM,
 * so it only ever returns a key.
 * @type {(algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params, extractable: boolean, keyUsages: ReadonlyArray<KeyUsage>) => Promise<globalThis.CryptoKey>}
 */
const generateKeyServesSecretKeyOverload = subtle.generateKey;

/**
 * `exportKey` also declares the `"jwk"` form returning a `JsonWebKey`, and
 * satisfying every overload would mean claiming a return type that is an
 * `ArrayBuffer` and a `JsonWebKey` at once. This library declines every
 * non-`"raw"` format at runtime.
 * @type {(format: Exclude<KeyFormat, "jwk">, key: globalThis.CryptoKey) => Promise<ArrayBuffer>}
 */
const exportKeyServesRawOverload = subtle.exportKey;

/**
 * Every key this library mints is a `CryptoKey` in the platform's sense.
 * Asserted as an assignment, never a cast: a cast succeeds when the two
 * types are related in either direction, which would accept a key missing
 * half the interface.
 *
 * The converse does not hold, and should not: the methods above accept any
 * platform `CryptoKey`, as the API declares, and reject at runtime the ones
 * this library did not mint.
 * @type {(key: CryptoKey) => globalThis.CryptoKey}
 */
const keyServesCryptoKey = (key) => key;

export const checked = {
  subtleServesWebCrypto,
  cryptoServesWebCrypto,
  generateKeyServesSecretKeyOverload,
  exportKeyServesRawOverload,
  keyServesCryptoKey,
};

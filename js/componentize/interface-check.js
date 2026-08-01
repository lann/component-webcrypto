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
// AES-256-GCM only, `"raw"`/`"jwk"` formats only, the `tagLength` rules. Those are
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
 * @typedef {"importKey" | "sign" | "verify" | "encrypt" | "decrypt" | "deriveBits" | "deriveKey" | "digest"} ServedMethods
 */

/** @type {Pick<SubtleCrypto, ServedMethods>} */
const subtleServesWebCrypto = subtle;

/** @type {{ subtle: Pick<SubtleCrypto, ServedMethods>, getRandomValues: Crypto["getRandomValues"] }} */
const cryptoServesWebCrypto = crypto;

/**
 * Two methods are asserted against the single overload they serve rather
 * than against the whole set. The standard uses those overloads to
 * distinguish algorithm families and key formats this library does not span,
 * so the narrower assertions are the true ones — and each puts a documented
 * deviation into the type rather than leaving it only in the README.
 *
 * `generateKey` returns a `CryptoKeyPair` for the asymmetric families and a
 * `CryptoKey` for the secret-key ones; this library serves both (X25519
 * beside HMAC and AES-GCM), so it is asserted against the standard's
 * catch-all overload.
 * @type {(algorithm: AlgorithmIdentifier, extractable: boolean, keyUsages: ReadonlyArray<KeyUsage>) => Promise<globalThis.CryptoKeyPair | globalThis.CryptoKey>}
 */
const generateKeyServesCatchAllOverload = subtle.generateKey;

/**
 * `exportKey`'s TS declaration is overloaded — `"jwk"` returns a
 * `JsonWebKey`, the buffer formats an `ArrayBuffer` — and the library's
 * implementation declares matching `@overload`s, so each shape is asserted
 * as a plain assignment.
 * @type {(format: Exclude<KeyFormat, "jwk">, key: globalThis.CryptoKey) => Promise<ArrayBuffer>}
 */
const exportKeyServesRawOverload = subtle.exportKey;
/** @type {(format: "jwk", key: globalThis.CryptoKey) => Promise<JsonWebKey>} */
const exportKeyServesJwkOverload = subtle.exportKey;
void exportKeyServesJwkOverload;

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
  generateKeyServesCatchAllOverload,
  exportKeyServesRawOverload,
  keyServesCryptoKey,
};

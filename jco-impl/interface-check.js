// @ts-check
//
// The interface-conformance assertions: `webcrypto.js` against the
// definitions jco derives from the `lann:webcrypto` package.
//
// This module is never imported at runtime — `package.json` exposes only
// `webcrypto.js`, and nothing here has an effect. It exists so that
// `tsc --noEmit` reports a host that no longer matches the WIT: a renamed
// method, a dropped getter, a parameter or return type that drifted.
// `generated/` is produced from `wit/` on demand (`npm run types`), so there
// is no checked-in copy of the definitions to go stale.
//
// Every assertion is an *assignment*, never a cast: a cast succeeds when the
// two types are related in either direction, which would accept a host
// missing half the interface.
//
// The grouping mirrors the `jco transpile --map` flags this host is wired in
// with — resource-bearing interfaces map to the module itself, minting and
// utility interfaces to named exports.

import {
  AeadKey,
  Digest,
  InternalNonceKey,
  MacKey,
  SigningKey,
  VerifyingKey,
  aesGcm,
  aesGcmInternalNonce,
  bytes,
  chacha20Poly1305,
  ecdsaSign,
  ecdsaVerify,
  ed25519Sign,
  ed25519Verify,
  hmacSha2,
  sha2,
  xchacha20Poly1305,
  xchachaInternalNonce,
} from "./webcrypto.js";

/** @import * as Mac from "./generated/interfaces/lann-webcrypto-mac.js" */
/** @import * as Aead from "./generated/interfaces/lann-webcrypto-aead.js" */
/** @import * as AeadInternalNonce from "./generated/interfaces/lann-webcrypto-aead-internal-nonce.js" */
/** @import * as DigestInterface from "./generated/interfaces/lann-webcrypto-digest.js" */
/** @import * as Signature from "./generated/interfaces/lann-webcrypto-signature.js" */

// --- resource-bearing interfaces -------------------------------------------
//
// Asserted on the instance type. The generated classes declare a private
// constructor — this host's minting functions stand in for it — so the
// assertion is that every instance this host mints serves the interface,
// not that the two constructors match.

/** @type {(key: MacKey) => Mac.MacKey} */
const macKeyServesMac = (key) => key;

/** @type {(key: AeadKey) => Aead.AeadKey} */
const aeadKeyServesAead = (key) => key;

/** @type {(key: InternalNonceKey) => AeadInternalNonce.InternalNonceKey} */
const internalNonceKeyServesAeadInternalNonce = (key) => key;

/** @type {(digest: Digest) => DigestInterface.Digest} */
const digestServesDigest = (digest) => digest;

/** @type {(key: VerifyingKey) => Signature.VerifyingKey} */
const verifyingKeyServesSignature = (key) => key;

/** @type {(key: SigningKey) => Signature.SigningKey} */
const signingKeyServesSignature = (key) => key;

// --- minting and utility interfaces ----------------------------------------

/** @type {typeof import("./generated/interfaces/lann-webcrypto-hmac-sha2.js")} */
const hmacSha2Interface = hmacSha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-sha2.js")} */
const sha2Interface = sha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-bytes.js")} */
const bytesInterface = bytes;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-gcm.js")} */
const aesGcmInterface = aesGcm;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-gcm-internal-nonce.js")} */
const aesGcmInternalNonceInterface = aesGcmInternalNonce;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-chacha20-poly1305.js")} */
const chacha20Poly1305Interface = chacha20Poly1305;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-xchacha20-poly1305.js")} */
const xchacha20Poly1305Interface = xchacha20Poly1305;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-xchacha20-poly1305-internal-nonce.js")} */
const xchachaInternalNonceInterface = xchachaInternalNonce;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ed25519-verify.js")} */
const ed25519VerifyInterface = ed25519Verify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ed25519-sign.js")} */
const ed25519SignInterface = ed25519Sign;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ecdsa-verify.js")} */
const ecdsaVerifyInterface = ecdsaVerify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ecdsa-sign.js")} */
const ecdsaSignInterface = ecdsaSign;

export const checked = {
  macKeyServesMac,
  aeadKeyServesAead,
  internalNonceKeyServesAeadInternalNonce,
  digestServesDigest,
  verifyingKeyServesSignature,
  signingKeyServesSignature,
  hmacSha2Interface,
  sha2Interface,
  bytesInterface,
  aesGcmInterface,
  aesGcmInternalNonceInterface,
  chacha20Poly1305Interface,
  xchacha20Poly1305Interface,
  xchachaInternalNonceInterface,
  ed25519VerifyInterface,
  ed25519SignInterface,
  ecdsaVerifyInterface,
  ecdsaSignInterface,
};

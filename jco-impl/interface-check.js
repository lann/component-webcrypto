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
// The grouping mirrors the wildcard `--map` convention this host is wired
// in with — every interface is a camelCased named export; the
// resource-bearing interfaces export objects holding their resource
// classes, asserted here on the instance types.

import {
  AeadKey,
  DeriveInput,
  DeriveOptions,
  Digest,
  Ikm,
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
  hkdf,
  hmacSha2,
  sha2,
  xchacha20Poly1305,
  xchacha20Poly1305InternalNonce,
} from "./webcrypto.js";

/** @import * as Mac from "./generated/interfaces/lann-webcrypto-mac.js" */
/** @import * as Aead from "./generated/interfaces/lann-webcrypto-aead.js" */
/** @import * as AeadInternalNonce from "./generated/interfaces/lann-webcrypto-aead-internal-nonce.js" */
/** @import * as DigestInterface from "./generated/interfaces/lann-webcrypto-digest.js" */
/** @import * as Signature from "./generated/interfaces/lann-webcrypto-signature.js" */
/** @import * as Derivation from "./generated/interfaces/lann-webcrypto-derivation.js" */
/** @import * as Hkdf from "./generated/interfaces/lann-webcrypto-hkdf.js" */

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

/** @type {(options: DeriveOptions) => Derivation.DeriveOptions} */
const deriveOptionsServeDerivation = (options) => options;

/**
 * Both directions, deliberately: `derive-input` and `ikm` appear as
 * *parameters* of other interfaces' functions, so the generated instances
 * must be assignable to this host's classes too (which is why their state
 * lives in WeakMaps rather than private fields).
 * @type {(input: DeriveInput) => Derivation.DeriveInput}
 */
const deriveInputServesDerivation = (input) => input;

/** @type {(input: Derivation.DeriveInput) => DeriveInput} */
const derivationServesDeriveInput = (input) => input;

/** @type {(ikm: Ikm) => Hkdf.Ikm} */
const ikmServesHkdf = (ikm) => ikm;

/** @type {(ikm: Hkdf.Ikm) => Ikm} */
const hkdfServesIkm = (ikm) => ikm;

// --- minting and utility interfaces ----------------------------------------

/**
 * `Omit` of the resource class, like the instance-type assertions above:
 * the generated `ikm` declares a private constructor that this host's
 * mint-token constructor cannot match, and the instance assertions carry
 * the class. The functions are what a namespace assertion buys here.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-hkdf.js"), "Ikm">}
 */
const hkdfInterface = hkdf;

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
const xchacha20Poly1305InternalNonceInterface = xchacha20Poly1305InternalNonce;

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
  deriveOptionsServeDerivation,
  deriveInputServesDerivation,
  derivationServesDeriveInput,
  ikmServesHkdf,
  hkdfServesIkm,
  hkdfInterface,
  hmacSha2Interface,
  sha2Interface,
  bytesInterface,
  aesGcmInterface,
  aesGcmInternalNonceInterface,
  chacha20Poly1305Interface,
  xchacha20Poly1305Interface,
  xchacha20Poly1305InternalNonceInterface,
  ed25519VerifyInterface,
  ed25519SignInterface,
  ecdsaVerifyInterface,
  ecdsaSignInterface,
};

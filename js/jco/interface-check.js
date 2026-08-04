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
  AgreementKeyOptions,
  AgreementPublicKey,
  AgreementSecretKey,
  DecryptionKey,
  DeriveInput,
  DeriveOptions,
  Digest,
  EncryptionKey,
  Ikm,
  KwKey,
  MacKey,
  Password,
  SigningKey,
  UnwrapInput,
  VerifyingKey,
  WrapInput,
  aesCbc,
  aesCtr,
  aesGcm,
  aesKw,
  ecdh,
  ecdsaSign,
  ecdsaVerify,
  ed25519Sign,
  ed25519Verify,
  hkdf,
  hkdfSha1,
  hkdfSha2,
  keyWrap,
  pbkdf2,
  pbkdf2Sha1,
  pbkdf2Sha2,
  publicEncryption,
  rsaOaepDecrypt,
  rsaOaepEncrypt,
  rsaPssSign,
  rsaPssVerify,
  rsassaPkcs1V15Sign,
  rsassaPkcs1V15Verify,
  hmacSha1,
  hmacSha2,
  sha2,
  sha1Checked,
  wrapping,
  x25519,
} from "./webcrypto.js";

/** @import * as Mac from "./generated/interfaces/lann-webcrypto-mac.js" */
/** @import * as Aead from "./generated/interfaces/lann-webcrypto-aead.js" */
/** @import * as DigestInterface from "./generated/interfaces/lann-webcrypto-digest.js" */
/** @import * as Signature from "./generated/interfaces/lann-webcrypto-signature.js" */
/** @import * as Derivation from "./generated/interfaces/lann-webcrypto-derivation.js" */
/** @import * as Hkdf from "./generated/interfaces/lann-webcrypto-hkdf.js" */
/** @import * as Pbkdf2 from "./generated/interfaces/lann-webcrypto-pbkdf2.js" */
/** @import * as KeyAgreement from "./generated/interfaces/lann-webcrypto-key-agreement.js" */
/** @import * as KeyWrap from "./generated/interfaces/lann-webcrypto-key-wrap.js" */
/** @import * as PublicEncryption from "./generated/interfaces/lann-webcrypto-public-encryption.js" */
/** @import * as Wrapping from "./generated/interfaces/lann-webcrypto-wrapping.js" */

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

/** @type {(password: Password) => Pbkdf2.Password} */
const passwordServesPbkdf2 = (password) => password;

/** @type {(password: Pbkdf2.Password) => Password} */
const pbkdf2ServesPassword = (password) => password;

/** @type {(options: AgreementKeyOptions) => KeyAgreement.AgreementKeyOptions} */
const agreementKeyOptionsServeKeyAgreement = (options) => options;

/**
 * Both directions, like `derive-input`: `public-key` appears as a
 * *parameter* (`agree`'s peer), so the generated instances must be
 * assignable to this host's class too.
 * @type {(key: AgreementPublicKey) => KeyAgreement.PublicKey}
 */
const agreementPublicKeyServesKeyAgreement = (key) => key;

/** @type {(key: KeyAgreement.PublicKey) => AgreementPublicKey} */
const keyAgreementServesAgreementPublicKey = (key) => key;

/** @type {(key: AgreementSecretKey) => KeyAgreement.SecretKey} */
const agreementSecretKeyServesKeyAgreement = (key) => key;

/**
 * Both directions, like `derive-input`: `wrap-input` and `unwrap-input`
 * appear as *parameters* of other interfaces' functions (`wrap` and the
 * unwrap mints), so the generated instances must be assignable to this
 * host's classes too.
 * @type {(input: WrapInput) => Wrapping.WrapInput}
 */
const wrapInputServesWrapping = (input) => input;

/** @type {(input: Wrapping.WrapInput) => WrapInput} */
const wrappingServesWrapInput = (input) => input;

/** @type {(input: UnwrapInput) => Wrapping.UnwrapInput} */
const unwrapInputServesWrapping = (input) => input;

/** @type {(input: Wrapping.UnwrapInput) => UnwrapInput} */
const wrappingServesUnwrapInput = (input) => input;

/** @type {(key: KwKey) => KeyWrap.KwKey} */
const kwKeyServesKeyWrap = (key) => key;

/** @type {(key: EncryptionKey) => PublicEncryption.EncryptionKey} */
const encryptionKeyServesPublicEncryption = (key) => key;

/** @type {(key: DecryptionKey) => PublicEncryption.DecryptionKey} */
const decryptionKeyServesPublicEncryption = (key) => key;

// --- minting and utility interfaces ----------------------------------------

/**
 * `Omit` of the resource class, like the instance-type assertions above:
 * the generated `ikm` declares a private constructor that this host's
 * mint-token constructor cannot match, and the instance assertions carry
 * the class. The functions are what a namespace assertion buys here.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-hkdf.js"), "Ikm">}
 */
const hkdfInterface = hkdf;

/**
 * See `hkdfInterface`: the resource class is carried by the instance
 * assertions above.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-pbkdf2.js"), "Password">}
 */
const pbkdf2Interface = pbkdf2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-hmac-sha2.js")} */
const hmacSha2Interface = hmacSha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-hmac-sha1.js")} */
const hmacSha1Interface = hmacSha1;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-hkdf-sha1.js")} */
const hkdfSha1Interface = hkdfSha1;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-hkdf-sha2.js")} */
const hkdfSha2Interface = hkdfSha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-pbkdf2-sha2.js")} */
const pbkdf2Sha2Interface = pbkdf2Sha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-pbkdf2-sha1.js")} */
const pbkdf2Sha1Interface = pbkdf2Sha1;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-sha2.js")} */
const sha2Interface = sha2;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-sha1-checked.js")} */
const sha1CheckedInterface = sha1Checked;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-gcm.js")} */
const aesGcmInterface = aesGcm;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-cbc.js")} */
const aesCbcInterface = aesCbc;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-ctr.js")} */
const aesCtrInterface = aesCtr;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ed25519-verify.js")} */
const ed25519VerifyInterface = ed25519Verify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ed25519-sign.js")} */
const ed25519SignInterface = ed25519Sign;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ecdsa-verify.js")} */
const ecdsaVerifyInterface = ecdsaVerify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ecdsa-sign.js")} */
const ecdsaSignInterface = ecdsaSign;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsassa-pkcs1-v15-verify.js")} */
const rsassaPkcs1V15VerifyInterface = rsassaPkcs1V15Verify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsa-pss-verify.js")} */
const rsaPssVerifyInterface = rsaPssVerify;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsassa-pkcs1-v15-sign.js")} */
const rsassaPkcs1V15SignInterface = rsassaPkcs1V15Sign;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsa-pss-sign.js")} */
const rsaPssSignInterface = rsaPssSign;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-x25519.js")} */
const x25519Interface = x25519;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-ecdh.js")} */
const ecdhInterface = ecdh;

/**
 * `Omit` of the token-constructor resource classes, like `hkdfInterface`:
 * the instance assertions above carry them.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-wrapping.js"), "WrapInput" | "UnwrapInput">}
 */
const wrappingInterface = wrapping;

/**
 * See `wrappingInterface`; `KwKeyOptions` has a public constructor, so
 * only `KwKey` is carried by its instance assertion.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-key-wrap.js"), "KwKey">}
 */
const keyWrapInterface = keyWrap;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-aes-kw.js")} */
const aesKwInterface = aesKw;

/**
 * See `wrappingInterface`; `DecryptionKeyOptions` has a public
 * constructor, so only the key classes are carried by their instance
 * assertions.
 * @type {Omit<typeof import("./generated/interfaces/lann-webcrypto-public-encryption.js"), "EncryptionKey" | "DecryptionKey">}
 */
const publicEncryptionInterface = publicEncryption;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsa-oaep-encrypt.js")} */
const rsaOaepEncryptInterface = rsaOaepEncrypt;

/** @type {typeof import("./generated/interfaces/lann-webcrypto-rsa-oaep-decrypt.js")} */
const rsaOaepDecryptInterface = rsaOaepDecrypt;

export const checked = {
  macKeyServesMac,
  aeadKeyServesAead,
  digestServesDigest,
  verifyingKeyServesSignature,
  signingKeyServesSignature,
  deriveOptionsServeDerivation,
  deriveInputServesDerivation,
  derivationServesDeriveInput,
  ikmServesHkdf,
  hkdfServesIkm,
  hkdfInterface,
  pbkdf2Interface,
  passwordServesPbkdf2,
  pbkdf2ServesPassword,
  agreementKeyOptionsServeKeyAgreement,
  agreementPublicKeyServesKeyAgreement,
  keyAgreementServesAgreementPublicKey,
  agreementSecretKeyServesKeyAgreement,
  wrapInputServesWrapping,
  wrappingServesWrapInput,
  unwrapInputServesWrapping,
  wrappingServesUnwrapInput,
  kwKeyServesKeyWrap,
  wrappingInterface,
  keyWrapInterface,
  aesKwInterface,
  hmacSha2Interface,
  sha2Interface,
  aesGcmInterface,
  ed25519VerifyInterface,
  ed25519SignInterface,
  ecdsaVerifyInterface,
  ecdsaSignInterface,
  rsassaPkcs1V15VerifyInterface,
  rsaPssVerifyInterface,
  rsassaPkcs1V15SignInterface,
  rsaPssSignInterface,
  encryptionKeyServesPublicEncryption,
  decryptionKeyServesPublicEncryption,
  publicEncryptionInterface,
  rsaOaepEncryptInterface,
  rsaOaepDecryptInterface,
  x25519Interface,
  ecdhInterface,
};

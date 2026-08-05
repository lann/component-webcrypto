// The module specifiers componentize-js resolves against the component's
// world, declared untyped on purpose.
//
// There is no definition of these to check against. `jco types` emits some,
// but they describe *jco's* JS lowering, and the two toolchains differ where
// it matters most here: jco lowers `stream<u8>` to a web
// `ReadableStream<number>`, while componentize-js hands the guest the paired
// handles `wit-world`'s `u8Stream()` mints. Pointing this file at jco's
// output would assert that difference away — a confident type where the
// truth is that nothing here is verified except by componentizing and
// running (`just wpt::test`).
declare module "polymorph:webcrypto/hmac-sha2@0.1.0";
declare module "polymorph:webcrypto/hmac-sha1@0.1.0";
declare module "polymorph:webcrypto/aes-gcm@0.1.0";
declare module "polymorph:webcrypto/aes-cbc@0.1.0";
declare module "polymorph:webcrypto/aes-ctr@0.1.0";
declare module "polymorph:webcrypto/aes-kw@0.1.0";
declare module "polymorph:webcrypto/wrapping@0.1.0";
declare module "polymorph:webcrypto/key-wrap@0.1.0";
declare module "polymorph:webcrypto/cipher@0.1.0";
declare module "polymorph:webcrypto/mac@0.1.0";
declare module "polymorph:webcrypto/aead@0.1.0";
declare module "polymorph:webcrypto/derivation@0.1.0";
declare module "polymorph:webcrypto/hkdf@0.1.0";
declare module "polymorph:webcrypto/hkdf-sha2@0.1.0";
declare module "polymorph:webcrypto/hkdf-sha1@0.1.0";
declare module "polymorph:webcrypto/pbkdf2@0.1.0";
declare module "polymorph:webcrypto/pbkdf2-sha2@0.1.0";
declare module "polymorph:webcrypto/pbkdf2-sha1@0.1.0";
declare module "polymorph:webcrypto/key-agreement@0.1.0";
declare module "polymorph:webcrypto/x25519@0.1.0";
declare module "polymorph:webcrypto/ecdh@0.1.0";
declare module "polymorph:webcrypto/sha2@0.1.0";
declare module "polymorph:webcrypto/sha1-checked@0.1.0";
declare module "polymorph:webcrypto/digest@0.1.0";
declare module "polymorph:webcrypto/signature@0.1.0";
declare module "polymorph:webcrypto/ed25519-verify@0.1.0";
declare module "polymorph:webcrypto/ed25519-sign@0.1.0";
declare module "polymorph:webcrypto/ecdsa-verify@0.1.0";
declare module "polymorph:webcrypto/rsassa-pkcs1-v15-verify@0.1.0";
declare module "polymorph:webcrypto/rsa-pss-verify@0.1.0";
declare module "wasi:random/random@0.2.0";
declare module "wit-world";

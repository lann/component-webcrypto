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
declare module "lann:webcrypto/hmac-sha2@0.1.0";
declare module "lann:webcrypto/hmac-sha1@0.1.0";
declare module "lann:webcrypto/aes-gcm@0.1.0";
declare module "lann:webcrypto/aes-cbc@0.1.0";
declare module "lann:webcrypto/aes-ctr@0.1.0";
declare module "lann:webcrypto/aes-kw@0.1.0";
declare module "lann:webcrypto/wrapping@0.1.0";
declare module "lann:webcrypto/key-wrap@0.1.0";
declare module "lann:webcrypto/chacha20-poly1305@0.1.0";
declare module "lann:webcrypto/cipher@0.1.0";
declare module "lann:webcrypto/mac@0.1.0";
declare module "lann:webcrypto/aead@0.1.0";
declare module "lann:webcrypto/derivation@0.1.0";
declare module "lann:webcrypto/hkdf@0.1.0";
declare module "lann:webcrypto/hkdf-sha2@0.1.0";
declare module "lann:webcrypto/hkdf-sha1@0.1.0";
declare module "lann:webcrypto/pbkdf2@0.1.0";
declare module "lann:webcrypto/pbkdf2-sha2@0.1.0";
declare module "lann:webcrypto/pbkdf2-sha1@0.1.0";
declare module "lann:webcrypto/key-agreement@0.1.0";
declare module "lann:webcrypto/x25519@0.1.0";
declare module "lann:webcrypto/ecdh@0.1.0";
declare module "lann:webcrypto/sha2@0.1.0";
declare module "lann:webcrypto/sha1-checked@0.1.0";
declare module "lann:webcrypto/digest@0.1.0";
declare module "lann:webcrypto/signature@0.1.0";
declare module "lann:webcrypto/ed25519-verify@0.1.0";
declare module "lann:webcrypto/ed25519-sign@0.1.0";
declare module "lann:webcrypto/ecdsa-verify@0.1.0";
declare module "wasi:random/random@0.2.0";
declare module "wit-world";

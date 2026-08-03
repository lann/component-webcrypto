/** @module Interface lann:webcrypto/ed25519-sign@0.1.0 **/
export function generateKey(options: SigningKeyOptions): Promise<[SigningKey, VerifyingKey]>;
export function importSigningKeyPkcs8(pkcs8: Uint8Array, options: SigningKeyOptions): Promise<SigningKey>;
export function importSigningKeyJwk(jwk: string, options: SigningKeyOptions): Promise<SigningKey>;
export function unwrapSigningKeyPkcs8(input: UnwrapInput, options: SigningKeyOptions): Promise<SigningKey>;
export function unwrapSigningKeyJwk(input: UnwrapInput, options: SigningKeyOptions): Promise<SigningKey>;
export type SigningKeyOptions = import('./lann-webcrypto-signature.js').SigningKeyOptions;
export type SigningKey = import('./lann-webcrypto-signature.js').SigningKey;
export type VerifyingKey = import('./lann-webcrypto-signature.js').VerifyingKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

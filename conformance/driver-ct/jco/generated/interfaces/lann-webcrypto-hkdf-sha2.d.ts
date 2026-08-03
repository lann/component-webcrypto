/** @module Interface lann:webcrypto/hkdf-sha2@0.1.0 **/
export function prepare(variant: Sha2Variant, input: Ikm, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput>;
export function prepareFrom(variant: Sha2Variant, input: DeriveInput, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput>;
export type Sha2Variant = import('./lann-webcrypto-sha2.js').Sha2Variant;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type Error = import('./lann-webcrypto-types.js').Error;
export type Ikm = import('./lann-webcrypto-hkdf.js').Ikm;

/** @module Interface lann:webcrypto/hkdf-sha1@0.1.0 **/
export function prepare(input: Ikm, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput>;
export function prepareFrom(input: DeriveInput, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput>;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type Error = import('./lann-webcrypto-types.js').Error;
export type Ikm = import('./lann-webcrypto-hkdf.js').Ikm;

/** @module Interface lann:webcrypto/pbkdf2-sha2@0.1.0 **/
export function prepare(variant: Sha2Variant, input: Password, salt: Uint8Array, iterations: number): Promise<DeriveInput>;
export type Sha2Variant = import('./lann-webcrypto-sha2.js').Sha2Variant;
export type Password = import('./lann-webcrypto-pbkdf2.js').Password;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type Error = import('./lann-webcrypto-types.js').Error;

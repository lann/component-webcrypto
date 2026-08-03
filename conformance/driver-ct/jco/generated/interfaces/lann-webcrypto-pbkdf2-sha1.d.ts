/** @module Interface lann:webcrypto/pbkdf2-sha1@0.1.0 **/
export function prepare(input: Password, salt: Uint8Array, iterations: number): Promise<DeriveInput>;
export type Password = import('./lann-webcrypto-pbkdf2.js').Password;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type Error = import('./lann-webcrypto-types.js').Error;

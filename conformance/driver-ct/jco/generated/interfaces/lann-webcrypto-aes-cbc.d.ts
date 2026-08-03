/** @module Interface lann:webcrypto/aes-cbc@0.1.0 **/
export function importKeyRaw(variant: AesVariant, raw: Uint8Array, options: CipherKeyOptions): Promise<CipherKey>;
export function importKeyJwk(variant: AesVariant, jwk: string, options: CipherKeyOptions): Promise<CipherKey>;
export function generateKey(variant: AesVariant, options: CipherKeyOptions): Promise<CipherKey>;
export function deriveKey(variant: AesVariant, input: DeriveInput, options: CipherKeyOptions): Promise<CipherKey>;
export function unwrapKeyRaw(variant: AesVariant, input: UnwrapInput, options: CipherKeyOptions): Promise<CipherKey>;
export type AesVariant = import('./lann-webcrypto-aes.js').AesVariant;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type CipherKeyOptions = import('./lann-webcrypto-cipher.js').CipherKeyOptions;
export type CipherKey = import('./lann-webcrypto-cipher.js').CipherKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

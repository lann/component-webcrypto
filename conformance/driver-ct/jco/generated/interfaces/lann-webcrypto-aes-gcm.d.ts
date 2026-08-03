/** @module Interface lann:webcrypto/aes-gcm@0.1.0 **/
export function importKeyRaw(variant: AesVariant, raw: Uint8Array, options: AeadKeyOptions): Promise<AeadKey>;
export function importKeyJwk(variant: AesVariant, jwk: string, options: AeadKeyOptions): Promise<AeadKey>;
export function generateKey(variant: AesVariant, options: AeadKeyOptions): Promise<AeadKey>;
export function deriveKey(variant: AesVariant, input: DeriveInput, options: AeadKeyOptions): Promise<AeadKey>;
export type AesVariant = import('./lann-webcrypto-aes.js').AesVariant;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type AeadKeyOptions = import('./lann-webcrypto-aead.js').AeadKeyOptions;
export type AeadKey = import('./lann-webcrypto-aead.js').AeadKey;
export type Error = import('./lann-webcrypto-types.js').Error;

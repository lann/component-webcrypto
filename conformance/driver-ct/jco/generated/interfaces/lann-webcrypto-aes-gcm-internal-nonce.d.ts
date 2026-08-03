/** @module Interface lann:webcrypto/aes-gcm-internal-nonce@0.1.0 **/
export function importKeyRaw(variant: AesVariant, raw: Uint8Array, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function importKeyJwk(variant: AesVariant, jwk: string, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function generateKey(variant: AesVariant, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function unwrapKeyRaw(variant: AesVariant, input: UnwrapInput, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function unwrapKeyJwk(variant: AesVariant, input: UnwrapInput, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export type AesVariant = import('./lann-webcrypto-aes.js').AesVariant;
export type InternalNonceKeyOptions = import('./lann-webcrypto-aead-internal-nonce.js').InternalNonceKeyOptions;
export type InternalNonceKey = import('./lann-webcrypto-aead-internal-nonce.js').InternalNonceKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

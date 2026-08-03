/** @module Interface lann:webcrypto/xchacha20-poly1305-internal-nonce@0.1.0 **/
export function importKeyRaw(raw: Uint8Array, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function generateKey(options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export function unwrapKeyRaw(input: UnwrapInput, options: InternalNonceKeyOptions): Promise<InternalNonceKey>;
export type InternalNonceKeyOptions = import('./lann-webcrypto-aead-internal-nonce.js').InternalNonceKeyOptions;
export type InternalNonceKey = import('./lann-webcrypto-aead-internal-nonce.js').InternalNonceKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

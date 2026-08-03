/** @module Interface lann:webcrypto/chacha20-poly1305@0.1.0 **/
export function importKeyRaw(raw: Uint8Array, options: AeadKeyOptions): Promise<AeadKey>;
export function importKeyJwk(jwk: string, options: AeadKeyOptions): Promise<AeadKey>;
export function generateKey(options: AeadKeyOptions): Promise<AeadKey>;
export function unwrapKeyRaw(input: UnwrapInput, options: AeadKeyOptions): Promise<AeadKey>;
export function unwrapKeyJwk(input: UnwrapInput, options: AeadKeyOptions): Promise<AeadKey>;
export type AeadKeyOptions = import('./lann-webcrypto-aead.js').AeadKeyOptions;
export type AeadKey = import('./lann-webcrypto-aead.js').AeadKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

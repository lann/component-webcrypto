/** @module Interface lann:webcrypto/aes-kw@0.1.0 **/
export function importKeyRaw(variant: AesVariant, raw: Uint8Array, options: KwKeyOptions): Promise<KwKey>;
export function importKeyJwk(variant: AesVariant, jwk: string, options: KwKeyOptions): Promise<KwKey>;
export function generateKey(variant: AesVariant, options: KwKeyOptions): Promise<KwKey>;
export type AesVariant = import('./lann-webcrypto-aes.js').AesVariant;
export type KwKeyOptions = import('./lann-webcrypto-key-wrap.js').KwKeyOptions;
export type KwKey = import('./lann-webcrypto-key-wrap.js').KwKey;
export type Error = import('./lann-webcrypto-types.js').Error;

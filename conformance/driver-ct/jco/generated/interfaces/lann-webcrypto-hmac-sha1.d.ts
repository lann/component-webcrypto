/** @module Interface lann:webcrypto/hmac-sha1@0.1.0 **/
export function importKeyRaw(raw: Uint8Array, options: MacKeyOptions): Promise<MacKey>;
export function importKeyJwk(jwk: string, options: MacKeyOptions): Promise<MacKey>;
export function generateKey(length: number | undefined, options: MacKeyOptions): Promise<MacKey>;
export function deriveKey(input: DeriveInput, length: number | undefined, options: MacKeyOptions): Promise<MacKey>;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type MacKeyOptions = import('./lann-webcrypto-mac.js').MacKeyOptions;
export type MacKey = import('./lann-webcrypto-mac.js').MacKey;
export type Error = import('./lann-webcrypto-types.js').Error;

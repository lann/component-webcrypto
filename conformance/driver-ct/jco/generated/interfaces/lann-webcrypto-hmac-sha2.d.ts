/** @module Interface lann:webcrypto/hmac-sha2@0.1.0 **/
export function importKeyRaw(variant: Sha2Variant, raw: Uint8Array, options: MacKeyOptions): Promise<MacKey>;
export function importKeyJwk(variant: Sha2Variant, jwk: string, options: MacKeyOptions): Promise<MacKey>;
export function generateKey(variant: Sha2Variant, length: number | undefined, options: MacKeyOptions): Promise<MacKey>;
export function deriveKey(variant: Sha2Variant, input: DeriveInput, length: number | undefined, options: MacKeyOptions): Promise<MacKey>;
export function unwrapKeyRaw(variant: Sha2Variant, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey>;
export function unwrapKeyJwk(variant: Sha2Variant, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey>;
export type Sha2Variant = import('./lann-webcrypto-sha2.js').Sha2Variant;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type MacKeyOptions = import('./lann-webcrypto-mac.js').MacKeyOptions;
export type MacKey = import('./lann-webcrypto-mac.js').MacKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

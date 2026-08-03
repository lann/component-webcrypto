/** @module Interface lann:webcrypto/ecdsa-verify@0.1.0 **/
export function importVerifyingKeyRaw(variant: EcdsaVariant, raw: Uint8Array): Promise<VerifyingKey>;
export function importVerifyingKeySpki(variant: EcdsaVariant, spki: Uint8Array): Promise<VerifyingKey>;
export function importVerifyingKeyJwk(variant: EcdsaVariant, jwk: string): Promise<VerifyingKey>;
/**
 * # Variants
 * 
 * ## `"p256-sha256"`
 * 
 * ## `"p256-sha384"`
 * 
 * ## `"p256-sha512"`
 * 
 * ## `"p384-sha256"`
 * 
 * ## `"p384-sha384"`
 * 
 * ## `"p384-sha512"`
 * 
 * ## `"p521-sha512"`
 */
export type EcdsaVariant = 'p256-sha256' | 'p256-sha384' | 'p256-sha512' | 'p384-sha256' | 'p384-sha384' | 'p384-sha512' | 'p521-sha512';
export type VerifyingKey = import('./lann-webcrypto-signature.js').VerifyingKey;
export type Error = import('./lann-webcrypto-types.js').Error;

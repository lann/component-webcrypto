/** @module Interface lann:webcrypto/ecdh@0.1.0 **/
export function importPublicKeyRaw(variant: EcdhVariant, raw: Uint8Array): Promise<PublicKey>;
export function importPublicKeySpki(variant: EcdhVariant, spki: Uint8Array): Promise<PublicKey>;
export function importPublicKeyJwk(variant: EcdhVariant, jwk: string): Promise<PublicKey>;
export function importSecretKeyJwk(variant: EcdhVariant, jwk: string, options: AgreementKeyOptions): Promise<SecretKey>;
export function importSecretKeyPkcs8(variant: EcdhVariant, pkcs8: Uint8Array, options: AgreementKeyOptions): Promise<SecretKey>;
export function generateKey(variant: EcdhVariant, options: AgreementKeyOptions): Promise<[SecretKey, PublicKey]>;
/**
 * # Variants
 * 
 * ## `"p256"`
 * 
 * ## `"p384"`
 * 
 * ## `"p521"`
 */
export type EcdhVariant = 'p256' | 'p384' | 'p521';
export type AgreementKeyOptions = import('./lann-webcrypto-key-agreement.js').AgreementKeyOptions;
export type SecretKey = import('./lann-webcrypto-key-agreement.js').SecretKey;
export type PublicKey = import('./lann-webcrypto-key-agreement.js').PublicKey;
export type Error = import('./lann-webcrypto-types.js').Error;

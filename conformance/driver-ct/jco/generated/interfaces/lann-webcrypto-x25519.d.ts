/** @module Interface lann:webcrypto/x25519@0.1.0 **/
export function importPublicKeyRaw(raw: Uint8Array): Promise<PublicKey>;
export function importPublicKeySpki(spki: Uint8Array): Promise<PublicKey>;
export function importPublicKeyJwk(jwk: string): Promise<PublicKey>;
export function importSecretKeyJwk(jwk: string, options: AgreementKeyOptions): Promise<SecretKey>;
export function importSecretKeyPkcs8(pkcs8: Uint8Array, options: AgreementKeyOptions): Promise<SecretKey>;
export function generateKey(options: AgreementKeyOptions): Promise<[SecretKey, PublicKey]>;
export function unwrapSecretKeyJwk(input: UnwrapInput, options: AgreementKeyOptions): Promise<SecretKey>;
export function unwrapSecretKeyPkcs8(input: UnwrapInput, options: AgreementKeyOptions): Promise<SecretKey>;
export type AgreementKeyOptions = import('./lann-webcrypto-key-agreement.js').AgreementKeyOptions;
export type SecretKey = import('./lann-webcrypto-key-agreement.js').SecretKey;
export type PublicKey = import('./lann-webcrypto-key-agreement.js').PublicKey;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

/** @module Interface lann:webcrypto/ed25519-verify@0.1.0 **/
export function importVerifyingKeyRaw(raw: Uint8Array): Promise<VerifyingKey>;
export function importVerifyingKeySpki(spki: Uint8Array): Promise<VerifyingKey>;
export function importVerifyingKeyJwk(jwk: string): Promise<VerifyingKey>;
export type VerifyingKey = import('./lann-webcrypto-signature.js').VerifyingKey;
export type Error = import('./lann-webcrypto-types.js').Error;

/** @module Interface lann:webcrypto/sha2@0.1.0 **/
export function makeDigest(variant: Sha2Variant): Digest;
/**
 * # Variants
 * 
 * ## `"sha224"`
 * 
 * ## `"sha256"`
 * 
 * ## `"sha384"`
 * 
 * ## `"sha512"`
 * 
 * ## `"sha512-224"`
 * 
 * ## `"sha512-256"`
 */
export type Sha2Variant = 'sha224' | 'sha256' | 'sha384' | 'sha512' | 'sha512-224' | 'sha512-256';
export type Digest = import('./lann-webcrypto-digest.js').Digest;
export type Error = import('./lann-webcrypto-types.js').Error;

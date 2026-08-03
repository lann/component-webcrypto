/** @module Interface lann:webcrypto/sha1-checked@0.1.0 **/
export function makeRejectingDigest(): Digest;
export function makeMitigatingDigest(): Digest;
export type Digest = import('./lann-webcrypto-digest.js').Digest;
export type Error = import('./lann-webcrypto-types.js').Error;

/** @module Interface lann:webcrypto/hkdf@0.1.0 **/
export function importIkm(raw: Uint8Array, options: DeriveOptions): Promise<Ikm>;
export function unwrapIkm(input: UnwrapInput, options: DeriveOptions): Promise<Ikm>;
export type DeriveOptions = import('./lann-webcrypto-derivation.js').DeriveOptions;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

export class Ikm {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  canDeriveBits(): boolean;
  canDeriveKey(): boolean;
}

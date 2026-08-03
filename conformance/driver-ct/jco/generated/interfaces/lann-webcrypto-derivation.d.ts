/** @module Interface lann:webcrypto/derivation@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;

export class DeriveInput {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  canDeriveBits(): boolean;
  canDeriveKey(): boolean;
  deriveBits(length: number | undefined): Promise<Uint8Array>;
}

export class DeriveOptions {
  constructor()
  canDeriveBits(allowed: boolean): void;
  canDeriveKey(allowed: boolean): void;
}

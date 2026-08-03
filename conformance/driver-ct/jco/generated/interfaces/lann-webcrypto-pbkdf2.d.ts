/** @module Interface lann:webcrypto/pbkdf2@0.1.0 **/
export function importPassword(raw: Uint8Array, options: DeriveOptions): Promise<Password>;
export function unwrapPassword(input: UnwrapInput, options: DeriveOptions): Promise<Password>;
export type DeriveOptions = import('./lann-webcrypto-derivation.js').DeriveOptions;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

export class Password {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  canDeriveBits(): boolean;
  canDeriveKey(): boolean;
}

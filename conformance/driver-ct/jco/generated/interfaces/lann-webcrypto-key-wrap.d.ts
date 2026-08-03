/** @module Interface lann:webcrypto/key-wrap@0.1.0 **/
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;
export type Error = import('./lann-webcrypto-types.js').Error;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

export class KwKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  wrap(input: WrapInput): Promise<Uint8Array>;
  unwrap(wrapped: Uint8Array): Promise<UnwrapInput>;
  algorithmName(): string;
  algorithmLength(): number;
  extractable(): boolean;
  canWrap(): boolean;
  canUnwrap(): boolean;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
}

export class KwKeyOptions {
  constructor()
  canWrap(allowed: boolean): void;
  canUnwrap(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

/** @module Interface lann:webcrypto/mac@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;

export class MacKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  sign(data: ReadableStream<number>): Promise<Uint8Array>;
  verify(data: ReadableStream<number>, tag: Uint8Array): Promise<void>;
  algorithmName(): string;
  algorithmHash(): string | undefined;
  algorithmLength(): number;
  extractable(): boolean;
  canSign(): boolean;
  canVerify(): boolean;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
  toWrapInputRaw(): Promise<WrapInput>;
  toWrapInputJwk(): Promise<WrapInput>;
}

export class MacKeyOptions {
  constructor()
  canSign(allowed: boolean): void;
  canVerify(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

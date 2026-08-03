/** @module Interface lann:webcrypto/aead-internal-nonce@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;

export class InternalNonceKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  seal(aad: Uint8Array, plaintext: ReadableStream<number>): Promise<ReadableStream<number>>;
  open(aad: Uint8Array, sealed: ReadableStream<number>): Promise<ReadableStream<number>>;
  algorithmName(): string;
  algorithmLength(): number;
  sealsRemaining(): bigint | undefined;
  extractable(): boolean;
  canSeal(): boolean;
  canOpen(): boolean;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
  toWrapInputRaw(): Promise<WrapInput>;
  toWrapInputJwk(): Promise<WrapInput>;
}

export class InternalNonceKeyOptions {
  constructor()
  canSeal(allowed: boolean): void;
  canOpen(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

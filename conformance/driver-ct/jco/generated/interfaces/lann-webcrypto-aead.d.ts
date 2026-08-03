/** @module Interface lann:webcrypto/aead@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

export class AeadKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  seal(nonce: Uint8Array, aad: Uint8Array, tagSize: number | undefined, plaintext: ReadableStream<number>): Promise<ReadableStream<number>>;
  open(nonce: Uint8Array, aad: Uint8Array, tagSize: number | undefined, ciphertext: ReadableStream<number>): Promise<ReadableStream<number>>;
  wrap(nonce: Uint8Array, aad: Uint8Array, tagSize: number | undefined, input: WrapInput): Promise<Uint8Array>;
  unwrap(nonce: Uint8Array, aad: Uint8Array, tagSize: number | undefined, wrapped: Uint8Array): Promise<UnwrapInput>;
  algorithmName(): string;
  algorithmLength(): number;
  nonceSize(): number;
  tagSize(): number;
  extractable(): boolean;
  canSeal(): boolean;
  canOpen(): boolean;
  canWrap(): boolean;
  canUnwrap(): boolean;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
  toWrapInputRaw(): Promise<WrapInput>;
  toWrapInputJwk(): Promise<WrapInput>;
}

export class AeadKeyOptions {
  constructor()
  canSeal(allowed: boolean): void;
  canOpen(allowed: boolean): void;
  canWrap(allowed: boolean): void;
  canUnwrap(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

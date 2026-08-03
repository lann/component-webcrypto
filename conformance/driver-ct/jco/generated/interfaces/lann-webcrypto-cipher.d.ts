/** @module Interface lann:webcrypto/cipher@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;
export type UnwrapInput = import('./lann-webcrypto-wrapping.js').UnwrapInput;

export class CipherKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  encrypt(iv: Uint8Array, counterLength: number | undefined, plaintext: ReadableStream<number>): Promise<ReadableStream<number>>;
  decrypt(iv: Uint8Array, counterLength: number | undefined, ciphertext: ReadableStream<number>): Promise<ReadableStream<number>>;
  wrap(iv: Uint8Array, counterLength: number | undefined, input: WrapInput): Promise<Uint8Array>;
  unwrap(iv: Uint8Array, counterLength: number | undefined, wrapped: Uint8Array): Promise<UnwrapInput>;
  algorithmName(): string;
  algorithmLength(): number;
  ivSize(): number;
  extractable(): boolean;
  canEncrypt(): boolean;
  canDecrypt(): boolean;
  canWrap(): boolean;
  canUnwrap(): boolean;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
  toWrapInputRaw(): Promise<WrapInput>;
  toWrapInputJwk(): Promise<WrapInput>;
}

export class CipherKeyOptions {
  constructor()
  canEncrypt(allowed: boolean): void;
  canDecrypt(allowed: boolean): void;
  canWrap(allowed: boolean): void;
  canUnwrap(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

/** @module Interface lann:webcrypto/signature@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;

export class SigningKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  sign(data: ReadableStream<number>): Promise<Uint8Array>;
  algorithmName(): string;
  algorithmCurve(): string | undefined;
  algorithmHash(): string | undefined;
  extractable(): boolean;
  canSign(): boolean;
  exportKeyJwk(): Promise<string>;
  exportKeyPkcs8(): Promise<Uint8Array>;
  toWrapInputJwk(): Promise<WrapInput>;
  toWrapInputPkcs8(): Promise<WrapInput>;
}

export class SigningKeyOptions {
  constructor()
  canSign(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

export class VerifyingKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  verify(data: ReadableStream<number>, sig: Uint8Array): Promise<void>;
  algorithmName(): string;
  algorithmCurve(): string | undefined;
  algorithmHash(): string | undefined;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeySpki(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
}

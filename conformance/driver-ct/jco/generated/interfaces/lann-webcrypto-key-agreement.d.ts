/** @module Interface lann:webcrypto/key-agreement@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;
export type DeriveInput = import('./lann-webcrypto-derivation.js').DeriveInput;
export type WrapInput = import('./lann-webcrypto-wrapping.js').WrapInput;

export class AgreementKeyOptions {
  constructor()
  canDeriveBits(allowed: boolean): void;
  canDeriveKey(allowed: boolean): void;
  extractable(allowed: boolean): void;
}

export class PublicKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  algorithmName(): string;
  exportKeyRaw(): Promise<Uint8Array>;
  exportKeyJwk(): Promise<string>;
  exportKeySpki(): Promise<Uint8Array>;
}

export class SecretKey {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  agree(peer: PublicKey): Promise<DeriveInput>;
  algorithmName(): string;
  canDeriveBits(): boolean;
  canDeriveKey(): boolean;
  extractable(): boolean;
  exportKeyJwk(): Promise<string>;
  exportKeyPkcs8(): Promise<Uint8Array>;
  toWrapInputJwk(): Promise<WrapInput>;
  toWrapInputPkcs8(): Promise<WrapInput>;
}

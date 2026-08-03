/** @module Interface lann:webcrypto/types@0.1.0 **/
export interface ExtensionError {
  origin: string,
  name: string,
  message: string,
}
export type Error = ErrorInvalidKey | ErrorInvalidNonce | ErrorAuthenticationFailed | ErrorNotExtractable | ErrorUnsupported | ErrorNotPermitted | ErrorKeyExhausted | ErrorOther | ErrorExtension;
export interface ErrorInvalidKey {
  tag: 'invalid-key',
  val: string,
}
export interface ErrorInvalidNonce {
  tag: 'invalid-nonce',
  val: string,
}
export interface ErrorAuthenticationFailed {
  tag: 'authentication-failed',
}
export interface ErrorNotExtractable {
  tag: 'not-extractable',
}
export interface ErrorUnsupported {
  tag: 'unsupported',
  val: string,
}
export interface ErrorNotPermitted {
  tag: 'not-permitted',
  val: string,
}
export interface ErrorKeyExhausted {
  tag: 'key-exhausted',
}
export interface ErrorOther {
  tag: 'other',
  val: string,
}
export interface ErrorExtension {
  tag: 'extension',
  val: ExtensionError,
}

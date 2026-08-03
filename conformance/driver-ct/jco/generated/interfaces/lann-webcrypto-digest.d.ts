/** @module Interface lann:webcrypto/digest@0.1.0 **/
export type Error = import('./lann-webcrypto-types.js').Error;

export class Digest {
  /**
   * This type does not have a public constructor.
   */
  private constructor();
  compute(data: ReadableStream<number>): Promise<Uint8Array>;
  algorithmName(): string;
}

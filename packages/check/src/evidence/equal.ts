import { canonicalizeJcs } from '@pacspace/shared';

/** Two JSON values are the same when their JCS forms are; a value JCS cannot write is equal to nothing. */
export function isDeepStrictEqual(a: unknown, b: unknown): boolean {
  try {
    return a !== undefined && b !== undefined && canonicalizeJcs(a) === canonicalizeJcs(b);
  } catch {
    return false;
  }
}

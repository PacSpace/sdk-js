import { BlindingError, assertBlindingValue, serializeBlindingFile } from '@pacspace/shared';
import { ValidationError } from './errors';

export const BLINDING_WORDS = {
  hidden: '[Blinding: value hidden]',
  noJson: "A blinding cannot be turned into JSON. Save it with writeBlindingFile, or pass the fingerprint's ref.",
  notAFile: 'This is not a valid blinding file.',
  otherBytes: 'This blinding file does not match these bytes.',
  valueSize: 'A blinding value is exactly 32 bytes.',
} as const;

const HEX_64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;

let readValue: (blinding: Blinding) => Uint8Array;

/**
 * The blinding value of one blinded fingerprint, beside the digest and size
 * it was made for. The value is held privately and never shown: printing,
 * inspecting or spreading a Blinding shows no value, and JSON.stringify
 * throws. `blindingFileText` is the one way to get the file's text.
 */
export class Blinding {
  readonly #value: Uint8Array;
  /** The blinded digest this value was made for (lowercase hex). */
  readonly digest: string;
  /** The file's length, as a decimal string. */
  readonly byteLength: string;

  static {
    readValue = (blinding) => blinding.#value;
  }

  /** Made by `fingerprint` and `readBlindingFile`; not part of the public API. */
  constructor(value: Uint8Array, digest: string, byteLength: string) {
    try {
      assertBlindingValue(value);
    } catch {
      throw new ValidationError(BLINDING_WORDS.valueSize);
    }
    if (typeof digest !== 'string' || !HEX_64.test(digest) || typeof byteLength !== 'string' || !DECIMAL.test(byteLength)) {
      throw new ValidationError(BLINDING_WORDS.notAFile);
    }
    this.#value = new Uint8Array(value);
    this.digest = digest;
    this.byteLength = byteLength;
  }

  toJSON(): never {
    throw new ValidationError(BLINDING_WORDS.noJson);
  }

  toString(): string {
    return BLINDING_WORDS.hidden;
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return BLINDING_WORDS.hidden;
  }
}

/** The value, for the SDK's own HMAC and file writer only. */
export function blindingValueOf(blinding: Blinding): Uint8Array {
  return readValue(blinding);
}

/**
 * The blinding file's canonical text. This is the one export that yields the
 * value: keep the text as private as the file it belongs to.
 */
export function blindingFileText(blinding: Blinding): string {
  if (!(blinding instanceof Blinding)) throw new ValidationError(BLINDING_WORDS.notAFile);
  try {
    return serializeBlindingFile({ value: readValue(blinding), digest: blinding.digest, byteLength: blinding.byteLength });
  } catch (error) {
    if (error instanceof BlindingError) throw new ValidationError(BLINDING_WORDS.notAFile);
    throw error;
  }
}

import { BLINDING_FILE_SCHEMA_V1 } from '../proof/payload-ref-v1';
import { BLINDING_VALUE_BYTES, BlindingError, assertBlindingValue, toHex } from './blinding-value';

/** A reader refuses a file longer than this; the largest valid file is 259 bytes. */
export const BLINDING_FILE_MAX_BYTES = 1024;

const BLINDING_FILE_MESSAGE = 'This is not a valid blinding file.';
const HEX_64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const FIELDS = ['schema', 'alg', 'value', 'digest', 'byteLength'];

export interface BlindingFileV1 {
  /** The 32-byte blinding value. It never leaves the holder. */
  value: Uint8Array;
  /** The blinded digest the file was made for (lowercase hex). */
  digest: string;
  /** The file's length, as a decimal string. */
  byteLength: string;
}

export type BlindingFileRefusal =
  | 'over-cap'
  | 'not-utf8'
  | 'not-json'
  | 'not-object'
  | 'fields'
  | 'schema'
  | 'alg'
  | 'value'
  | 'digest'
  | 'byteLength'
  | 'not-canonical';

export type ParsedBlindingFile = { ok: true; blinding: BlindingFileV1 } | { ok: false; reason: BlindingFileRefusal };

const isDecimalWithinSafeRange = (text: string) => DECIMAL.test(text) && BigInt(text) <= BigInt(Number.MAX_SAFE_INTEGER);

function canonicalText(fields: { value: string; digest: string; byteLength: string }): string {
  return (
    JSON.stringify(
      { schema: BLINDING_FILE_SCHEMA_V1, alg: 'hmac-sha-256', value: fields.value, digest: fields.digest, byteLength: fields.byteLength },
      null,
      2,
    ) + '\n'
  );
}

/** The canonical bytes of a blinding file (slot-encoding-v1 section 6.2). */
export function serializeBlindingFile(blinding: BlindingFileV1): string {
  assertBlindingValue(blinding.value);
  if (typeof blinding.digest !== 'string' || !HEX_64.test(blinding.digest)) throw new BlindingError(BLINDING_FILE_MESSAGE);
  if (typeof blinding.byteLength !== 'string' || !isDecimalWithinSafeRange(blinding.byteLength)) {
    throw new BlindingError(BLINDING_FILE_MESSAGE);
  }
  return canonicalText({ value: toHex(blinding.value), digest: blinding.digest, byteLength: blinding.byteLength });
}

/**
 * The exact reader: strict UTF-8, the five string fields, then the canonical
 * form rewritten from the parsed fields must equal the input byte for byte,
 * which refuses duplicate keys, other whitespace, key order and line ends.
 */
export function parseBlindingFile(bytes: Uint8Array): ParsedBlindingFile {
  if (bytes.length > BLINDING_FILE_MAX_BYTES) return { ok: false, reason: 'over-cap' };
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return { ok: false, reason: 'not-utf8' };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'not-json' };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { ok: false, reason: 'not-object' };
  const obj = parsed as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== FIELDS.length || !FIELDS.every((field) => keys.includes(field))) return { ok: false, reason: 'fields' };
  if (obj.schema !== BLINDING_FILE_SCHEMA_V1) return { ok: false, reason: 'schema' };
  if (obj.alg !== 'hmac-sha-256') return { ok: false, reason: 'alg' };
  if (typeof obj.value !== 'string' || !HEX_64.test(obj.value)) return { ok: false, reason: 'value' };
  if (typeof obj.digest !== 'string' || !HEX_64.test(obj.digest)) return { ok: false, reason: 'digest' };
  if (typeof obj.byteLength !== 'string' || !isDecimalWithinSafeRange(obj.byteLength)) {
    return { ok: false, reason: 'byteLength' };
  }
  if (canonicalText({ value: obj.value, digest: obj.digest, byteLength: obj.byteLength }) !== text) {
    return { ok: false, reason: 'not-canonical' };
  }
  const value = new Uint8Array(BLINDING_VALUE_BYTES);
  for (let i = 0; i < BLINDING_VALUE_BYTES; i += 1) value[i] = parseInt(obj.value.slice(i * 2, i * 2 + 2), 16);
  return { ok: true, blinding: { value, digest: obj.digest, byteLength: obj.byteLength } };
}

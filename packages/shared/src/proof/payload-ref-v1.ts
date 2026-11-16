import { RecordIntakeError } from './layout-document-v1';

/**
 * payload-ref/v1 (slot-encoding-v1 section 6.1).
 *
 * Bulk bytes never pass through PacSpace. The tenant digests them where they
 * live and places `{ alg, digest, byteLength }` in the record content. The
 * storage locator is never part of the record. `digestPayload` is the
 * streaming helper every tenant can use so the same bytes give the same
 * reference regardless of chunking; it runs in Node (crypto.subtle or
 * node:crypto) and in browsers (crypto.subtle for one-shot digests).
 */

/**
 * The list only grows: an alg is never removed or redefined (section 6.1).
 * `hmac-sha-256` is a blinded fingerprint, HMAC-SHA256 of the bytes keyed by
 * a 32-byte blinding value the tenant keeps.
 */
export const PAYLOAD_REF_ALGS = ['sha-256', 'hmac-sha-256'] as const;
export type PayloadRefAlg = (typeof PAYLOAD_REF_ALGS)[number];

export interface PayloadRefV1 {
  alg: PayloadRefAlg;
  /** Lowercase hex, no 0x prefix. */
  digest: string;
  /** Decimal string. */
  byteLength: string;
}

export const BLINDING_FILE_SCHEMA_V1 = 'pacspace-blinding/v1';

/**
 * RECORD_BLINDING_INCLUDED's sentences: B1 and B2 found blinding material; B3
 * found an extra field on a blinded fingerprint, which may be an ordinary note.
 */
export const RECORD_BLINDING_INCLUDED_SENTENCES = {
  material:
    "This write includes a blinding file or its value. Send only the fingerprint's alg, digest and byteLength; the blinding file stays with you.",
  extraField: 'A blinded fingerprint carries only alg, digest and byteLength. Move any other field out of it.',
} as const;

const PAYLOAD_REF_FIELDS = new Set(['alg', 'digest', 'byteLength']);

export function validatePayloadRefV1(ref: unknown): PayloadRefV1 {
  if (!ref || typeof ref !== 'object') {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'payload reference must be an object');
  }
  const r = ref as Record<string, unknown>;
  if (!PAYLOAD_REF_ALGS.includes(r.alg as PayloadRefAlg)) {
    throw new RecordIntakeError(
      'RECORD_PAYLOAD_ALG_UNSUPPORTED',
      `payload alg is not supported; use one of ${PAYLOAD_REF_ALGS.join(', ')}`,
    );
  }
  if (typeof r.digest !== 'string' || !/^[0-9a-f]{64}$/.test(r.digest)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'payload digest must be 64 lowercase hex characters');
  }
  if (typeof r.byteLength !== 'string' || !/^\d+$/.test(r.byteLength)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'payload byteLength must be a decimal string');
  }
  if (r.alg === 'hmac-sha-256' && !/^(0|[1-9][0-9]*)$/.test(r.byteLength)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'payload byteLength must be a decimal string with no leading zero');
  }
  return { alg: r.alg as PayloadRefAlg, digest: r.digest, byteLength: r.byteLength };
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);

/** Rule B at one object, in order B1, B2, B3, B4 (slot-encoding-v1 section 6.1). */
function applyRuleB(obj: Record<string, unknown>): void {
  if (obj.schema === BLINDING_FILE_SCHEMA_V1) {
    throw new RecordIntakeError('RECORD_BLINDING_INCLUDED', RECORD_BLINDING_INCLUDED_SENTENCES.material, 'B1');
  }
  if (
    isPlainObject(obj.ref) &&
    obj.ref.alg === 'hmac-sha-256' &&
    Object.prototype.hasOwnProperty.call(obj, 'blinding') &&
    obj.blinding !== null
  ) {
    throw new RecordIntakeError('RECORD_BLINDING_INCLUDED', RECORD_BLINDING_INCLUDED_SENTENCES.material, 'B2');
  }
  if (obj.alg === 'hmac-sha-256') {
    if (Object.keys(obj).some((key) => !PAYLOAD_REF_FIELDS.has(key))) {
      throw new RecordIntakeError('RECORD_BLINDING_INCLUDED', RECORD_BLINDING_INCLUDED_SENTENCES.extraField, 'B3');
    }
    validatePayloadRefV1(obj);
  }
}

const isReferenceShaped = (obj: Record<string, unknown>): boolean =>
  'alg' in obj && 'digest' in obj && 'byteLength' in obj;

/**
 * Walk a record content object: Rule B at every object and every depth, then
 * today's rule for each payload reference. A validated reference's own three
 * fields are not descended into; its other fields are, under Rule B only.
 * Inside those other fields a reference-shaped object is not validated, so
 * all of its fields are walked, as assertNoBlindingMaterial walks them.
 */
export function validatePayloadRefsInContent(content: unknown): void {
  const visit = (value: unknown, insideReferenceExtras: boolean): void => {
    if (!value || typeof value !== 'object') return;
    if (Array.isArray(value)) {
      for (const item of value) visit(item, insideReferenceExtras);
      return;
    }
    const obj = value as Record<string, unknown>;
    applyRuleB(obj);
    if (isReferenceShaped(obj)) {
      if (!insideReferenceExtras) validatePayloadRefV1(obj);
      for (const [key, field] of Object.entries(obj)) {
        if (insideReferenceExtras || !PAYLOAD_REF_FIELDS.has(key)) visit(field, true);
      }
      return;
    }
    for (const field of Object.values(obj)) visit(field, insideReferenceExtras);
  };
  visit(content, false);
}

/** Rule B alone, at every object and every depth; the SDKs call it before any request. */
export function assertNoBlindingMaterial(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) assertNoBlindingMaterial(item);
    return;
  }
  const obj = value as Record<string, unknown>;
  applyRuleB(obj);
  for (const field of Object.values(obj)) assertNoBlindingMaterial(field);
}

export type PayloadByteSource = Uint8Array | Iterable<Uint8Array> | AsyncIterable<Uint8Array>;

function isAsyncIterable(v: unknown): v is AsyncIterable<Uint8Array> {
  return !!v && typeof (v as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function';
}
function isIterable(v: unknown): v is Iterable<Uint8Array> {
  return !!v && typeof (v as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function' && !(v instanceof Uint8Array);
}

/**
 * Digest a payload with constant memory over any chunking. In Node the
 * incremental `node:crypto` hash is used; in a browser the chunks are
 * concatenated for `crypto.subtle.digest` (one-shot API).
 */
export async function digestPayload(source: PayloadByteSource, alg: 'sha-256' = 'sha-256'): Promise<PayloadRefV1> {
  if ((alg as string) === 'hmac-sha-256') {
    throw new RecordIntakeError(
      'RECORD_PAYLOAD_ALG_UNSUPPORTED',
      'digestPayload makes sha-256 fingerprints only; a blinded fingerprint is made with blindedDigest and its blinding value',
    );
  }
  if (alg !== 'sha-256') {
    throw new RecordIntakeError('RECORD_PAYLOAD_ALG_UNSUPPORTED', 'digestPayload supports sha-256 only');
  }
  let byteLength = 0n;
  const chunks = async function* (): AsyncGenerator<Uint8Array> {
    if (source instanceof Uint8Array) {
      yield source;
    } else if (isAsyncIterable(source)) {
      for await (const c of source) yield c;
    } else if (isIterable(source)) {
      for (const c of source) yield c;
    } else {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'digestPayload needs bytes or an iterable of bytes');
    }
  };

  let nodeCrypto: typeof import('node:crypto') | null = null;
  const isNode = typeof process !== 'undefined' && !!(process as { versions?: { node?: string } }).versions?.node;
  if (isNode) {
    try {
      // Prefer the incremental Node hash when available (constant memory).
      // The specifier is a variable so browser bundlers leave it alone.
      const specifier = 'node:crypto';
      nodeCrypto = await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
    } catch {
      nodeCrypto = null;
    }
  }

  if (nodeCrypto && typeof nodeCrypto.createHash === 'function') {
    const hash = nodeCrypto.createHash('sha256');
    for await (const c of chunks()) {
      hash.update(c);
      byteLength += BigInt(c.length);
    }
    return { alg, digest: hash.digest('hex'), byteLength: byteLength.toString() };
  }

  const parts: Uint8Array[] = [];
  for await (const c of chunks()) {
    parts.push(c);
    byteLength += BigInt(c.length);
  }
  const joined = new Uint8Array(Number(byteLength));
  let offset = 0;
  for (const p of parts) {
    joined.set(p, offset);
    offset += p.length;
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', joined);
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  return { alg, digest: hex, byteLength: byteLength.toString() };
}

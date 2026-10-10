import { BlindingError, blindedDigest, newBlindingValue } from '@pacspace/shared';
import { BLINDING_WORDS, Blinding, blindingValueOf } from './blinding';
import { PacSpaceError, ValidationError } from './errors';

export interface PayloadRef {
  alg: 'sha-256' | 'hmac-sha-256';
  digest: string;
  byteLength: string;
}

export interface FingerprintOptions {
  /** Blind the fingerprint with a fresh random value (the default). */
  blind?: boolean;
  /** An alias: 'sha-256' is blind: false, 'hmac-sha-256' is blind: true. */
  alg?: 'sha-256' | 'hmac-sha-256';
  /** The same file again: recompute with this blinding and return the same ref. */
  blinding?: Blinding;
}

export interface FingerprintResult {
  /** Send this as the payload. */
  ref: PayloadRef;
  /** Save this beside the file with writeBlindingFile; null when not blinded. */
  blinding: Blinding | null;
}

const ALG_WORDS = {
  unsupported: 'A fingerprint is made with sha-256 or hmac-sha-256.',
  disagree: 'alg and blind disagree. Pass one of them.',
} as const;

const issued = new WeakSet<object>();

/** True for an object `fingerprint` returned: the whole result, never a payload. */
export function isFingerprintResult(value: unknown): boolean {
  return !!value && typeof value === 'object' && issued.has(value);
}

export type FingerprintInput =
  | File
  | Blob
  | ArrayBuffer
  | Uint8Array
  | ReadableStream<Uint8Array>
  | Iterable<Uint8Array>
  | AsyncIterable<Uint8Array>;

function isAsyncIterable(value: unknown): value is AsyncIterable<Uint8Array> {
  return !!value && typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function';
}

function isIterable(value: unknown): value is Iterable<Uint8Array> {
  return (
    !!value &&
    typeof (value as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function' &&
    !(value instanceof Uint8Array)
  );
}

export async function* chunksOf(input: FingerprintInput): AsyncGenerator<Uint8Array> {
  if (input instanceof Uint8Array) {
    yield input;
    return;
  }
  if (typeof ArrayBuffer !== 'undefined' && input instanceof ArrayBuffer) {
    yield new Uint8Array(input);
    return;
  }
  if (typeof Blob !== 'undefined' && input instanceof Blob) {
    const buffer = await input.arrayBuffer();
    yield new Uint8Array(buffer);
    return;
  }
  if (typeof ReadableStream !== 'undefined' && input instanceof ReadableStream) {
    const reader = input.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) yield value;
      }
    } finally {
      reader.releaseLock();
    }
    return;
  }
  if (isAsyncIterable(input)) {
    for await (const chunk of input) yield chunk;
    return;
  }
  if (isIterable(input)) {
    for (const chunk of input) yield chunk;
    return;
  }
  throw new PacSpaceError(
    'fingerprint needs bytes or an iterable of bytes',
    0,
    'RECORD_CONTENT_INVALID',
  );
}

function blindsBy(options: FingerprintOptions | undefined): boolean {
  const alg = options?.alg;
  if (alg !== undefined && alg !== 'sha-256' && alg !== 'hmac-sha-256') {
    throw new PacSpaceError(ALG_WORDS.unsupported, 0, 'RECORD_PAYLOAD_ALG_UNSUPPORTED');
  }
  const byAlg = alg === undefined ? undefined : alg === 'hmac-sha-256';
  const blind = options?.blind;
  if (blind !== undefined && typeof blind !== 'boolean') throw new ValidationError(ALG_WORDS.disagree);
  if (byAlg !== undefined && blind !== undefined && byAlg !== blind) throw new ValidationError(ALG_WORDS.disagree);
  const blinds = blind ?? byAlg ?? true;
  if (options?.blinding !== undefined && options.blinding !== null) {
    if (!blinds) throw new ValidationError(ALG_WORDS.disagree);
    if (!(options.blinding instanceof Blinding)) throw new ValidationError(BLINDING_WORDS.notAFile);
  }
  return blinds;
}

async function blindedRef(input: FingerprintInput, blinding: Blinding | undefined): Promise<FingerprintResult> {
  try {
    if (blinding) {
      const ref = (await blindedDigest(chunksOf(input), blindingValueOf(blinding))) as PayloadRef;
      if (ref.digest !== blinding.digest || ref.byteLength !== blinding.byteLength) {
        throw new ValidationError(BLINDING_WORDS.otherBytes);
      }
      return { ref, blinding };
    }
    const made = await newBlindingValue();
    try {
      const ref = (await blindedDigest(chunksOf(input), made)) as PayloadRef;
      return { ref, blinding: new Blinding(made, ref.digest, ref.byteLength) };
    } finally {
      made.fill(0);
    }
  } catch (error) {
    if (error instanceof BlindingError) throw new ValidationError(BLINDING_WORDS.valueSize);
    throw error;
  }
}

/**
 * Fingerprint bytes where they live. PacSpace receives the digest and size,
 * never the file. Blinded by default: an HMAC-SHA256 under a fresh 32-byte
 * value, returned as `{ ref, blinding }`; send `ref` and keep `blinding`
 * beside the file. `{ blind: false }` gives the plain sha-256 reference
 * (the same rule as `digestPayload`) with `blinding: null`.
 */
export async function fingerprint(input: FingerprintInput, options?: FingerprintOptions): Promise<FingerprintResult> {
  const result = blindsBy(options)
    ? await blindedRef(input, options?.blinding ?? undefined)
    : { ref: await plainRef(input), blinding: null };
  issued.add(result);
  return result;
}

/** The plain sha-256 reference, unchanged from 0.11.0. */
export async function plainRef(input: FingerprintInput): Promise<PayloadRef> {
  const alg = 'sha-256';
  let byteLength = 0n;
  let nodeCrypto: typeof import('node:crypto') | null = null;
  const isNode = typeof process !== 'undefined' && !!(process as { versions?: { node?: string } }).versions?.node;
  if (isNode) {
    try {
      const specifier = 'node:crypto';
      nodeCrypto = await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
    } catch {
      nodeCrypto = null;
    }
  }

  if (nodeCrypto && typeof nodeCrypto.createHash === 'function') {
    const hash = nodeCrypto.createHash('sha256');
    for await (const chunk of chunksOf(input)) {
      hash.update(chunk);
      byteLength += BigInt(chunk.length);
    }
    return { alg, digest: hash.digest('hex'), byteLength: byteLength.toString() };
  }

  const parts: Uint8Array[] = [];
  for await (const chunk of chunksOf(input)) {
    parts.push(chunk);
    byteLength += BigInt(chunk.length);
  }
  const joined = new Uint8Array(Number(byteLength));
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.length;
  }
  const digest = await globalThis.crypto.subtle.digest('SHA-256', joined);
  const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
  return { alg, digest: hex, byteLength: byteLength.toString() };
}

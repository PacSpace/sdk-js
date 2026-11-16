import type { PayloadByteSource } from '../proof/payload-ref-v1';

export const BLINDING_VALUE_BYTES = 32;

const BLINDING_VALUE_MESSAGE = 'A blinding value is exactly 32 bytes.';

/** A refusal of a blinding value or file. The message is fixed and names no value. */
export class BlindingError extends Error {
  constructor(message: string = BLINDING_VALUE_MESSAGE) {
    super(message);
    this.name = 'BlindingError';
  }
}

/**
 * HMAC zero-pads a short key and hashes a long one, so two different values
 * could give the same MAC; every entry point refuses anything but 32 bytes
 * before HMAC runs (slot-encoding-v1 section 6.2).
 */
export function assertBlindingValue(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== BLINDING_VALUE_BYTES) {
    throw new BlindingError();
  }
}

function isAsyncIterable(v: unknown): v is AsyncIterable<Uint8Array> {
  return !!v && typeof (v as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function';
}
function isIterable(v: unknown): v is Iterable<Uint8Array> {
  return !!v && typeof (v as { [Symbol.iterator]?: unknown })[Symbol.iterator] === 'function' && !(v instanceof Uint8Array);
}

/**
 * Every chunk as a Uint8Array view of its bytes. A chunk that is not a byte
 * view (a string, a number) is refused, so the two implementations never
 * count or hash it differently; a Uint8Array from another realm is a view.
 */
function bytesOf(chunk: unknown): Uint8Array {
  if (!ArrayBuffer.isView(chunk)) throw new TypeError();
  return new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
}

export async function* chunksOf(source: PayloadByteSource): AsyncGenerator<Uint8Array> {
  if (ArrayBuffer.isView(source)) {
    yield bytesOf(source);
  } else if (isAsyncIterable(source)) {
    for await (const c of source) yield bytesOf(c);
  } else if (isIterable(source)) {
    for (const c of source) yield bytesOf(c);
  } else {
    throw new TypeError();
  }
}

export function isNodeRuntime(): boolean {
  return typeof process !== 'undefined' && !!(process as { versions?: { node?: string } }).versions?.node;
}

/** `node:crypto`, loaded so browser bundlers leave it alone (see payload-ref-v1's digestPayload). */
export async function loadNodeCrypto(): Promise<typeof import('node:crypto')> {
  const specifier = 'node:crypto';
  return import(/* @vite-ignore */ /* webpackIgnore: true */ specifier);
}

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

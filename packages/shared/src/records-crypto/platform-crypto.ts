import { isNodeRuntime, loadNodeCrypto } from './blinding-value';

/**
 * The platform's WebCrypto: `globalThis.crypto` where the runtime has it
 * (browsers, Node 19 and later), else `node:crypto`'s `webcrypto` (Node 18).
 * Record hash v2 and the disclosure envelope use only SHA-256, HMAC-SHA256
 * and AES-256-GCM through it (ADR 0016).
 */
export async function platformCrypto(): Promise<Crypto> {
  const global = (globalThis as { crypto?: Crypto }).crypto;
  if (global?.subtle && typeof global.getRandomValues === 'function') return global;
  if (isNodeRuntime()) {
    const nodeCrypto = await loadNodeCrypto();
    return nodeCrypto.webcrypto as unknown as Crypto;
  }
  throw new Error('This runtime has no WebCrypto.');
}

/** Random bytes, synchronously, from the global WebCrypto (every supported runtime has one). */
export function randomBytes(length: number): Uint8Array {
  const global = (globalThis as { crypto?: Crypto }).crypto;
  if (!global || typeof global.getRandomValues !== 'function') throw new Error('This runtime has no WebCrypto.');
  return global.getRandomValues(new Uint8Array(length));
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const { subtle } = await platformCrypto();
  return new Uint8Array(await subtle.digest('SHA-256', Uint8Array.from(bytes)));
}

export async function hmacSha256(key: Uint8Array, bytes: Uint8Array): Promise<Uint8Array> {
  const { subtle } = await platformCrypto();
  const cryptoKey = await subtle.importKey('raw', Uint8Array.from(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, Uint8Array.from(bytes)));
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

export const toHex0x = (bytes: Uint8Array): string =>
  '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const HEX32 = /^0x[0-9a-f]{64}$/;
export const isHex32 = (value: unknown): value is string => typeof value === 'string' && HEX32.test(value);

/** Decodes `0x` plus 64 lowercase hex; the caller has checked the form. */
export function fromHex32(value: string): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) out[i] = parseInt(value.slice(2 + i * 2, 4 + i * 2), 16);
  return out;
}

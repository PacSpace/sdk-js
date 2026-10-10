import type { PayloadByteSource, PayloadRefV1 } from '../proof/payload-ref-v1';
import { assertBlindingValue, chunksOf, toHex } from './blinding-value';

/** HMAC-SHA256 through WebCrypto. `sign` is one-shot, so the chunks are joined first. */
export const hmacWeb = {
  async hmacSha256(key: Uint8Array, source: PayloadByteSource): Promise<{ digest: string; byteLength: string }> {
    const parts: Uint8Array[] = [];
    let length = 0;
    for await (const chunk of chunksOf(source)) {
      parts.push(chunk);
      length += chunk.length;
    }
    const joined = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      joined.set(part, offset);
      offset += part.length;
    }
    const subtle = globalThis.crypto.subtle;
    const cryptoKey = await subtle.importKey('raw', Uint8Array.from(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const mac = await subtle.sign('HMAC', cryptoKey, joined);
    return { digest: toHex(new Uint8Array(mac)), byteLength: String(length) };
  },

  async blindedDigest(source: PayloadByteSource, value: Uint8Array): Promise<PayloadRefV1> {
    assertBlindingValue(value);
    const { digest, byteLength } = await hmacWeb.hmacSha256(value, source);
    return { alg: 'hmac-sha-256', digest, byteLength };
  },
};

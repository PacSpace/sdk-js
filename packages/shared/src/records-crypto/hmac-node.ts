import type { PayloadByteSource, PayloadRefV1 } from '../proof/payload-ref-v1';
import { assertBlindingValue, chunksOf, loadNodeCrypto } from './blinding-value';

/** HMAC-SHA256 through `node:crypto`, streaming. */
export const hmacNode = {
  async hmacSha256(key: Uint8Array, source: PayloadByteSource): Promise<{ digest: string; byteLength: string }> {
    const { createHmac } = await loadNodeCrypto();
    const mac = createHmac('sha256', key);
    let byteLength = 0n;
    for await (const chunk of chunksOf(source)) {
      mac.update(chunk);
      byteLength += BigInt(chunk.length);
    }
    return { digest: mac.digest('hex'), byteLength: byteLength.toString() };
  },

  async blindedDigest(source: PayloadByteSource, value: Uint8Array): Promise<PayloadRefV1> {
    assertBlindingValue(value);
    const { digest, byteLength } = await hmacNode.hmacSha256(value, source);
    return { alg: 'hmac-sha-256', digest, byteLength };
  },
};

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_TEXT = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url (RFC 4648 section 5). */
export function toBase64Url(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  if (i < bytes.length) {
    const rest = bytes.length - i;
    const n = (bytes[i] << 16) | (rest === 2 ? bytes[i + 1] << 8 : 0);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63];
    if (rest === 2) out += B64URL[(n >> 6) & 63];
  }
  return out;
}

/** Canonical unpadded base64url only: decoding and re-encoding gives the same text. */
export function fromBase64Url(text: string): Uint8Array | null {
  if (typeof text !== 'string' || !B64URL_TEXT.test(text) || text.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < text.length; i += 1) {
    acc = (acc << 6) | B64URL.indexOf(text[i]);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) return null;
  return out;
}

/** The length of the unpadded base64url text of `byteLength` bytes. */
export function base64UrlLength(byteLength: number): number {
  return Math.floor(byteLength / 3) * 4 + (byteLength % 3 ? (byteLength % 3) + 1 : 0);
}

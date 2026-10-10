/** Unpadded base64url from the platform's own btoa and atob, so encrypted records run in a browser as in Node. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Lenient as Node's base64url decoding is: what isn't base64url decodes to fewer bytes, never throws. */
export function fromBase64Url(text: string): Uint8Array {
  const clean = String(text).replace(/[^A-Za-z0-9_-]/g, '');
  const usable = clean.length % 4 === 1 ? clean.slice(0, -1) : clean;
  const padded = usable.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (usable.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

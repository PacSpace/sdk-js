import { fromBase64Url } from './base64url';
import { concatBytes, sha256, utf8 } from './platform-crypto';
import type { RecordsRefusalV1 } from './records-encryption-v1';

/**
 * The keyless half of level 2's asymmetric formats (ADR 0015, formats notes
 * N3, N9 and N12): the sizes, the public key id, and the shape checks of a
 * seed wrap and of a wrap to a holder. Nothing here loads a library, so the
 * API checks what it stores with the same code the SDKs open it with; the
 * `records-crypto/asymmetric` subpath re-exports these.
 */
export const KEY_WRAP_SUITE_V1 = 'hpke-1' as const;
export const WORKSPACE_PUBLIC_KEY_BYTES_V1 = 1216;
export const KEY_WRAP_ENC_BYTES_V1 = 1120;
export const KEY_WRAP_CT_BYTES_V1 = 48;
export const SEED_WRAP_CT_BYTES_V1 = 48;
export const PUBLIC_KEY_ID_LABEL_V1 = 'pacspace:public-key-id:v1';

const SEP = new Uint8Array([0]);
const HEX64 = /^[0-9a-f]{64}$/;
const IV_BYTES = 12;

const refuse = <C extends string>(code: C): RecordsRefusalV1<C> => ({ ok: false, code });
const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * `SHA-256("pacspace:public-key-id:v1" || 0x00 || encoded public key)`, 64
 * lowercase hex; null unless the key is the encoded 1,216 bytes.
 */
export async function workspacePublicKeyIdV1(publicKey: Uint8Array): Promise<string | null> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== WORKSPACE_PUBLIC_KEY_BYTES_V1) return null;
  return hex(await sha256(concatBytes(utf8(PUBLIC_KEY_ID_LABEL_V1), SEP, publicKey)));
}

/** The seed wrap's keyless checks (N9). Never throws. */
export function readSeedWrapShapeV1(wrap: unknown): { ok: true; kid: string; iv: Uint8Array; ct: Uint8Array } | RecordsRefusalV1<'SEED_WRAP_MALFORMED'> {
  if (!wrap || typeof wrap !== 'object' || Array.isArray(wrap)) return refuse('SEED_WRAP_MALFORMED');
  const w = wrap as Record<string, unknown>;
  if (Object.keys(w).sort().join(',') !== 'alg,ct,iv,kid,v') return refuse('SEED_WRAP_MALFORMED');
  if (w.v !== 1 || w.alg !== 'A256GCM' || typeof w.kid !== 'string' || !HEX64.test(w.kid)) return refuse('SEED_WRAP_MALFORMED');
  const iv = typeof w.iv === 'string' ? fromBase64Url(w.iv) : null;
  const ct = typeof w.ct === 'string' ? fromBase64Url(w.ct) : null;
  if (!iv || iv.length !== IV_BYTES || !ct || ct.length !== SEED_WRAP_CT_BYTES_V1) return refuse('SEED_WRAP_MALFORMED');
  return { ok: true, kid: w.kid, iv, ct };
}

type KeyWrapShape = { ok: true; to: string; enc: Uint8Array; ct: Uint8Array } | RecordsRefusalV1<'KEY_WRAP_MALFORMED' | 'KEY_WRAP_SUITE'>;

/** The keyless checks every reader of a wrap to a holder runs first (N9). Never throws. */
export function readKeyWrapShapeV1(wrap: unknown): KeyWrapShape {
  return readKeyWrapShape(wrap, 1);
}

/**
 * The same checks for a wrap v2 (card 10, F3), the only form a store route
 * takes and a reader opens: a v1 wrap is malformed here. Never throws.
 */
export function readKeyWrapShapeV2(wrap: unknown): KeyWrapShape {
  return readKeyWrapShape(wrap, 2);
}

function readKeyWrapShape(wrap: unknown, v: 1 | 2): KeyWrapShape {
  if (!wrap || typeof wrap !== 'object' || Array.isArray(wrap)) return refuse('KEY_WRAP_MALFORMED');
  const w = wrap as Record<string, unknown>;
  if (Object.keys(w).sort().join(',') !== 'ct,enc,suite,to,v' || w.v !== v || typeof w.suite !== 'string') return refuse('KEY_WRAP_MALFORMED');
  if (w.suite !== KEY_WRAP_SUITE_V1) return refuse('KEY_WRAP_SUITE');
  if (typeof w.to !== 'string' || !HEX64.test(w.to)) return refuse('KEY_WRAP_MALFORMED');
  const enc = typeof w.enc === 'string' ? fromBase64Url(w.enc) : null;
  const ct = typeof w.ct === 'string' ? fromBase64Url(w.ct) : null;
  if (!enc || enc.length !== KEY_WRAP_ENC_BYTES_V1 || !ct || ct.length !== KEY_WRAP_CT_BYTES_V1) return refuse('KEY_WRAP_MALFORMED');
  return { ok: true, to: w.to, enc, ct };
}

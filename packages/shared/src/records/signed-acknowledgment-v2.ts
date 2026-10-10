/**
 * `signed-acknowledgment/v2` (ADR 0015 question C; the L2a2 formats in its
 * note, N12): an acknowledgment signed twice over the same canonical body,
 * once with ES256 and once with ML-DSA-65, both required. The key id names
 * the pair, and the body carries it, so neither signature can be lifted onto
 * another key's half.
 *
 * Like v1 this module holds only what the browser, the SDK and the API must
 * agree on byte for byte. It loads no signing library: the API verifies with
 * its platform (L2-2), and signing lives behind records-crypto's asymmetric
 * subpath.
 */
import { fromBase64Url } from '../records-crypto/base64url';
import { concatBytes, sha256, utf8 } from '../records-crypto/platform-crypto';
import type { AcknowledgmentSignedBodyV1, SigningPublicKeyJwkV1 } from './signed-acknowledgment-v1';

export const SIGNED_ACKNOWLEDGMENT_ALGS_V2 = ['ES256', 'ML-DSA-65'] as const;
export const ACKNOWLEDGMENT_KEY_ID_LABEL_V2 = 'pacspace:ack-key-id:v1';
export const MLDSA65_PUBLIC_KEY_BYTES = 1952;
export const MLDSA65_SIGNATURE_BYTES = 3309;
export const ES256_PUBLIC_POINT_BYTES = 65;

/** Fields of a v2 acknowledgment that both signatures cover: v1's, and the pair's key id. */
export interface AcknowledgmentSignedBodyV2 extends AcknowledgmentSignedBodyV1 {
  /** 64 lowercase hex: acknowledgmentKeyIdV2 of the two public keys. */
  keyId: string;
}

/** Canonical JSON in the fixed member order below, as v1 writes it. */
export function canonicalAcknowledgmentBodyV2(body: AcknowledgmentSignedBodyV2): string {
  return JSON.stringify({
    v: 2,
    kind: 'acknowledgment',
    handle: body.handle,
    seq: body.seq,
    matched: body.matched,
    missing: body.missing,
    historyDigest: body.historyDigest.toLowerCase(),
    signedAt: body.signedAt,
    keyId: body.keyId.toLowerCase(),
  });
}

/** The P-256 public key as its 65-byte uncompressed point, or null if the JWK is not one. */
export function es256PublicPointV1(key: SigningPublicKeyJwkV1): Uint8Array | null {
  if (!key || key.kty !== 'EC' || key.crv !== 'P-256') return null;
  const x = typeof key.x === 'string' ? fromBase64Url(key.x) : null;
  const y = typeof key.y === 'string' ? fromBase64Url(key.y) : null;
  if (!x || !y || x.length !== 32 || y.length !== 32) return null;
  return concatBytes(new Uint8Array([4]), x, y);
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * `SHA-256("pacspace:ack-key-id:v1" || 0x00 || P-256 point || 0x00 || ML-DSA-65
 * public key)`, 64 lowercase hex; null when either key has the wrong form.
 * Carried as `actorId`.
 */
export async function acknowledgmentKeyIdV2(es256: SigningPublicKeyJwkV1, mldsaPublicKey: Uint8Array): Promise<string | null> {
  const point = es256PublicPointV1(es256);
  if (!point || !(mldsaPublicKey instanceof Uint8Array) || mldsaPublicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) return null;
  const sep = new Uint8Array([0]);
  return hex(await sha256(concatBytes(utf8(ACKNOWLEDGMENT_KEY_ID_LABEL_V2), sep, point, sep, mldsaPublicKey)));
}

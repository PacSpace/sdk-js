/**
 * Signed acknowledgments and claims, custody rung (b) of the records buyer
 * posture plan (Slice E2b; design record
 * docs/eng/verification-statement-and-bilateral-signing.md:59).
 *
 * The browser mints one ECDSA P-256 keypair per Shared Record handle,
 * non-extractable, kept in its own storage for that origin, and signs the
 * canonical body below. The API verifies the signature, derives the key's
 * RFC 7638 thumbprint, and (key rule (i), David 2026-09-17 on HG-V38-006)
 * binds the first thumbprint that signs for a handle to that handle; a
 * later key on the same handle is not admitted as a signed acknowledgment
 * and the write falls back to rung (a).
 *
 * This module holds only what both sides must agree on byte for byte: the
 * canonical bodies and the thumbprint input. It has no dependency on
 * WebCrypto or node:crypto so it can be imported anywhere.
 */

/** The only algorithm admitted at rung (b): ECDSA over P-256 with SHA-256, IEEE P1363 (r || s) signature. */
export const SIGNED_ACKNOWLEDGMENT_ALG_V1 = 'ES256' as const;

/** Public half of the browser's key, as the JWK members that identify an EC P-256 key. */
export interface SigningPublicKeyJwkV1 {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

/** What travels beside an acknowledgment or a claim when the browser signed it. */
export interface SignedEnvelopeV1 {
  alg: typeof SIGNED_ACKNOWLEDGMENT_ALG_V1;
  publicKey: SigningPublicKeyJwkV1;
  /** base64url, no padding, of the 64-byte r || s signature. */
  signature: string;
  /** RFC 3339 UTC instant the browser signed at; part of the signed body. */
  signedAt: string;
}

/** Fields of an acknowledgment that the signature covers. */
export interface AcknowledgmentSignedBodyV1 {
  handle: string;
  seq: number;
  matched: boolean;
  missing: boolean;
  historyDigest: string;
  signedAt: string;
}

/** Fields of a Balance claim half that the signature covers. */
export interface ClaimSignedBodyV1 {
  customerId: string;
  period: string;
  balance: number;
  signedAt: string;
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

/**
 * Canonical JSON: members in the fixed order below, no whitespace, strings
 * JSON-escaped, `historyDigest` lowercased. Both the browser and the API
 * serialize with this function so the bytes under the signature match.
 */
export function canonicalAcknowledgmentBodyV1(body: AcknowledgmentSignedBodyV1): string {
  return JSON.stringify({
    v: 1,
    kind: 'acknowledgment',
    handle: body.handle,
    seq: body.seq,
    matched: body.matched,
    missing: body.missing,
    historyDigest: body.historyDigest.toLowerCase(),
    signedAt: body.signedAt,
  });
}

/** What a reader confirms on a Balance cycle page; its SHA-256 is the acknowledgment's payload. */
export interface CycleConfirmationBodyV1 {
  checkpointId: string;
  customerId: string;
  period: string;
  balance: number;
}

export function canonicalCycleConfirmationBodyV1(body: CycleConfirmationBodyV1): string {
  return JSON.stringify({
    v: 1,
    kind: 'cycle-confirmation',
    checkpointId: body.checkpointId,
    customerId: body.customerId,
    period: body.period,
    balance: body.balance,
  });
}

export function canonicalClaimBodyV1(body: ClaimSignedBodyV1): string {
  return JSON.stringify({
    v: 1,
    kind: 'claim',
    customerId: body.customerId,
    period: body.period,
    balance: body.balance,
    signedAt: body.signedAt,
  });
}

/**
 * RFC 7638 thumbprint input for an EC key: the required members, in
 * lexicographic order, no whitespace. Hash it with SHA-256 to get the
 * thumbprint; the hex of that hash is what PacSpace stores as `actorId`.
 */
export function signingKeyThumbprintInputV1(key: SigningPublicKeyJwkV1): string {
  return JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y });
}

/** Shape check for the envelope (no cryptography). */
export function isSignedEnvelopeV1(value: unknown): value is SignedEnvelopeV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  if (v.alg !== SIGNED_ACKNOWLEDGMENT_ALG_V1) return false;
  if (typeof v.signature !== 'string' || !BASE64URL.test(v.signature) || v.signature.length !== 86) return false;
  if (typeof v.signedAt !== 'string' || !RFC3339_UTC.test(v.signedAt)) return false;
  const k = v.publicKey as Record<string, unknown> | undefined;
  if (!k || typeof k !== 'object') return false;
  if (k.kty !== 'EC' || k.crv !== 'P-256') return false;
  // The private member never belongs in a request; refuse rather than drop it.
  if ('d' in k) return false;
  return (
    typeof k.x === 'string' && BASE64URL.test(k.x) && k.x.length === 43 && typeof k.y === 'string' && BASE64URL.test(k.y) && k.y.length === 43
  );
}

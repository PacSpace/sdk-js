import { canonicalizeJcs } from '../proof/jcs';
import { fromBase64Url, toBase64Url } from './base64url';
import { concatBytes, platformCrypto, randomBytes, utf8 } from './platform-crypto';
import { RECORD_DISCLOSURE_MAX_BYTES_V1, RecordDisclosureError, type RecordDisclosureV1 } from './record-disclosure-v1';

/**
 * The sealed disclosure a link holds (ADR 0016; record-hash-v2.md section 7):
 * AES-256-GCM under a fresh key that travels only after `#` in the link, with
 * the link's handle as additional data. The plaintext is the disclosure's
 * canonical bytes padded with spaces to a 4096-byte step. These functions keep
 * no copy of the key and never log; no result or error carries the key, the
 * handle or the plaintext.
 */
export const RECORD_DISCLOSURE_ENVELOPE_VERSION_V1 = 0x01;
export const RECORD_DISCLOSURE_PAD_BLOCK_V1 = 4096;
export const RECORD_DISCLOSURE_ENVELOPE_MAX_BYTES_V1 = 1 + 12 + RECORD_DISCLOSURE_MAX_BYTES_V1 + 16;
export const RECORD_DISCLOSURE_ENVELOPE_MAX_CHARS_V1 = Math.ceil((RECORD_DISCLOSURE_ENVELOPE_MAX_BYTES_V1 * 4) / 3);

export type DisclosureEnvelopeRefusalV1 =
  | 'DISCLOSURE_ENVELOPE_MALFORMED'
  | 'DISCLOSURE_ENVELOPE_TOO_LARGE'
  | 'DISCLOSURE_ENVELOPE_AUTH_FAILED';

const REASONS: Record<DisclosureEnvelopeRefusalV1, string> = {
  DISCLOSURE_ENVELOPE_MALFORMED: "This link's sealed disclosure is not in a form this version can open.",
  DISCLOSURE_ENVELOPE_TOO_LARGE: "This link's sealed disclosure is larger than a disclosure may be.",
  DISCLOSURE_ENVELOPE_AUTH_FAILED:
    'This disclosure could not be opened with this link. The link may be incomplete, or the disclosure belongs to another link.',
};

const AAD_LABEL = 'pacspace:record-disclosure:v1';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + IV_BYTES;
const SPACE = 0x20;
const FRAGMENT = /^dk=([A-Za-z0-9_-]{43})$/;

function aadOf(handle: string): Uint8Array {
  return concatBytes(utf8(AAD_LABEL), new Uint8Array([0]), utf8(handle));
}

function refuse(code: DisclosureEnvelopeRefusalV1): { ok: false; code: DisclosureEnvelopeRefusalV1; reason: string } {
  return { ok: false, code, reason: REASONS[code] };
}

/** 32 fresh random bytes, one key per disclosure. */
export function newDisclosureKeyV1(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

/** "dk=" plus the key's 43 base64url characters, for after `#` in the link. */
export function disclosureFragmentV1(key: Uint8Array): string {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
  return `dk=${toBase64Url(key)}`;
}

/** The key from "#dk=..." or "dk=...", or null for anything else, including a non-canonical key text. */
export function readDisclosureFragmentV1(hash: string): Uint8Array | null {
  if (typeof hash !== 'string') return null;
  const match = FRAGMENT.exec(hash.startsWith('#') ? hash.slice(1) : hash);
  if (!match) return null;
  const key = fromBase64Url(match[1]);
  return key && key.length === KEY_BYTES ? key : null;
}

/** The keyless checks decryption runs first (size, encoding, version byte, padded length). Never throws. */
export function readDisclosureEnvelopeShapeV1(
  text: string,
): { ok: true; byteLength: number } | { ok: false; code: 'DISCLOSURE_ENVELOPE_MALFORMED' | 'DISCLOSURE_ENVELOPE_TOO_LARGE' } {
  if (typeof text !== 'string') return { ok: false, code: 'DISCLOSURE_ENVELOPE_MALFORMED' };
  if (text.length > RECORD_DISCLOSURE_ENVELOPE_MAX_CHARS_V1) return { ok: false, code: 'DISCLOSURE_ENVELOPE_TOO_LARGE' };
  const bytes = fromBase64Url(text);
  if (!bytes || bytes[0] !== RECORD_DISCLOSURE_ENVELOPE_VERSION_V1) return { ok: false, code: 'DISCLOSURE_ENVELOPE_MALFORMED' };
  const cipherLength = bytes.length - HEADER_BYTES - TAG_BYTES;
  if (cipherLength <= 0 || cipherLength % RECORD_DISCLOSURE_PAD_BLOCK_V1 !== 0) {
    return { ok: false, code: 'DISCLOSURE_ENVELOPE_MALFORMED' };
  }
  return { ok: true, byteLength: bytes.length };
}

async function aesKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const subtle = (await platformCrypto()).subtle;
  return subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, [usage]);
}

/** The base64url envelope of a disclosure under a fresh IV. */
export async function encryptDisclosureV1(input: { disclosure: RecordDisclosureV1; key: Uint8Array; handle: string }): Promise<string> {
  const { key, handle } = input;
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES || typeof handle !== 'string') {
    throw new RecordDisclosureError('DISCLOSURE_MALFORMED');
  }
  const text = utf8(canonicalizeJcs(input.disclosure));
  if (text.length > RECORD_DISCLOSURE_MAX_BYTES_V1) throw new RecordDisclosureError('DISCLOSURE_TOO_LARGE');
  const padded = new Uint8Array(Math.ceil(text.length / RECORD_DISCLOSURE_PAD_BLOCK_V1) * RECORD_DISCLOSURE_PAD_BLOCK_V1);
  padded.set(text);
  padded.fill(SPACE, text.length);
  const iv = randomBytes(IV_BYTES);
  const subtle = (await platformCrypto()).subtle;
  const sealed = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aadOf(handle) as BufferSource, tagLength: 128 }, await aesKey(key, 'encrypt'), padded as BufferSource),
  );
  return toBase64Url(concatBytes(new Uint8Array([RECORD_DISCLOSURE_ENVELOPE_VERSION_V1]), iv, sealed));
}

/** Opens an envelope; the caller then runs verifyRecordDisclosureV1 on `disclosure`. Never throws. */
export async function decryptDisclosureV1(input: {
  envelope: string;
  key: Uint8Array;
  handle: string;
}): Promise<{ ok: true; disclosure: unknown } | { ok: false; code: DisclosureEnvelopeRefusalV1; reason: string }> {
  try {
    const shape = readDisclosureEnvelopeShapeV1(input?.envelope);
    if (!shape.ok) return refuse(shape.code);
    const bytes = fromBase64Url(input.envelope) as Uint8Array;
    const { key, handle } = input;
    if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES || typeof handle !== 'string') {
      return refuse('DISCLOSURE_ENVELOPE_AUTH_FAILED');
    }
    let plain: Uint8Array;
    try {
      const subtle = (await platformCrypto()).subtle;
      plain = new Uint8Array(
        await subtle.decrypt(
          { name: 'AES-GCM', iv: bytes.subarray(1, HEADER_BYTES) as BufferSource, additionalData: aadOf(handle) as BufferSource, tagLength: 128 },
          await aesKey(key, 'decrypt'),
          bytes.subarray(HEADER_BYTES) as BufferSource,
        ),
      );
    } catch {
      return refuse('DISCLOSURE_ENVELOPE_AUTH_FAILED');
    }
    let end = plain.length;
    while (end > 0 && plain[end - 1] === SPACE) end -= 1;
    if (plain.length - end >= RECORD_DISCLOSURE_PAD_BLOCK_V1) return refuse('DISCLOSURE_ENVELOPE_MALFORMED');
    const trimmed = plain.subarray(0, end);
    const text = new TextDecoder('utf-8', { fatal: true }).decode(trimmed);
    const disclosure: unknown = JSON.parse(text);
    const canonical = utf8(canonicalizeJcs(disclosure));
    if (canonical.length !== trimmed.length || canonical.some((b, i) => b !== trimmed[i])) return refuse('DISCLOSURE_ENVELOPE_MALFORMED');
    return { ok: true, disclosure };
  } catch {
    return refuse('DISCLOSURE_ENVELOPE_MALFORMED');
  }
}

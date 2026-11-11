/**
 * `reader-crypto-v1` (ADR 0019; records prototype build, R6, D-1, D-14, D-16): the compositions a trail link's
 * devices, link keys, reveals, answers, sealed notes and seeded samples are made of. This half holds every
 * composition that needs no key wrap, built only from SHA-256, HMAC-SHA-256, HKDF-SHA-256 and AES-256-GCM through
 * the platform's WebCrypto and BF's `record-disclosure/v1` envelope, so the API, the browser, the SDK and the
 * checker all read the same bytes. The wraps (`wrapDisclosureKeyV1` and its open) live beside BF's asymmetric layer,
 * in `records-crypto/asymmetric/reader-wraps-v1.ts`, so nothing that imports shared's index loads that layer.
 *
 * Nothing here logs, and no refusal carries a key, a note or a disclosure.
 */
import { canonicalizeJcs } from '../proof/jcs';
import { fromBase64Url, toBase64Url } from '../records-crypto/base64url';
import { decryptDisclosureV1, encryptDisclosureV1 } from '../records-crypto/disclosure-envelope-v1';
import { concatBytes, hmacSha256, platformCrypto, randomBytes, sha256, utf8 } from '../records-crypto/platform-crypto';
import { RECORD_DISCLOSURE_SCHEMA_V1, RECORD_DISCLOSURE_SCHEMA_V2, type RecordDisclosure } from '../records-crypto/record-disclosure-v1';
import { workspacePublicKeyIdV1 } from '../records-crypto/wrap-shapes-v1';
import { MLDSA65_PUBLIC_KEY_BYTES, es256PublicPointV1 } from './signed-acknowledgment-v2';
import type { SigningPublicKeyJwkV1 } from './signed-acknowledgment-v1';

export const READER_CRYPTO_LABELS_V1 = {
  deviceId: 'pacspace:reader-device:v1',
  proofKey: 'pacspace:device-proof-key:v1',
  deviceProof: 'pacspace:device-proof:v1',
  deviceConfirmed: 'pacspace:device-confirmed:v1',
  deviceApproval: 'pacspace:device-approval:v1',
  signedRequest: 'pacspace:signed-request:v1',
  deviceDisconnect: 'pacspace:device-disconnect:v1',
  sealedNote: 'pacspace:sealed-note:v1',
  workspaceKey: 'pacspace:workspace-key:v1',
} as const;

export const SEALED_NOTE_SCHEMA_V1 = 'sealed-note/v1' as const;
export const SAMPLE_METHOD_V1 = 'pacspace-sample/v1' as const;
/** The X-Wing public key's encoded length (the ML-KEM-768 key, then the X25519 key), as BF's wraps take it. */
export const DEVICE_XWING_PUBLIC_KEY_BYTES_V1 = 1216;
/** A P-256 SubjectPublicKeyInfo in DER, uncompressed point. */
export const DEVICE_P256_SPKI_BYTES_V1 = 91;
export const DEVICE_CODE_DIGITS_V1 = 40;
export const LINK_KEY_BYTES_V1 = 32;
export const SAMPLE_SEED_HEX_V1 = /^[0-9a-f]{64}$/;
/** A note's envelope, as text, at most this long: about 48 KiB of note. */
export const SEALED_NOTE_MAX_CHARS_V1 = 65_536;

export type ReaderCryptoCodeV1 = 'READER_BINDING_INVALID' | 'READER_DEVICE_KEYS_INVALID' | 'READER_KEY_INVALID' | 'SEALED_NOTE_MALFORMED';

/** Thrown by the making side only; its message is the code. */
export class ReaderCryptoError extends Error {
  constructor(readonly code: ReaderCryptoCodeV1) {
    super(code);
    this.name = 'ReaderCryptoError';
  }
}

const SEP = new Uint8Array([0]);
const HEX64 = /^[0-9a-f]{64}$/;
const P256_SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// ------------------------------------------------------------------ typed bindings (D-1)

/** A trail link's handle as bindings take it: `csh1_` and base64url characters, never a colon. */
const HANDLE = /^csh1_[A-Za-z0-9_-]{1,80}$/;
/** A record key or wire id, a reference or a kind: printable, never a colon, so no two bindings can read alike. */
const PART = /^[\x21-\x39\x3b-\x7e]{1,128}$/;
const KIND = /^[a-z][a-z0-9-]{0,31}$/;
const TRAIL_ID = /^[a-z0-9]{20,32}$/;

function check(ok: boolean): void {
  if (!ok) throw new ReaderCryptoError('READER_BINDING_INVALID');
}
const isEpoch = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 1;
const isNatural = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;

/** `link-key:<handle>:<epoch>`, a link key's wraps. */
export function linkKeyBindingV1(handle: string, epoch: number): string {
  check(HANDLE.test(handle) && isEpoch(epoch));
  return `link-key:${handle}:${epoch}`;
}

/** `reveal:<handle>:<epoch>:<recordKey>`, a reveal's envelope. */
export function revealBindingV1(handle: string, epoch: number, recordKey: string): string {
  check(HANDLE.test(handle) && isEpoch(epoch) && PART.test(recordKey));
  return `reveal:${handle}:${epoch}:${recordKey}`;
}

/** `answer:<handle>:<requestRef>`, an answer key's wraps. */
export function answerKeyBindingV1(handle: string, requestRef: string): string {
  check(HANDLE.test(handle) && PART.test(requestRef));
  return `answer:${handle}:${requestRef}`;
}

/** `answer:<handle>:<requestRef>:<number>:<seq>`, one shown entry's envelope. */
export function answerEntryBindingV1(handle: string, requestRef: string, number: number, seq: number): string {
  check(HANDLE.test(handle) && PART.test(requestRef) && isEpoch(number) && isNatural(seq));
  return `answer:${handle}:${requestRef}:${number}:${seq}`;
}

/** Where a note belongs: a link's handle, or a trail's rule (`trail-rule:<trailId>`, which never reads as a handle). */
export type NoteScopeV1 = { handle: string } | { trailRuleOf: string };

export interface NoteNameV1 {
  scope: NoteScopeV1;
  kind: string;
  ref: string;
  n: number;
}

function scopeText(scope: NoteScopeV1): string {
  if (scope && 'handle' in scope) {
    check(HANDLE.test(scope.handle));
    return scope.handle;
  }
  check(!!scope && typeof scope.trailRuleOf === 'string' && TRAIL_ID.test(scope.trailRuleOf));
  return `trail-rule:${scope.trailRuleOf}`;
}

function noteParts(name: NoteNameV1): string {
  check(!!name && KIND.test(name.kind) && PART.test(name.ref) && isEpoch(name.n));
  return `${scopeText(name.scope)}:${name.kind}:${name.ref}:${name.n}`;
}

/** `note:<handle or trail-rule:<trailId>>:<kind>:<ref>:<n>`, a sealed note key's wraps. */
export function noteKeyBindingV1(name: NoteNameV1): string {
  return `note:${noteParts(name)}`;
}

/** `pacspace:sealed-note:v1:<handle or trail binding>:<kind>:<ref>:<n>`, a sealed note's additional data. */
export function noteAdditionalDataV1(name: NoteNameV1): string {
  return `${READER_CRYPTO_LABELS_V1.sealedNote}:${noteParts(name)}`;
}

/**
 * An acknowledgment's flag notes (R7; David, 2026-10-26): one fresh key per acknowledgment, wrapped under
 * `note:<handle>:ack-flags:<checkRef>:1`, and each flagged entry's note sealed under it with the additional data
 * `pacspace:sealed-note:v1:<handle>:ack-flag:<checkRef>.<record>.<entry>:1`, so a note opens only as its own entry's.
 */
export function ackFlagNotesKeyNameV1(handle: string, checkRef: string): NoteNameV1 {
  return { scope: { handle }, kind: 'ack-flags', ref: checkRef, n: 1 };
}

export function ackFlagNoteNameV1(handle: string, checkRef: string, record: number, entry: number): NoteNameV1 {
  check(isEpoch(record) && isEpoch(entry));
  return { scope: { handle }, kind: 'ack-flag', ref: `${checkRef}.${record}.${entry}`, n: 1 };
}

/** The acknowledgment's own note, under the same key: `pacspace:sealed-note:v1:<handle>:ack-note:<checkRef>:1`. */
export function ackNoteNameV1(handle: string, checkRef: string): NoteNameV1 {
  return { scope: { handle }, kind: 'ack-note', ref: checkRef, n: 1 };
}

// ------------------------------------------------------------------ the device id and its code (D-1)

export interface DevicePublicKeysV1 {
  xwingPublicKey: Uint8Array;
  p256Jwk: SigningPublicKeyJwkV1;
  mldsaPublicKey: Uint8Array;
}

/** A P-256 public JWK as its 91-byte SubjectPublicKeyInfo, once WebCrypto has taken the point as one on the curve. */
export async function p256SpkiOfJwkV1(jwk: SigningPublicKeyJwkV1): Promise<Uint8Array> {
  const point = es256PublicPointV1(jwk);
  if (!point) throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  const { subtle } = await platformCrypto();
  let spki: Uint8Array;
  try {
    const key = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    spki = new Uint8Array(await subtle.exportKey('spki', key));
  } catch {
    throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  }
  const expected = concatBytes(P256_SPKI_PREFIX, point);
  if (spki.length !== DEVICE_P256_SPKI_BYTES_V1 || spki.some((b, i) => b !== expected[i])) throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  return spki;
}

/**
 * `SHA-256("pacspace:reader-device:v1" || 0x00 || xwingPublicKey || 0x00 || p256Spki || 0x00 || mldsaPublicKey)`,
 * 64 lowercase hex: one id over all three public keys, so a key swapped anywhere changes it.
 */
export async function deviceIdV1(keys: DevicePublicKeysV1): Promise<string> {
  if (!(keys?.xwingPublicKey instanceof Uint8Array) || keys.xwingPublicKey.length !== DEVICE_XWING_PUBLIC_KEY_BYTES_V1) {
    throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  }
  if (!(keys.mldsaPublicKey instanceof Uint8Array) || keys.mldsaPublicKey.length !== MLDSA65_PUBLIC_KEY_BYTES) {
    throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  }
  const spki = await p256SpkiOfJwkV1(keys.p256Jwk);
  return hex(await sha256(concatBytes(utf8(READER_CRYPTO_LABELS_V1.deviceId), SEP, keys.xwingPublicKey, SEP, spki, SEP, keys.mldsaPublicKey)));
}

/**
 * The device's code: the device id in the key holder code's format, the first 17 bytes as an unsigned big-endian
 * integer modulo 10^40, 40 digits with leading zeros in eight groups of five.
 */
export function deviceCodeV1(deviceId: string): string {
  check(typeof deviceId === 'string' && HEX64.test(deviceId));
  let n = 0n;
  for (let i = 0; i < 17; i += 1) n = (n << 8n) | BigInt(parseInt(deviceId.slice(i * 2, i * 2 + 2), 16));
  const digits = (n % 10n ** 40n).toString().padStart(DEVICE_CODE_DIGITS_V1, '0');
  return digits.match(/.{5}/g)!.join(' ');
}

// ------------------------------------------------------------------ the proof key, proofs, tags and approvals (D-16)

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== LINK_KEY_BYTES_V1) throw new ReaderCryptoError('READER_KEY_INVALID');
}

/** `HKDF-SHA-256(linkKey, salt empty, info "pacspace:device-proof-key:v1", 32 bytes)`; proofs and tags never use the link key itself. */
export async function proofKeyV1(linkKey: Uint8Array): Promise<Uint8Array> {
  assertKey(linkKey);
  const { subtle } = await platformCrypto();
  const base = await subtle.importKey('raw', Uint8Array.from(linkKey), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(READER_CRYPTO_LABELS_V1.proofKey) as BufferSource }, base, 256);
  return new Uint8Array(bits);
}

function deviceMessage(label: string, handle: string, epoch: number, deviceId: string): string {
  check(HANDLE.test(handle) && isEpoch(epoch) && typeof deviceId === 'string' && HEX64.test(deviceId));
  return `${label}:${handle}:${epoch}:${deviceId}`;
}

/** A proof key a browser keeps as a CryptoKey: HMAC with SHA-256 over 32 bytes, usable to sign. */
function isProofKey(key: unknown): key is CryptoKey {
  if (typeof CryptoKey === 'undefined' || !(key instanceof CryptoKey) || key.type !== 'secret' || !key.usages.includes('sign')) return false;
  const algorithm = key.algorithm as HmacKeyAlgorithm;
  return algorithm.name === 'HMAC' && algorithm.hash?.name === 'SHA-256' && algorithm.length === LINK_KEY_BYTES_V1 * 8;
}

async function proofHmac(proofKey: Uint8Array | CryptoKey, message: string): Promise<string> {
  if (isProofKey(proofKey)) {
    const { subtle } = await platformCrypto();
    return hex(new Uint8Array(await subtle.sign('HMAC', proofKey, utf8(message) as BufferSource)));
  }
  assertKey(proofKey as Uint8Array);
  return hex(await hmacSha256(proofKey as Uint8Array, utf8(message)));
}

/** `HMAC-SHA-256(proofKey, "pacspace:device-proof:v1:<handle>:<epoch>:<deviceId>")`, 64 lowercase hex: the device holds the link key. */
export async function deviceProofV1(proofKey: Uint8Array | CryptoKey, handle: string, epoch: number, deviceId: string): Promise<string> {
  return proofHmac(proofKey, deviceMessage(READER_CRYPTO_LABELS_V1.deviceProof, handle, epoch, deviceId));
}

/** `HMAC-SHA-256(proofKey, "pacspace:device-confirmed:v1:<handle>:<epoch>:<deviceId>")`, 64 lowercase hex: the lab's side confirmed it. */
export async function confirmationTagV1(proofKey: Uint8Array | CryptoKey, handle: string, epoch: number, deviceId: string): Promise<string> {
  return proofHmac(proofKey, deviceMessage(READER_CRYPTO_LABELS_V1.deviceConfirmed, handle, epoch, deviceId));
}

/** What a browser keeps of a code link's key (plan conflict 2, D-26): two keys it can use and never export. */
export interface ReaderLinkKeysV1 {
  /** AES-256-GCM, decrypt only: opens the link's reveals. */
  revealKey: CryptoKey;
  /** HMAC-SHA-256 over proofKeyV1's bytes, sign only: proofs and confirmation tags. */
  proofKey: CryptoKey;
}

/**
 * The link key as the two non-extractable keys a browser keeps in its place. The caller's bytes are neither kept nor
 * changed; the caller zeroes them once these are made. The proof key's bytes are zeroed here.
 */
export async function readerLinkKeysV1(linkKey: Uint8Array): Promise<ReaderLinkKeysV1> {
  assertKey(linkKey);
  const { subtle } = await platformCrypto();
  const copy = Uint8Array.from(linkKey);
  const proofBytes = await proofKeyV1(copy);
  try {
    const [revealKey, proofKey] = await Promise.all([
      subtle.importKey('raw', copy as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']),
      subtle.importKey('raw', proofBytes as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']),
    ]);
    return { revealKey, proofKey };
  } finally {
    copy.fill(0);
    proofBytes.fill(0);
  }
}

/**
 * `HMAC-SHA-256(proofKey, "pacspace:workspace-key:v1:<handle>:<epoch>:<keyId>")`, 64 lowercase hex: the lab's browser
 * names the workspace identity a reader seals to (David, 2026-10-26). `keyId` is `workspacePublicKeyIdV1` of the
 * identity's X-Wing key. PacSpace never holds the proof key in an encrypted workspace, so it cannot tag a key of its own.
 * A reader's browser on a code link checks the tag with the proof key it keeps as a CryptoKey it can use and never
 * export (U5), as it works out confirmation tags.
 */
export async function workspaceKeyTagV1(proofKey: Uint8Array | CryptoKey, handle: string, epoch: number, keyId: string): Promise<string> {
  return proofHmac(proofKey, deviceMessage(READER_CRYPTO_LABELS_V1.workspaceKey, handle, epoch, keyId));
}

/**
 * Whether a served workspace key is the one the lab's browser tagged for this link and epoch: its key id worked out
 * from the key's own bytes, never read from the response, and the tag compared in constant time. A reader's browser
 * seals nothing to the workspace unless this holds. Never throws.
 */
export async function servedWorkspaceKeyV1(input: {
  proofKey: Uint8Array | CryptoKey;
  handle: string;
  epoch: number;
  publicKey: Uint8Array;
  tag: unknown;
}): Promise<{ ok: true; keyId: string } | { ok: false; code: 'WORKSPACE_KEY_NOT_TAGGED' }> {
  const refused = { ok: false as const, code: 'WORKSPACE_KEY_NOT_TAGGED' as const };
  try {
    const keyId = await workspacePublicKeyIdV1(input.publicKey);
    if (!keyId || typeof input.tag !== 'string') return refused;
    return sameHex64V1(await workspaceKeyTagV1(input.proofKey, input.handle, input.epoch, keyId), input.tag) ? { ok: true, keyId } : refused;
  } catch {
    return refused;
  }
}

/**
 * Whether every device `GET /seal-to` serves is one the lab's side confirmed on this link and epoch: each device id
 * worked out from the device's three public keys, never read from the response, so a sealing key PacSpace swapped in
 * changes the id and fails its confirmation tag. One device that fails refuses them all. A reader's browser seals
 * nothing to a device unless this holds. Never throws.
 */
export async function servedDevicesV1(input: {
  proofKey: Uint8Array | CryptoKey;
  handle: string;
  epoch: number;
  devices: unknown;
}): Promise<{ ok: true; devices: Array<{ deviceId: string; xwingPublicKey: Uint8Array }> } | { ok: false; code: 'DEVICE_NOT_TAGGED' }> {
  const refused = { ok: false as const, code: 'DEVICE_NOT_TAGGED' as const };
  try {
    if (!Array.isArray(input.devices) || input.devices.length === 0) return refused;
    const checked: Array<{ deviceId: string; xwingPublicKey: Uint8Array }> = [];
    for (const served of input.devices as Array<Record<string, unknown>>) {
      if (served?.confirmedEpoch !== input.epoch || typeof served.xwingPublicKey !== 'string' || typeof served.mldsaPublicKey !== 'string') return refused;
      const xwingPublicKey = fromBase64Url(served.xwingPublicKey);
      const mldsaPublicKey = fromBase64Url(served.mldsaPublicKey);
      if (!xwingPublicKey || !mldsaPublicKey) return refused;
      const deviceId = await deviceIdV1({ xwingPublicKey, p256Jwk: served.p256Jwk as SigningPublicKeyJwkV1, mldsaPublicKey });
      if (!sameHex64V1(deviceId, served.deviceId)) return refused;
      if (!sameHex64V1(await confirmationTagV1(input.proofKey, input.handle, input.epoch, deviceId), served.confirmationTag)) return refused;
      checked.push({ deviceId, xwingPublicKey });
    }
    return new Set(checked.map((d) => d.deviceId)).size === checked.length ? { ok: true, devices: checked } : refused;
  } catch {
    return refused;
  }
}

/** `pacspace:device-approval:v1:<handle>:<epoch>:<new deviceId>`, the message a confirmed device signs with its v2 pair. */
export function approvalMessageV1(handle: string, epoch: number, newDeviceId: string): string {
  return deviceMessage(READER_CRYPTO_LABELS_V1.deviceApproval, handle, epoch, newDeviceId);
}

/**
 * ADR 0019's signed request (vector RQ-01): SHA-256, as 64 lowercase hex, of the JCS of the request's body as sent,
 * without `signedBy` (`{clientRequestId, items, sample, question}`), so every pick, the sample and the question are bound.
 */
export async function signedRequestDigestV1(body: Readonly<Record<string, unknown>>): Promise<string> {
  check(!!body && typeof body === 'object' && !Array.isArray(body));
  const rest: Record<string, unknown> = { ...body };
  delete rest.signedBy;
  return hex(await sha256(utf8(canonicalizeJcs(rest))));
}

/** `pacspace:signed-request:v1:<handle>:<epoch>:<deviceId>:<requestDigest>`, what the sending device signs with its v2 pair. */
export function signedRequestMessageV1(handle: string, epoch: number, deviceId: string, requestDigest: string): string {
  check(typeof requestDigest === 'string' && HEX64.test(requestDigest));
  return `${deviceMessage(READER_CRYPTO_LABELS_V1.signedRequest, handle, epoch, deviceId)}:${requestDigest}`;
}

/** `pacspace:device-disconnect:v1:<handle>:<epoch>:<agent deviceId>` (vector RQ-02), signed by the agent or its person's confirmed browser. */
export function disconnectMessageV1(handle: string, epoch: number, deviceId: string): string {
  return deviceMessage(READER_CRYPTO_LABELS_V1.deviceDisconnect, handle, epoch, deviceId);
}

/** Two 64-hex values compared in time that does not depend on where they differ. */
export function sameHex64V1(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string' || !HEX64.test(a) || !HEX64.test(b)) return false;
  let diff = 0;
  for (let i = 0; i < 64; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ------------------------------------------------------------------ reveals and answers (record-disclosure under typed bindings)

/** A record's reveal, `record-disclosure` under the link key for its epoch and record. */
export function revealRecordV1(input: { disclosure: RecordDisclosure; linkKey: Uint8Array; handle: string; epoch: number; recordKey: string }): Promise<string> {
  assertKey(input.linkKey);
  return encryptDisclosureV1({ disclosure: input.disclosure, key: input.linkKey, handle: revealBindingV1(input.handle, input.epoch, input.recordKey) });
}

/** Opens a reveal with the link key's bytes, or with the reveal key a browser keeps (readerLinkKeysV1). */
export function openRevealV1(input: { envelope: string; linkKey: Uint8Array | CryptoKey; handle: string; epoch: number; recordKey: string }) {
  return decryptDisclosureV1({ envelope: input.envelope, key: input.linkKey, handle: revealBindingV1(input.handle, input.epoch, input.recordKey) });
}

/** One shown entry's disclosure under the answer key. */
export function sealAnswerEntryV1(input: { disclosure: RecordDisclosure; answerKey: Uint8Array; handle: string; requestRef: string; number: number; seq: number }): Promise<string> {
  assertKey(input.answerKey);
  return encryptDisclosureV1({
    disclosure: input.disclosure,
    key: input.answerKey,
    handle: answerEntryBindingV1(input.handle, input.requestRef, input.number, input.seq),
  });
}

/**
 * Opens one shown entry and checks its form against the record's hash version: `record-disclosure/v1` for a
 * record on record hash v2 (or v1), `record-disclosure/v2` for one on v3. The caller then checks it against the
 * entry's committed seal with `verifyRecordDisclosureV1` and its fields with `shownFieldsMatchV1`.
 */
export async function openAnswerEntryV1(input: {
  envelope: string;
  answerKey: Uint8Array;
  handle: string;
  requestRef: string;
  number: number;
  seq: number;
  recordHashVersion: 1 | 2 | 3;
}): Promise<{ ok: true; disclosure: RecordDisclosure } | { ok: false; code: string }> {
  const opened = await decryptDisclosureV1({
    envelope: input.envelope,
    key: input.answerKey,
    handle: answerEntryBindingV1(input.handle, input.requestRef, input.number, input.seq),
  });
  if (!opened.ok) return { ok: false, code: opened.code };
  const d = opened.disclosure as { schema?: unknown; recordHashVersion?: unknown };
  const wanted = input.recordHashVersion === 3 ? RECORD_DISCLOSURE_SCHEMA_V2 : RECORD_DISCLOSURE_SCHEMA_V1;
  if (d?.schema !== wanted || (input.recordHashVersion === 3) !== (d.recordHashVersion === 3)) return { ok: false, code: 'RECORD_HASH_VERSION_UNKNOWN' };
  return { ok: true, disclosure: opened.disclosure as RecordDisclosure };
}

/**
 * The fields a disclosure shows, per entry, sorted, each named as an answer declares it: by its top-level pointer,
 * so a list field's leaves (`/payloads/0`, `/payloads/1`) are the one field `/payloads`.
 */
export function shownFieldsV1(disclosure: RecordDisclosure): Map<number, string[]> {
  const out = new Map<number, string[]>();
  const top = (pointer: string) => `/${pointer.split('/')[1] ?? ''}`;
  for (const e of disclosure.entries as Array<{ seq: number; revealed?: Array<{ pointer: string }>; recordContent?: Record<string, unknown> }>) {
    const pointers = e.revealed ? e.revealed.map((l) => top(l.pointer)) : Object.keys(e.recordContent ?? {}).map((k) => `/${k}`);
    out.set(e.seq, [...new Set(pointers)].sort());
  }
  return out;
}

/**
 * Whether the entry shows exactly the declared fields (D-22): "This answer shows fields it did not declare." otherwise.
 * An answer declares field names (`/tags`) while an array field shows one leaf per element (`/tags/0`), so each shown
 * pointer is read as its field's name.
 */
export function shownFieldsMatchV1(disclosure: RecordDisclosure, seq: number, declared: readonly string[]): boolean {
  const pointers = shownFieldsV1(disclosure).get(seq);
  const shown = pointers && [...new Set(pointers.map((p) => `/${p.split('/')[1] ?? ''}`))].sort();
  const want = [...new Set(declared)].sort();
  return !!shown && shown.length === want.length && shown.every((p, i) => p === want[i]);
}

/** SHA-256 of an envelope's text, 64 lowercase hex: what a manifest commits for each disclosure. */
export async function disclosureDigestV1(envelope: string): Promise<string> {
  return hex(await sha256(utf8(envelope)));
}

// ------------------------------------------------------------------ sealed-note/v1

export interface SealedNoteV1 {
  schema: typeof SEALED_NOTE_SCHEMA_V1;
  iv: string;
  ct: string;
}

const NOTE_MEMBERS = ['schema', 'iv', 'ct'];

/** The keyless checks: exactly the three members, a 12-byte IV, and a ciphertext with its tag, all canonical base64url. */
export function readSealedNoteShapeV1(value: unknown): { ok: true; iv: Uint8Array; ct: Uint8Array } | { ok: false; code: 'SEALED_NOTE_MALFORMED' } {
  const bad = { ok: false as const, code: 'SEALED_NOTE_MALFORMED' as const };
  if (!value || typeof value !== 'object' || Array.isArray(value)) return bad;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).length !== NOTE_MEMBERS.length || !NOTE_MEMBERS.every((k) => Object.prototype.hasOwnProperty.call(v, k))) return bad;
  if (v.schema !== SEALED_NOTE_SCHEMA_V1 || typeof v.iv !== 'string' || typeof v.ct !== 'string' || v.ct.length > SEALED_NOTE_MAX_CHARS_V1) return bad;
  const iv = fromBase64Url(v.iv);
  const ct = fromBase64Url(v.ct);
  if (!iv || iv.length !== 12 || toBase64Url(iv) !== v.iv || !ct || ct.length <= 16 || toBase64Url(ct) !== v.ct) return bad;
  return { ok: true, iv, ct };
}

async function noteCipher(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const { subtle } = await platformCrypto();
  return subtle.importKey('raw', Uint8Array.from(key), { name: 'AES-GCM' }, false, [usage]);
}

/**
 * @internal Seals under a given key and IV: the published vectors, and an acknowledgment's flag notes, which share
 * one fresh key with a random IV each (`sealAckFlagNotesV1`). Any other note takes `sealNoteV1`.
 */
export async function sealNoteWithV1(text: string, name: NoteNameV1, key: Uint8Array, iv: Uint8Array): Promise<SealedNoteV1> {
  assertKey(key);
  if (typeof text !== 'string' || !(iv instanceof Uint8Array) || iv.length !== 12) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  const aad = utf8(noteAdditionalDataV1(name)) as BufferSource;
  const { subtle } = await platformCrypto();
  const ct = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: Uint8Array.from(iv), additionalData: aad, tagLength: 128 }, await noteCipher(key, 'encrypt'), utf8(text) as BufferSource),
  );
  const note: SealedNoteV1 = { schema: SEALED_NOTE_SCHEMA_V1, iv: toBase64Url(iv), ct: toBase64Url(ct) };
  if (note.ct.length > SEALED_NOTE_MAX_CHARS_V1) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  return note;
}

/** A note sealed under a fresh 32-byte key and a random IV; the caller wraps `key` and then lets it go. */
export async function sealNoteV1(text: string, name: NoteNameV1): Promise<{ note: SealedNoteV1; key: Uint8Array }> {
  const key = randomBytes(LINK_KEY_BYTES_V1);
  return { note: await sealNoteWithV1(text, name, key, randomBytes(12)), key };
}

/** Opens a note under its own name; any other scope, kind, reference or number fails. Never throws. */
export async function openNoteV1(input: { note: unknown; key: Uint8Array; name: NoteNameV1 }): Promise<{ ok: true; text: string } | { ok: false; code: 'SEALED_NOTE_MALFORMED' | 'SEALED_NOTE_AUTH_FAILED' }> {
  const shape = readSealedNoteShapeV1(input?.note);
  if (!shape.ok) return shape;
  try {
    assertKey(input.key);
    const aad = utf8(noteAdditionalDataV1(input.name)) as BufferSource;
    const { subtle } = await platformCrypto();
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: shape.iv as BufferSource, additionalData: aad, tagLength: 128 }, await noteCipher(input.key, 'decrypt'), shape.ct as BufferSource);
    return { ok: true, text: new TextDecoder('utf-8', { fatal: true }).decode(plain) };
  } catch {
    return { ok: false, code: 'SEALED_NOTE_AUTH_FAILED' };
  }
}

/** SHA-256 of a note's JCS, 64 lowercase hex: what an answer's manifest commits for its reply. */
export async function sealedNoteDigestV1(note: SealedNoteV1): Promise<string> {
  return hex(await sha256(utf8(canonicalizeJcs(note))));
}

// ------------------------------------------------------------------ pacspace-sample/v1 (D-14)

/** The seed as the draw reads it: 32 bytes from `crypto.getRandomValues`, as 64 lowercase hex. */
export function newSampleSeedV1(): string {
  return hex(randomBytes(32));
}

/**
 * The draw: each call takes the next k, from 0, and reads the first 4 bytes of `SHA-256("<seed>:<k>")` as an
 * unsigned big-endian integer, drawing again at or above the largest multiple of `size` below 2^32; otherwise its
 * remainder by `size`. `rejected` lists every k drawn again.
 */
export function sampleDrawerV1(seed: string): { next(size: number): Promise<number>; rejected: number[] } {
  check(typeof seed === 'string' && SAMPLE_SEED_HEX_V1.test(seed));
  let k = 0;
  const rejected: number[] = [];
  return {
    rejected,
    async next(size: number) {
      check(Number.isSafeInteger(size) && size >= 1 && size <= 0x1_0000_0000);
      const limit = Math.floor(0x1_0000_0000 / size) * size;
      for (;;) {
        const at = k;
        k += 1;
        const h = await sha256(utf8(`${seed}:${at}`));
        const x = ((h[0] << 24) >>> 0) + (h[1] << 16) + (h[2] << 8) + h[3];
        if (x < limit) return x % size;
        rejected.push(at);
      }
    },
  };
}

export type SampleSpreadV1 = 'any' | 'records' | 'days';

export interface SamplePoolRecordV1 {
  /** The member's number on the link. */
  number: number;
  /** How many entries it has: seqs 0 to entries - 1. */
  entries: number;
  /** The day it opened, `YYYY-MM-DD` (UTC), which a spread across days groups by. */
  openedOn: string;
}

export interface SamplePickV1 {
  number: number;
  seq: number;
}

const pickKey = (p: SamplePickV1) => `${p.number}:${p.seq}`;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

/** The pool in its committed order, record by record and entry by entry, less what was left out. */
export function samplePoolV1(records: readonly SamplePoolRecordV1[], leftOut: readonly SamplePickV1[]): Array<SamplePickV1 & { openedOn: string }> {
  const skip = new Set(leftOut.map(pickKey));
  const out: Array<SamplePickV1 & { openedOn: string }> = [];
  for (const r of records) {
    check(isEpoch(r?.number) && isNatural(r.entries) && typeof r.openedOn === 'string' && DAY.test(r.openedOn));
    for (let seq = 0; seq < r.entries; seq += 1) if (!skip.has(`${r.number}:${seq}`)) out.push({ number: r.number, seq, openedOn: r.openedOn });
  }
  return out;
}

/** SHA-256 of the JCS of the pool's records as `[number, entries, openedOn]`, 64 lowercase hex. */
export async function samplePoolDigestV1(records: readonly SamplePoolRecordV1[]): Promise<string> {
  return hex(await sha256(utf8(canonicalizeJcs(records.map((r) => [r.number, r.entries, r.openedOn])))));
}

/**
 * The picks a seed gives (`pacspace-sample/v1`), the same in every browser, the API and the checker: with no
 * spread, draw from what is left, each pick leaving the pool; with a spread, put the groups (in the order the pool
 * first meets them) in order by the same draws from the last down, then take one pick from each group in turn.
 */
export async function drawSampleV1(input: {
  seed: string;
  records: readonly SamplePoolRecordV1[];
  leftOut: readonly SamplePickV1[];
  n: number;
  spread: SampleSpreadV1;
}): Promise<SamplePickV1[]> {
  check(isNatural(input.n) && (input.spread === 'any' || input.spread === 'records' || input.spread === 'days'));
  const draw = sampleDrawerV1(input.seed);
  const left = samplePoolV1(input.records, input.leftOut);
  const out: SamplePickV1[] = [];
  const take = (from: Array<SamplePickV1 & { openedOn: string }>, i: number) => {
    const [p] = from.splice(i, 1);
    out.push({ number: p.number, seq: p.seq });
  };
  if (input.spread === 'any') {
    while (out.length < input.n && left.length) take(left, await draw.next(left.length));
    return out;
  }
  const groups = new Map<string, Array<SamplePickV1 & { openedOn: string }>>();
  const order: string[] = [];
  for (const p of left) {
    const g = input.spread === 'records' ? String(p.number) : p.openedOn;
    if (!groups.has(g)) {
      groups.set(g, []);
      order.push(g);
    }
    groups.get(g)!.push(p);
  }
  for (let i = order.length - 1; i > 0; i -= 1) {
    const j = await draw.next(i + 1);
    [order[i], order[j]] = [order[j], order[i]];
  }
  let turn = order;
  while (out.length < input.n && turn.length) {
    turn = turn.filter((g) => groups.get(g)!.length);
    for (const g of turn) {
      if (out.length >= input.n) break;
      const group = groups.get(g)!;
      take(group, await draw.next(group.length));
    }
  }
  return out;
}

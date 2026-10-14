import { canonicalizeJcs } from '../proof/jcs';
import { base64UrlLength, fromBase64Url, toBase64Url } from './base64url';
import { concatBytes, hmacSha256, isHex32, platformCrypto, randomBytes, sha256, utf8 } from './platform-crypto';

/**
 * Level 2's symmetric layer (ADR 0015 sections 5 and 7, and its formats
 * note, N1 to N6): the workspace secret's derivations, wire ids, the content
 * tag, the entry envelope and its padding, the size caps, the outside-copy
 * check and the keyring file. WebCrypto only, through platformCrypto.
 *
 * No key's bytes are ever printed: every key type keeps them in a module
 * WeakMap, so `JSON.stringify`, `inspect` and `toString` see the version and
 * the id only. Refusals carry a code and no sentence; nothing here logs.
 */
export const RECORDS_ENCRYPTION_LABELS_V1 = {
  idKey: 'pacspace:id-key:v1',
  recordsKey: 'pacspace:records-key:v1',
  wrapKey: 'pacspace:wrap-key:v1',
  recordKey: 'pacspace:record-key:v1',
  recordsKeyId: 'pacspace:records-key-id:v1',
  wrapKeyId: 'pacspace:wrap-key-id:v1',
  recordKeyId: 'pacspace:record-key-id:v1',
  recordId: 'pacspace:record-id:v1',
  referenceId: 'pacspace:reference-id:v1',
  contentTag: 'pacspace:content-tag:v1',
  entry: 'pacspace:record-entry:v1',
} as const;

export const RECORDS_ENCRYPTION_PAD_BLOCK_V1 = 256;
export const RECORD_ENTRY_PLAINTEXT_MAX_BYTES_V1 = 47104;
export const RECORD_ENTRY_CIPHERTEXT_MAX_BYTES_V1 = RECORD_ENTRY_PLAINTEXT_MAX_BYTES_V1 + 16;
export const RECORD_ENTRY_CIPHERTEXT_MAX_CHARS_V1 = base64UrlLength(RECORD_ENTRY_CIPHERTEXT_MAX_BYTES_V1);
export const RECORD_ENTRY_BODY_MAX_BYTES_V1 = 65536;
export const RECORDS_KEYRING_MAX_BYTES_V1 = 65536;
export const RECORDS_KEYRING_SCHEMA_V1 = 'pacspace-workspace-secret/v1';
export const WORKSPACE_SECRET_BYTES_V1 = 32;

export type RecordsEncryptionCodeV1 =
  | 'RECORDS_KEY_INVALID'
  | 'RECORDS_KEYRING_MALFORMED'
  | 'RECORDS_KEYRING_TOO_LARGE'
  | 'RECORD_ENTRY_MALFORMED'
  | 'RECORD_ENTRY_TOO_LARGE'
  | 'RECORD_ENTRY_BODY_TOO_LARGE'
  | 'RECORD_ENTRY_REFS_MISMATCH'
  | 'RECORD_ENTRY_HASH_MISMATCH'
  | 'RECORD_ENVELOPE_MALFORMED'
  | 'RECORD_ENVELOPE_TOO_LARGE'
  | 'RECORD_ENVELOPE_WRONG_KEY'
  | 'RECORD_ENVELOPE_AUTH_FAILED'
  | 'RECORD_ENVELOPE_PADDING';

/** Thrown by the writing side only; its message is the code. */
export class RecordsEncryptionError extends Error {
  constructor(readonly code: RecordsEncryptionCodeV1) {
    super(code);
    this.name = 'RecordsEncryptionError';
  }
}

export type RecordsRefusalV1<C extends string = RecordsEncryptionCodeV1> = { ok: false; code: C };
const refuse = <C extends string>(code: C): RecordsRefusalV1<C> => ({ ok: false, code });

const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const SPACE = 0x20;
const SEP = new Uint8Array([0]);
const HEX64 = /^[0-9a-f]{64}$/;
const WIRE_ID = /^[A-Za-z0-9_-]{22}$/;
const L = RECORDS_ENCRYPTION_LABELS_V1;
const INSPECT = Symbol.for('nodejs.util.inspect.custom');

// ------------------------------------------------------------------ key types

const KEY_BYTES_OF = new WeakMap<object, Uint8Array>();
/** Only this module makes keys, so a key's id is always the one its bytes derive. */
const MINT: unique symbol = Symbol('records key');
type Mint = typeof MINT;

abstract class HiddenKey {
  protected constructor(mint: Mint, bytes: Uint8Array) {
    if (mint !== MINT) throw new TypeError('records keys are made by their derive and import functions');
    KEY_BYTES_OF.set(this, Uint8Array.from(bytes));
  }
  protected abstract describe(): string;
  toString(): string {
    return this.describe();
  }
  toJSON(): string {
    return this.describe();
  }
  [INSPECT](): string {
    return this.describe();
  }
}

/** The id key, from version 1 of the workspace secret only (wire ids never change across rotations). */
export class RecordsIdKeyV1 extends HiddenKey {
  /** @internal */
  constructor(mint: Mint, bytes: Uint8Array) {
    super(mint, bytes);
  }
  protected describe(): string {
    return '[records id key]';
  }
}

/** `K_v`: reads every record made under version `version`. */
export class RecordsKeyV1 extends HiddenKey {
  /** @internal */
  constructor(mint: Mint, bytes: Uint8Array, readonly version: number, readonly id: string) {
    super(mint, bytes);
  }
  protected describe(): string {
    return `[records key v${this.version} ${this.id.slice(0, 8)}]`;
  }
}

/** `W_v`: wraps the workspace's private seed for storage at PacSpace (L2a2). */
export class RecordsWrapKeyV1 extends HiddenKey {
  /** @internal */
  constructor(mint: Mint, bytes: Uint8Array, readonly version: number, readonly id: string) {
    super(mint, bytes);
  }
  protected describe(): string {
    return `[wrap key v${this.version} ${this.id.slice(0, 8)}]`;
  }
}

/**
 * `RK`: opens one record's envelopes and no other. `recordsKeyId` is the id
 * of the `K_v` that made it, or null for a key that arrived on its own (a
 * copy file, a grant, a record-scope holder).
 */
export class RecordKeyV1 extends HiddenKey {
  /** @internal */
  constructor(mint: Mint, bytes: Uint8Array, readonly id: string, readonly recordsKeyId: string | null) {
    super(mint, bytes);
  }
  protected describe(): string {
    return `[record key ${this.id.slice(0, 8)}]`;
  }
}

type AnyKey = RecordsIdKeyV1 | RecordsKeyV1 | RecordsWrapKeyV1 | RecordKeyV1;

function bytesOf(key: AnyKey): Uint8Array {
  const bytes = KEY_BYTES_OF.get(key);
  if (!bytes) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return bytes;
}

/**
 * A key's raw bytes, for the three places they may leave the key layer: a
 * copy file (`RK`), a wrap to a holder (L2a2), and the published vectors.
 */
export function exportKeyBytesV1(key: AnyKey): Uint8Array {
  return Uint8Array.from(bytesOf(key));
}

// ------------------------------------------------------------------ derivations (N3)

async function hkdf32(ikm: Uint8Array, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const { subtle } = await platformCrypto();
  const base = await subtle.importKey('raw', Uint8Array.from(ikm), 'HKDF', false, ['deriveBits']);
  return hkdf32From(base, salt, info);
}

async function hkdf32From(base: CryptoKey, salt: Uint8Array, info: string): Promise<Uint8Array> {
  const { subtle } = await platformCrypto();
  const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: Uint8Array.from(salt), info: utf8(info) as BufferSource }, base, KEY_BYTES * 8);
  return new Uint8Array(bits);
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const keyIdOf = async (label: string, key: Uint8Array) => hex(await sha256(concatBytes(utf8(label), SEP, key)));

function assertSecret(secret: Uint8Array, version: number): void {
  if (!(secret instanceof Uint8Array) || secret.length !== WORKSPACE_SECRET_BYTES_V1 || !Number.isSafeInteger(version) || version < 1) {
    throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
}

/** 32 fresh random bytes: a new workspace secret. It is the customer's; it never reaches PacSpace. */
export function generateWorkspaceSecretV1(): Uint8Array {
  return randomBytes(WORKSPACE_SECRET_BYTES_V1);
}

/** The id key, from version 1 of the workspace secret. */
export async function deriveRecordsIdKeyV1(secretV1: Uint8Array): Promise<RecordsIdKeyV1> {
  assertSecret(secretV1, 1);
  return new RecordsIdKeyV1(MINT, await hkdf32(secretV1, new Uint8Array(0), L.idKey));
}

/** `K_v` and `W_v` of one version, with their ids. */
export async function deriveRecordsKeysV1(secret: Uint8Array, version: number): Promise<{ recordsKey: RecordsKeyV1; wrapKey: RecordsWrapKeyV1 }> {
  assertSecret(secret, version);
  const k = await hkdf32(secret, new Uint8Array(0), L.recordsKey);
  const w = await hkdf32(secret, new Uint8Array(0), L.wrapKey);
  return {
    recordsKey: new RecordsKeyV1(MINT, k, version, await keyIdOf(L.recordsKeyId, k)),
    wrapKey: new RecordsWrapKeyV1(MINT, w, version, await keyIdOf(L.wrapKeyId, w)),
  };
}

/**
 * One version of the workspace secret as a non-extractable HKDF key, for a
 * browser to store: no script can read the secret back out of it. Keys
 * derived from it are bytes in memory, as every derivation here needs.
 */
export async function importWorkspaceSecretKeyV1(secret: Uint8Array, version: number): Promise<CryptoKey> {
  assertSecret(secret, version);
  const { subtle } = await platformCrypto();
  return subtle.importKey('raw', Uint8Array.from(secret), 'HKDF', false, ['deriveBits']);
}

function assertBaseKey(base: CryptoKey): void {
  if (
    !base ||
    typeof base !== 'object' ||
    (base.algorithm as { name?: unknown } | undefined)?.name !== 'HKDF' ||
    base.extractable !== false ||
    !base.usages.includes('deriveBits')
  ) {
    throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
}

/** The id key, from version 1's stored key (`importWorkspaceSecretKeyV1`). */
export async function deriveRecordsIdKeyFromBaseV1(baseV1: CryptoKey): Promise<RecordsIdKeyV1> {
  assertBaseKey(baseV1);
  return new RecordsIdKeyV1(MINT, await hkdf32From(baseV1, new Uint8Array(0), L.idKey));
}

/** `K_v` and `W_v` of one version, from its stored key. */
export async function deriveRecordsKeysFromBaseV1(base: CryptoKey, version: number): Promise<{ recordsKey: RecordsKeyV1; wrapKey: RecordsWrapKeyV1 }> {
  assertBaseKey(base);
  if (!Number.isSafeInteger(version) || version < 1) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  const k = await hkdf32From(base, new Uint8Array(0), L.recordsKey);
  const w = await hkdf32From(base, new Uint8Array(0), L.wrapKey);
  return {
    recordsKey: new RecordsKeyV1(MINT, k, version, await keyIdOf(L.recordsKeyId, k)),
    wrapKey: new RecordsWrapKeyV1(MINT, w, version, await keyIdOf(L.wrapKeyId, w)),
  };
}

/** `RK` for one record: HKDF of `K_v` salted with the wire record id. */
export async function recordKeyOfV1(recordsKey: RecordsKeyV1, wireRecordId: string): Promise<RecordKeyV1> {
  if (!(recordsKey instanceof RecordsKeyV1) || !WIRE_ID.test(wireRecordId)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  const rk = await hkdf32(bytesOf(recordsKey), utf8(wireRecordId), L.recordKey);
  return new RecordKeyV1(MINT, rk, await keyIdOf(L.recordKeyId, rk), recordsKey.id);
}

/** `K_v` that arrived in a wrap: 32 bytes, its id recomputed from them. */
export async function recordsKeyFromBytesV1(bytes: Uint8Array, version: number): Promise<RecordsKeyV1> {
  if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_BYTES || !Number.isSafeInteger(version) || version < 1) {
    throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
  return new RecordsKeyV1(MINT, bytes, version, await keyIdOf(L.recordsKeyId, bytes));
}

/**
 * A record key that arrived on its own (a copy file, a grant): 32 bytes.
 * `recordsKeyId` is given only by a caller that made the key from that
 * `K_v` itself, so a verifier can tell which envelopes it must open.
 */
export async function recordKeyFromBytesV1(bytes: Uint8Array, recordsKeyId: string | null = null): Promise<RecordKeyV1> {
  if (!(bytes instanceof Uint8Array) || bytes.length !== KEY_BYTES) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  if (recordsKeyId !== null && !/^[0-9a-f]{64}$/.test(recordsKeyId)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return new RecordKeyV1(MINT, bytes, await keyIdOf(L.recordKeyId, bytes), recordsKeyId);
}

// ------------------------------------------------------------------ wire ids and the content tag (N4)

const wire16 = async (idKey: RecordsIdKeyV1, message: Uint8Array) => toBase64Url((await hmacSha256(bytesOf(idKey), message)).subarray(0, 16));

/** The record's id on the wire: 22 characters, the same across key rotations. */
export async function wireRecordIdV1(idKey: RecordsIdKeyV1, recordType: string, entityId: string): Promise<string> {
  return wire16(idKey, concatBytes(utf8(L.recordId), SEP, utf8(recordType), SEP, utf8(entityId)));
}

/** The caller's reference on the wire: 22 characters, scoped like today's reference. */
export async function wireReferenceIdV1(idKey: RecordsIdKeyV1, referenceId: string): Promise<string> {
  return wire16(idKey, concatBytes(utf8(L.referenceId), SEP, utf8(referenceId)));
}

/** The keyed tag of an entry's content and lifecycle; the default caller reference. 43 characters. */
export async function contentTagV1(
  idKey: RecordsIdKeyV1,
  input: { recordType: string; wireRecordId: string; content: Record<string, unknown>; lifecycle: string },
): Promise<string> {
  const message = concatBytes(
    utf8(L.contentTag), SEP, utf8(input.recordType), SEP, utf8(input.wireRecordId), SEP,
    utf8(canonicalizeJcs({ content: input.content, lifecycle: input.lifecycle })),
  );
  return toBase64Url(await hmacSha256(bytesOf(idKey), message));
}

// ------------------------------------------------------------------ the envelope (N5, N6)

export interface RecordEntryEnvelopeV1 {
  v: 1;
  alg: 'A256GCM';
  kid: string;
  iv: string;
  ct: string;
}

/**
 * `UTF-8(JCS({ content, saltKey }))`; throws RECORD_ENTRY_MALFORMED unless the
 * content is an object and the salt key 0x-prefixed 32-byte hex, and
 * RECORD_ENTRY_TOO_LARGE past the cap.
 */
export function recordEntryPlaintextV1(content: Record<string, unknown>, saltKey: string): Uint8Array {
  if (!content || typeof content !== 'object' || Array.isArray(content) || !isHex32(saltKey)) {
    throw new RecordsEncryptionError('RECORD_ENTRY_MALFORMED');
  }
  const p = utf8(canonicalizeJcs({ content, saltKey }));
  if (p.length > RECORD_ENTRY_PLAINTEXT_MAX_BYTES_V1) throw new RecordsEncryptionError('RECORD_ENTRY_TOO_LARGE');
  return p;
}

/** The plaintext with spaces to the next multiple of 256 bytes (none when it is one already). */
export function padRecordEntryV1(plaintext: Uint8Array): Uint8Array {
  const block = RECORDS_ENCRYPTION_PAD_BLOCK_V1;
  const out = new Uint8Array(Math.ceil(plaintext.length / block) * block);
  out.set(plaintext);
  out.fill(SPACE, plaintext.length);
  return out;
}

const aadOf = (recordType: string, wireRecordId: string) =>
  concatBytes(utf8(L.entry), SEP, utf8(recordType), SEP, utf8(wireRecordId)) as BufferSource;

async function aesKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const { subtle } = await platformCrypto();
  return subtle.importKey('raw', Uint8Array.from(key), { name: 'AES-GCM' }, false, [usage]);
}

/** @internal Seals already padded bytes under a given IV; vectors and the seal below only. */
export async function sealPaddedEntryV1(input: {
  recordKey: RecordKeyV1;
  recordsKeyId: string;
  recordType: string;
  wireRecordId: string;
  padded: Uint8Array;
  iv: Uint8Array;
}): Promise<RecordEntryEnvelopeV1> {
  if (!HEX64.test(input.recordsKeyId) || !(input.iv instanceof Uint8Array) || input.iv.length !== IV_BYTES) {
    throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
  const { subtle } = await platformCrypto();
  const sealed = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: Uint8Array.from(input.iv), additionalData: aadOf(input.recordType, input.wireRecordId), tagLength: 128 },
      await aesKey(bytesOf(input.recordKey), 'encrypt'),
      Uint8Array.from(input.padded),
    ),
  );
  return { v: 1, alg: 'A256GCM', kid: input.recordsKeyId, iv: toBase64Url(input.iv), ct: toBase64Url(sealed) };
}

/** Seals one entry under its record key with a fresh IV. The record key must come from a `K_v` (it names it as `kid`). */
export async function sealRecordEntryV1(input: {
  recordKey: RecordKeyV1;
  recordType: string;
  wireRecordId: string;
  content: Record<string, unknown>;
  saltKey: string;
}): Promise<RecordEntryEnvelopeV1> {
  if (!(input.recordKey instanceof RecordKeyV1) || input.recordKey.recordsKeyId === null) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return sealPaddedEntryV1({
    recordKey: input.recordKey,
    recordsKeyId: input.recordKey.recordsKeyId,
    recordType: input.recordType,
    wireRecordId: input.wireRecordId,
    padded: padRecordEntryV1(recordEntryPlaintextV1(input.content, input.saltKey)),
    iv: randomBytes(IV_BYTES),
  });
}

/** The keyless checks every reader and intake run first. Never throws. */
export function readRecordEnvelopeShapeV1(
  envelope: unknown,
): { ok: true; kid: string; iv: Uint8Array; ct: Uint8Array } | RecordsRefusalV1<'RECORD_ENVELOPE_MALFORMED' | 'RECORD_ENVELOPE_TOO_LARGE'> {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) return refuse('RECORD_ENVELOPE_MALFORMED');
  const e = envelope as Record<string, unknown>;
  const keys = Object.keys(e).sort();
  if (keys.join(',') !== 'alg,ct,iv,kid,v') return refuse('RECORD_ENVELOPE_MALFORMED');
  if (e.v !== 1 || e.alg !== 'A256GCM' || typeof e.kid !== 'string' || !HEX64.test(e.kid)) return refuse('RECORD_ENVELOPE_MALFORMED');
  if (typeof e.ct !== 'string' || typeof e.iv !== 'string') return refuse('RECORD_ENVELOPE_MALFORMED');
  if (e.ct.length > RECORD_ENTRY_CIPHERTEXT_MAX_CHARS_V1) return refuse('RECORD_ENVELOPE_TOO_LARGE');
  const iv = fromBase64Url(e.iv);
  const ct = fromBase64Url(e.ct);
  if (!iv || iv.length !== IV_BYTES || !ct) return refuse('RECORD_ENVELOPE_MALFORMED');
  const body = ct.length - TAG_BYTES;
  if (body <= 0 || body % RECORDS_ENCRYPTION_PAD_BLOCK_V1 !== 0) return refuse('RECORD_ENVELOPE_MALFORMED');
  return { ok: true, kid: e.kid, iv, ct };
}

export type OpenRecordEntryResultV1 =
  | { ok: true; content: Record<string, unknown>; saltKey: string; recordsKeyId: string | null }
  | RecordsRefusalV1<'RECORD_ENVELOPE_MALFORMED' | 'RECORD_ENVELOPE_TOO_LARGE' | 'RECORD_ENVELOPE_WRONG_KEY' | 'RECORD_ENVELOPE_AUTH_FAILED' | 'RECORD_ENVELOPE_PADDING'>;

/**
 * Opens one envelope with a record key, or with a keyring (whose `K_v`
 * named by `kid` makes the record key). Never throws.
 */
export async function openRecordEntryEnvelopeV1(input: {
  envelope: unknown;
  recordType: string;
  wireRecordId: string;
  recordKey?: RecordKeyV1;
  keyring?: RecordsKeyringV1;
}): Promise<OpenRecordEntryResultV1> {
  try {
    const shape = readRecordEnvelopeShapeV1(input?.envelope);
    if (!shape.ok) return shape;
    let rk = input.recordKey;
    if (input.keyring) {
      const k = input.keyring.byId(shape.kid);
      if (!k) return refuse('RECORD_ENVELOPE_WRONG_KEY');
      rk = await recordKeyOfV1(k, input.wireRecordId);
    }
    if (!(rk instanceof RecordKeyV1)) return refuse('RECORD_ENVELOPE_AUTH_FAILED');
    let plain: Uint8Array;
    try {
      const { subtle } = await platformCrypto();
      plain = new Uint8Array(
        await subtle.decrypt(
          { name: 'AES-GCM', iv: Uint8Array.from(shape.iv), additionalData: aadOf(input.recordType, input.wireRecordId), tagLength: 128 },
          await aesKey(bytesOf(rk), 'decrypt'),
          Uint8Array.from(shape.ct),
        ),
      );
    } catch {
      return refuse('RECORD_ENVELOPE_AUTH_FAILED');
    }
    let end = plain.length;
    while (end > 0 && plain[end - 1] === SPACE) end -= 1;
    if (plain.length - end >= RECORDS_ENCRYPTION_PAD_BLOCK_V1) return refuse('RECORD_ENVELOPE_PADDING');
    const trimmed = plain.subarray(0, end);
    const parsed: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(trimmed));
    const canonical = utf8(canonicalizeJcs(parsed));
    if (canonical.length !== trimmed.length || canonical.some((b, i) => b !== trimmed[i])) return refuse('RECORD_ENVELOPE_PADDING');
    const value = parsed as Record<string, unknown>;
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'content,saltKey') {
      return refuse('RECORD_ENVELOPE_PADDING');
    }
    const content = value.content;
    if (!content || typeof content !== 'object' || Array.isArray(content) || !isHex32(value.saltKey)) return refuse('RECORD_ENVELOPE_PADDING');
    return { ok: true, content: content as Record<string, unknown>, saltKey: value.saltKey as string, recordsKeyId: input.keyring ? shape.kid : rk.recordsKeyId };
  } catch {
    return refuse('RECORD_ENVELOPE_PADDING');
  }
}

// ------------------------------------------------------------------ the write body (N5)

/** The serialized length of an encrypted write's body, with the envelope at the length `plaintextBytes` gives it. */
export function encryptedWriteBodyBytesV1(body: Record<string, unknown>, recordsKeyId: string, plaintextBytes: number): number {
  const padded = Math.ceil(plaintextBytes / RECORDS_ENCRYPTION_PAD_BLOCK_V1) * RECORDS_ENCRYPTION_PAD_BLOCK_V1;
  const envelope = { v: 1, alg: 'A256GCM', kid: recordsKeyId, iv: 'A'.repeat(base64UrlLength(IV_BYTES)), ct: 'A'.repeat(base64UrlLength(padded + TAG_BYTES)) };
  return utf8(canonicalizeJcs({ ...body, envelope })).length;
}

/** Both caps, checked before encrypting. */
export function checkEncryptedWriteSizeV1(
  body: Record<string, unknown>,
  recordsKeyId: string,
  plaintextBytes: number,
): { ok: true; bodyBytes: number } | (RecordsRefusalV1<'RECORD_ENTRY_TOO_LARGE' | 'RECORD_ENTRY_BODY_TOO_LARGE'> & { bodyBytes: number | null }) {
  if (plaintextBytes > RECORD_ENTRY_PLAINTEXT_MAX_BYTES_V1) return { ...refuse('RECORD_ENTRY_TOO_LARGE'), bodyBytes: null };
  const bodyBytes = encryptedWriteBodyBytesV1(body, recordsKeyId, plaintextBytes);
  if (bodyBytes > RECORD_ENTRY_BODY_MAX_BYTES_V1) return { ...refuse('RECORD_ENTRY_BODY_TOO_LARGE'), bodyBytes };
  return { ok: true, bodyBytes };
}

// ------------------------------------------------------------------ the outside copies (N7)

const jcsOrNull = (value: unknown) => (value === undefined ? null : canonicalizeJcs(value));

/** `amends` and `references` inside the content equal the copies outside the envelope (both absent is equal). */
export function entryRefsMatchV1(
  content: Record<string, unknown>,
  outside: { amends?: unknown; references?: unknown },
): { ok: true } | RecordsRefusalV1<'RECORD_ENTRY_REFS_MISMATCH'> {
  try {
    for (const member of ['amends', 'references'] as const) {
      if (jcsOrNull(content?.[member]) !== jcsOrNull(outside?.[member])) return refuse('RECORD_ENTRY_REFS_MISMATCH');
    }
    return { ok: true };
  } catch {
    return refuse('RECORD_ENTRY_REFS_MISMATCH');
  }
}

// ------------------------------------------------------------------ the keyring (N2) and the key interface

/**
 * Where the SDKs get the workspace secret. The local provider holds it in
 * memory; a customer's provider can answer from a KMS or HSM.
 */
export interface RecordsKeyProviderV1 {
  /** Every version held, ascending from 1 with no gaps. */
  versions(): Promise<number[]>;
  /** The 32-byte secret of one version. */
  secret(version: number): Promise<Uint8Array>;
}

/** A provider over stored keys (`importWorkspaceSecretKeyV1`), for a browser that keeps no secret bytes. */
export interface RecordsBaseKeyProviderV1 {
  /** Every version held, ascending from 1 with no gaps. */
  versions(): Promise<number[]>;
  /** The stored key of one version. */
  baseKey(version: number): Promise<CryptoKey>;
}

function assertVersions(versions: unknown): void {
  if (!Array.isArray(versions) || versions.length === 0 || versions.some((v, i) => v !== i + 1)) {
    throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
}

/** Every version of a workspace's keys, made once from a provider. */
export class RecordsKeyringV1 {
  readonly #byId = new Map<string, RecordsKeyV1>();
  readonly #byVersion = new Map<number, RecordsKeyV1>();
  readonly #wrap = new Map<number, RecordsWrapKeyV1>();

  private constructor(readonly idKey: RecordsIdKeyV1) {}

  static async fromProvider(provider: RecordsKeyProviderV1): Promise<RecordsKeyringV1> {
    const versions = await provider.versions();
    assertVersions(versions);
    const ring = new RecordsKeyringV1(await deriveRecordsIdKeyV1(await provider.secret(1)));
    for (const version of versions) ring.#add(await deriveRecordsKeysV1(await provider.secret(version), version));
    return ring;
  }

  /** The same keyring, from stored keys: the same derivations, no secret bytes. */
  static async fromBaseKeys(provider: RecordsBaseKeyProviderV1): Promise<RecordsKeyringV1> {
    const versions = await provider.versions();
    assertVersions(versions);
    const ring = new RecordsKeyringV1(await deriveRecordsIdKeyFromBaseV1(await provider.baseKey(1)));
    for (const version of versions) ring.#add(await deriveRecordsKeysFromBaseV1(await provider.baseKey(version), version));
    return ring;
  }

  #add({ recordsKey, wrapKey }: { recordsKey: RecordsKeyV1; wrapKey: RecordsWrapKeyV1 }): void {
    this.#byId.set(recordsKey.id, recordsKey);
    this.#byVersion.set(recordsKey.version, recordsKey);
    this.#wrap.set(wrapKey.version, wrapKey);
  }

  /** The newest version: new records are made under it. */
  get current(): RecordsKeyV1 {
    return this.#byVersion.get(this.#byVersion.size) as RecordsKeyV1;
  }

  get versions(): number[] {
    return [...this.#byVersion.keys()];
  }

  byId(id: string): RecordsKeyV1 | null {
    return this.#byId.get(id) ?? null;
  }

  byVersion(version: number): RecordsKeyV1 | null {
    return this.#byVersion.get(version) ?? null;
  }

  wrapKey(version: number): RecordsWrapKeyV1 | null {
    return this.#wrap.get(version) ?? null;
  }

  toString(): string {
    return `[records keyring v1..v${this.#byVersion.size}]`;
  }

  toJSON(): string {
    return this.toString();
  }

  [INSPECT](): string {
    return this.toString();
  }
}

/** A provider over secrets held in memory: a keyring file's text, or the secrets themselves. */
export function localRecordsKeyProviderV1(source: string | ReadonlyArray<{ version: number; secret: Uint8Array }>): RecordsKeyProviderV1 {
  let secrets: Array<{ version: number; secret: Uint8Array }>;
  if (typeof source === 'string') {
    const parsed = parseRecordsKeyringFileV1(source);
    if (!parsed.ok) throw new RecordsEncryptionError(parsed.code);
    secrets = parsed.secrets;
  } else {
    secrets = source.map((s) => ({ version: s.version, secret: Uint8Array.from(s.secret) }));
    if (!secretsAreAKeyring(secrets)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  }
  const held = new Map(secrets.map((s) => [s.version, s.secret]));
  const provider: RecordsKeyProviderV1 & { toString(): string; toJSON(): string } = {
    versions: async () => [...held.keys()],
    secret: async (version: number) => {
      const s = held.get(version);
      if (!s) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
      return Uint8Array.from(s);
    },
    toString: () => `[local records key provider v1..v${held.size}]`,
    toJSON: () => `[local records key provider v1..v${held.size}]`,
  };
  Object.defineProperty(provider, INSPECT, { value: () => provider.toString() });
  return provider;
}

function secretsAreAKeyring(secrets: ReadonlyArray<{ version: unknown; secret: unknown }>): boolean {
  return (
    secrets.length > 0 &&
    secrets.every((s, i) => s.version === i + 1 && s.secret instanceof Uint8Array && s.secret.length === WORKSPACE_SECRET_BYTES_V1)
  );
}

/** The keyring file's text, as JCS. */
export function serializeRecordsKeyringFileV1(secrets: ReadonlyArray<{ version: number; secret: Uint8Array }>): string {
  if (!secretsAreAKeyring(secrets)) throw new RecordsEncryptionError('RECORDS_KEY_INVALID');
  return canonicalizeJcs({
    schema: RECORDS_KEYRING_SCHEMA_V1,
    secrets: secrets.map((s) => ({ version: s.version, secret: toBase64Url(s.secret) })),
  });
}

/** Reads a keyring file: any JSON of the shape, up to 65,536 bytes. Never throws. */
export function parseRecordsKeyringFileV1(
  text: string,
): { ok: true; secrets: Array<{ version: number; secret: Uint8Array }> } | RecordsRefusalV1<'RECORDS_KEYRING_MALFORMED' | 'RECORDS_KEYRING_TOO_LARGE'> {
  if (typeof text !== 'string') return refuse('RECORDS_KEYRING_MALFORMED');
  if (utf8(text).length > RECORDS_KEYRING_MAX_BYTES_V1) return refuse('RECORDS_KEYRING_TOO_LARGE');
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    return refuse('RECORDS_KEYRING_MALFORMED');
  }
  const d = doc as Record<string, unknown>;
  if (!d || typeof d !== 'object' || Array.isArray(d) || Object.keys(d).sort().join(',') !== 'schema,secrets') return refuse('RECORDS_KEYRING_MALFORMED');
  if (d.schema !== RECORDS_KEYRING_SCHEMA_V1 || !Array.isArray(d.secrets)) return refuse('RECORDS_KEYRING_MALFORMED');
  const secrets: Array<{ version: number; secret: Uint8Array }> = [];
  for (const item of d.secrets as unknown[]) {
    const s = item as Record<string, unknown>;
    if (!s || typeof s !== 'object' || Array.isArray(s) || Object.keys(s).sort().join(',') !== 'secret,version') return refuse('RECORDS_KEYRING_MALFORMED');
    const bytes = typeof s.secret === 'string' ? fromBase64Url(s.secret) : null;
    if (!Number.isSafeInteger(s.version) || !bytes) return refuse('RECORDS_KEYRING_MALFORMED');
    secrets.push({ version: s.version as number, secret: bytes });
  }
  if (!secretsAreAKeyring(secrets)) return refuse('RECORDS_KEYRING_MALFORMED');
  return { ok: true, secrets };
}

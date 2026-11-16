import { canonicalizeJcs } from '../proof/jcs';
import { RecordIntakeError } from '../proof/layout-document-v1';
import { concatBytes, fromHex32, hmacSha256, isHex32, randomBytes, sha256, toHex0x, utf8 } from './platform-crypto';

/**
 * Record hash v2 (ADR 0016; docs/spec/records/record-hash-v2.md): each
 * top-level member of an entry's content, and each element of a top-level
 * array, is one leaf with its own salt, and the record hash is SHA-256 over
 * the leaf count and the sorted leaf hashes. Everything after the record hash
 * (the opening, the seal, the word, the item hash) is slot-encoding-v1.
 */
export const RECORD_HASH_VERSION_V1 = 1 as const;
export const RECORD_HASH_VERSION_V2 = 2 as const;
export type RecordHashVersion = 1 | 2;
export const RECORD_LEAVES_MAX_V2 = 65535;

export interface RecordLeafV2 {
  pointer: string;
  value: unknown;
}
/** A leaf with its salt: `0x` plus 64 lowercase hex. */
export interface RevealedLeafV2 {
  pointer: string;
  value: unknown;
  salt: string;
}

const LABEL_SALT = 'pacspace:record-leaf-salt:v2';
const LABEL_LEAF = 'pacspace:record-leaf:v2';
const LABEL_RECORD = 'pacspace:record:v2';
const SEP = new Uint8Array([0]);

const TOO_MANY_LEAVES = 'This entry has more than 65535 fields and list items. Split it across entries.';
const NOT_CANONICAL = "This entry's sealed fields are not in their canonical form.";
/** The refusal for more leaves than a record hash can count (W-1). */
export const RECORD_LEAVES_TOO_MANY_V2 = TOO_MANY_LEAVES;
/** The refusal for content that has no canonical v2 form (W-2b). */
export const RECORD_CONTENT_NOT_CANONICAL_V2 = NOT_CANONICAL;

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const CANONICAL_INDEX = /^(0|[1-9][0-9]*)$/;
const FIRST_SEGMENT = /^(?:[^~]|~[01])*$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

/** True when a member name or string at any depth holds a lone UTF-16 surrogate. */
function hasLoneSurrogate(value: unknown): boolean {
  if (typeof value === 'string') return LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.some(hasLoneSurrogate);
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (LONE_SURROGATE.test(k) || hasLoneSurrogate(v)) return true;
    }
  }
  return false;
}

const escapeSegment = (key: string) => key.replace(/~/g, '~0').replace(/\//g, '~1');
const unescapeSegment = (segment: string) => segment.replace(/~1/g, '/').replace(/~0/g, '~');

/** UTF-16 code-unit order, the order JCS uses for member names. */
const byPointer = (a: { pointer: string }, b: { pointer: string }) => (a.pointer < b.pointer ? -1 : a.pointer > b.pointer ? 1 : 0);

/** A pointer's key and, for an array element, its index; null when not well-formed. */
/** A v2 pointer's member name and element index, or null when it is not a canonical v2 pointer. */
export function parsePointerV2(pointer: unknown): { key: string; index: number | null } | null {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || LONE_SURROGATE.test(pointer)) return null;
  const segments = pointer.slice(1).split('/');
  if (segments.length > 2 || !FIRST_SEGMENT.test(segments[0])) return null;
  if (segments.length === 1) return { key: unescapeSegment(segments[0]), index: null };
  if (!CANONICAL_INDEX.test(segments[1]) || segments[1].length > 5) return null;
  return { key: unescapeSegment(segments[0]), index: Number(segments[1]) };
}

/** Leaves of one content object, sorted by pointer. Throws RecordIntakeError RECORD_CONTENT_INVALID. */
export function recordLeavesV2(content: Record<string, unknown>): RecordLeafV2[] {
  if (!isPlainObject(content)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'content must be an object');
  if (hasLoneSurrogate(content)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', NOT_CANONICAL);
  const leaves: RecordLeafV2[] = [];
  for (const [key, value] of Object.entries(content)) {
    if (value === undefined) continue;
    const base = '/' + escapeSegment(key);
    if (Array.isArray(value) && value.length > 0) {
      if (leaves.length + value.length > RECORD_LEAVES_MAX_V2) throw new RecordIntakeError('RECORD_CONTENT_INVALID', TOO_MANY_LEAVES);
      value.forEach((element, i) => leaves.push({ pointer: `${base}/${i}`, value: element }));
    } else {
      leaves.push({ pointer: base, value });
    }
    if (leaves.length > RECORD_LEAVES_MAX_V2) throw new RecordIntakeError('RECORD_CONTENT_INVALID', TOO_MANY_LEAVES);
  }
  return leaves.sort(byPointer);
}

/** The content rebuilt from a canonical full leaf set, or null when the set is not canonical. */
export function recordContentFromLeavesV2(leaves: readonly RecordLeafV2[]): Record<string, unknown> | null {
  const whole = new Map<string, unknown>();
  const arrays = new Map<string, Map<number, unknown>>();
  for (const leaf of leaves) {
    const parsed = parsePointerV2(leaf?.pointer);
    if (!parsed || leaf.value === undefined) return null;
    if (parsed.index === null) {
      if (whole.has(parsed.key) || arrays.has(parsed.key)) return null;
      whole.set(parsed.key, leaf.value);
    } else {
      if (whole.has(parsed.key)) return null;
      const elements = arrays.get(parsed.key) ?? new Map<number, unknown>();
      if (elements.has(parsed.index)) return null;
      elements.set(parsed.index, leaf.value);
      arrays.set(parsed.key, elements);
    }
  }
  const content: Record<string, unknown> = {};
  for (const [key, value] of whole) content[key] = value;
  for (const [key, elements] of arrays) {
    const list: unknown[] = [];
    for (let i = 0; i < elements.size; i += 1) {
      if (!elements.has(i)) return null;
      list.push(elements.get(i));
    }
    content[key] = list;
  }
  let again: RecordLeafV2[];
  try {
    again = recordLeavesV2(content);
  } catch {
    return null;
  }
  const given = [...leaves].sort(byPointer);
  if (again.length !== given.length) return null;
  for (let i = 0; i < again.length; i += 1) {
    if (again[i].pointer !== given[i].pointer) return null;
    try {
      if (canonicalizeJcs(again[i].value) !== canonicalizeJcs(given[i].value)) return null;
    } catch {
      return null;
    }
  }
  return content;
}

/** 32 fresh random bytes, as `0x` plus 64 lowercase hex. */
export function newSaltKeyV2(): string {
  return toHex0x(randomBytes(32));
}

/**
 * Queue items with every `saltKey` removed (ADR 0016). An overflow payload,
 * a settled job and a log line never hold one; anything that is not an array
 * of objects is returned as it is.
 */
export function withoutSaltKeysV2<T>(records: T): T {
  if (!Array.isArray(records)) return records;
  return records.map((record) => {
    if (!record || typeof record !== 'object' || !('saltKey' in record)) return record;
    const { saltKey: _omit, ...rest } = record as Record<string, unknown>;
    return rest;
  }) as unknown as T;
}

/** True when any queue item carries a `saltKey` member. */
export function carriesSaltKeyV2(records: unknown): boolean {
  return Array.isArray(records) && records.some((r) => !!r && typeof r === 'object' && 'saltKey' in r);
}

export async function deriveLeafSaltV2(saltKey: string, pointer: string): Promise<string> {
  if (!isHex32(saltKey)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a salt key is 0x plus 64 lowercase hex');
  return toHex0x(await hmacSha256(fromHex32(saltKey), concatBytes(utf8(LABEL_SALT), SEP, utf8(pointer))));
}

export async function computeLeafHashV2(leaf: RevealedLeafV2): Promise<string> {
  if (!isHex32(leaf.salt)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a leaf salt is 0x plus 64 lowercase hex');
  const message = canonicalizeJcs([leaf.pointer, leaf.value]);
  return toHex0x(await sha256(concatBytes(utf8(LABEL_LEAF), SEP, fromHex32(leaf.salt), utf8(message))));
}

/** Takes leaf hashes in strictly ascending order (0x lowercase hex); throws otherwise. */
export async function computeRecordHashV2(leaves: readonly string[]): Promise<string> {
  if (!Array.isArray(leaves) || leaves.length > RECORD_LEAVES_MAX_V2) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a record hash takes 0 to 65535 leaves');
  }
  for (let i = 0; i < leaves.length; i += 1) {
    if (!isHex32(leaves[i]) || (i > 0 && !(leaves[i - 1] < leaves[i]))) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'leaf hashes must be 0x lowercase hex, strictly ascending');
    }
  }
  const count = new Uint8Array([(leaves.length >> 8) & 0xff, leaves.length & 0xff]);
  return toHex0x(await sha256(concatBytes(utf8(LABEL_RECORD), SEP, count, ...leaves.map(fromHex32))));
}

/** Everything a v2 entry needs: the record hash, every leaf hash (sorted), every leaf with its salt (by pointer). */
export async function commitRecordContentV2(
  content: Record<string, unknown>,
  saltKey: string,
): Promise<{ recordHash: string; leaves: string[]; revealed: RevealedLeafV2[] }> {
  const fields = recordLeavesV2(content);
  const revealed: RevealedLeafV2[] = [];
  const leaves: string[] = [];
  for (const field of fields) {
    const leaf = { pointer: field.pointer, value: field.value, salt: await deriveLeafSaltV2(saltKey, field.pointer) };
    revealed.push(leaf);
    leaves.push(await computeLeafHashV2(leaf));
  }
  leaves.sort();
  return { recordHash: await computeRecordHashV2(leaves), leaves, revealed };
}

export type OpenRecordEntryV2Result =
  | { ok: true; recordHash: string; fields: RecordLeafV2[]; withheld: number; content: Record<string, unknown> | null }
  | { ok: false; failure: 'malformed' | 'leaf-mismatch' | 'not-canonical'; reason: string };

const SHOWN_FIELD_MISMATCH = 'A shown field of this entry does not match the fields sealed for it.';
const MALFORMED = NOT_CANONICAL;

/** Opens an entry: every revealed leaf must recompute and appear in `leaves`. `every` requires all leaves revealed. */
export async function openRecordEntryV2(
  entry: { leaves: readonly string[]; revealed: readonly RevealedLeafV2[] },
  options: { every: boolean },
): Promise<OpenRecordEntryV2Result> {
  const malformed = { ok: false as const, failure: 'malformed' as const, reason: MALFORMED };
  const leaves = entry?.leaves;
  const revealed = entry?.revealed;
  if (!Array.isArray(leaves) || leaves.length > RECORD_LEAVES_MAX_V2 || !Array.isArray(revealed)) return malformed;
  for (let i = 0; i < leaves.length; i += 1) {
    if (!isHex32(leaves[i]) || (i > 0 && !(leaves[i - 1] < leaves[i]))) return malformed;
  }
  for (let i = 0; i < revealed.length; i += 1) {
    const leaf = revealed[i];
    if (!isPlainObject(leaf) || !parsePointerV2(leaf.pointer) || !isHex32(leaf.salt) || leaf.value === undefined) return malformed;
    if (i > 0 && !(revealed[i - 1].pointer < (leaf.pointer as string))) return malformed;
    if (hasLoneSurrogate(leaf.value)) return malformed;
    try {
      canonicalizeJcs(leaf.value);
    } catch {
      return malformed;
    }
  }
  const known = new Set(leaves);
  for (const leaf of revealed) {
    if (!known.has(await computeLeafHashV2(leaf))) return { ok: false, failure: 'leaf-mismatch', reason: SHOWN_FIELD_MISMATCH };
  }
  const fields = revealed.map((l) => ({ pointer: l.pointer, value: l.value }));
  const full = revealed.length === leaves.length;
  const content = full ? recordContentFromLeavesV2(fields) : null;
  if (options.every && (!full || content === null)) return { ok: false, failure: 'not-canonical', reason: NOT_CANONICAL };
  return { ok: true, recordHash: await computeRecordHashV2(leaves), fields, withheld: leaves.length - revealed.length, content };
}

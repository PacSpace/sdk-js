import { canonicalizeJcs } from '../proof/jcs';
import { RecordIntakeError } from '../proof/layout-document-v1';
import { concatBytes, fromHex32, hmacSha256, isHex32, sha256, toHex0x, utf8 } from './platform-crypto';
import { recordContentFromLeavesV2, recordLeavesV2, type RecordLeafV2, type RevealedLeafV2 } from './record-hash-v2';

/**
 * Record hash v3 (card 10, F1; docs/spec/records/record-hash-v3.md): members,
 * not pointers. Each leaf is committed as an item (memberTag, slot, leafHash):
 * the member tag names the top-level member, the slot is 0xFFFF for a whole
 * member or the element's index, and every group of items with one tag is
 * either one whole item or slots exactly 0..m-1. A member therefore has
 * exactly one committed value, which a partial disclosure cannot double.
 * Leaves are the same as v2's (recordLeavesV2); only the labels, the items
 * and the hash over them differ. The seal is over sealInputHash(3, hash).
 */
export const RECORD_HASH_VERSION_V3 = 3 as const;
export const RECORD_ITEMS_MAX_V3 = 65535;
export const RECORD_SLOT_WHOLE_V3 = 0xffff;
const ELEMENT_INDEX_MAX_V3 = 65534;

/** [memberTag, slot, leafHash]: tag and leaf hash `0x` plus 64 lowercase hex, slot an integer 0..65535. */
export type RecordItemV3 = [string, number, string];

const LABEL_MEMBER = 'pacspace:record-member:v3';
const LABEL_SALT = 'pacspace:record-leaf-salt:v3';
const LABEL_LEAF = 'pacspace:record-leaf:v3';
const LABEL_RECORD = 'pacspace:record:v3';
const SEP = new Uint8Array([0]);

const NOT_CANONICAL = "This entry's sealed fields are not in their canonical form.";
const SHOWN_FIELD_MISMATCH = 'A shown field of this entry does not match the fields sealed for it.';

const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const CANONICAL_INDEX = /^(0|[1-9][0-9]{0,4})$/;
const FIRST_SEGMENT = /^(?:[^~]|~[01])*$/;

const escapeSegment = (key: string) => key.replace(/~/g, '~0').replace(/\//g, '~1');
const unescapeSegment = (segment: string) => segment.replace(/~1/g, '/').replace(/~0/g, '~');

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) &&
  (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);

function hasLoneSurrogate(value: unknown): boolean {
  if (typeof value === 'string') return LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.some(hasLoneSurrogate);
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([k, v]) => LONE_SURROGATE.test(k) || hasLoneSurrogate(v));
  }
  return false;
}

/** A v3 pointer's member name and element index (at most 65534), or null. */
export function parsePointerV3(pointer: unknown): { key: string; index: number | null } | null {
  if (typeof pointer !== 'string' || !pointer.startsWith('/') || LONE_SURROGATE.test(pointer)) return null;
  const segments = pointer.slice(1).split('/');
  if (segments.length > 2 || !FIRST_SEGMENT.test(segments[0])) return null;
  if (segments.length === 1) return { key: unescapeSegment(segments[0]), index: null };
  if (!CANONICAL_INDEX.test(segments[1])) return null;
  const index = Number(segments[1]);
  if (index > ELEMENT_INDEX_MAX_V3) return null;
  return { key: unescapeSegment(segments[0]), index };
}

/** SHA-256("pacspace:record-member:v3" || 0x00 || UTF-8(escaped member name)); unsalted, so a partial reader can recompute it. */
export async function memberTagV3(key: string): Promise<string> {
  return toHex0x(await sha256(concatBytes(utf8(LABEL_MEMBER), SEP, utf8(escapeSegment(key)))));
}

export async function deriveLeafSaltV3(saltKey: string, pointer: string): Promise<string> {
  if (!isHex32(saltKey)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a salt key is 0x plus 64 lowercase hex');
  return toHex0x(await hmacSha256(fromHex32(saltKey), concatBytes(utf8(LABEL_SALT), SEP, utf8(pointer))));
}

export async function computeLeafHashV3(leaf: RevealedLeafV2): Promise<string> {
  if (!isHex32(leaf.salt)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a leaf salt is 0x plus 64 lowercase hex');
  const message = canonicalizeJcs([leaf.pointer, leaf.value]);
  return toHex0x(await sha256(concatBytes(utf8(LABEL_LEAF), SEP, fromHex32(leaf.salt), utf8(message))));
}

const isSlot = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= RECORD_SLOT_WHOLE_V3;

/** Bytewise order of the 34-byte (tag, u16be slot) prefix. Tags are same-length lowercase hex. */
const comparePrefix = (a: RecordItemV3, b: RecordItemV3) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] - b[1]);

/** True when the items are well formed, strictly ascending, and every group is one whole item or slots 0..m-1. */
export function validateRecordItemsV3(items: unknown): items is RecordItemV3[] {
  if (!Array.isArray(items) || items.length > RECORD_ITEMS_MAX_V3) return false;
  let groupTag: string | null = null;
  let groupWhole = false;
  let nextSlot = 0;
  for (let i = 0; i < items.length; i += 1) {
    const item = items[i];
    if (!Array.isArray(item) || item.length !== 3) return false;
    const [tag, slot, leafHash] = item;
    if (!isHex32(tag) || !isSlot(slot) || !isHex32(leafHash)) return false;
    if (i > 0 && comparePrefix(items[i - 1] as RecordItemV3, item as RecordItemV3) >= 0) return false;
    if (tag !== groupTag) {
      groupTag = tag;
      groupWhole = slot === RECORD_SLOT_WHOLE_V3;
      if (!groupWhole && slot !== 0) return false;
      nextSlot = 1;
      continue;
    }
    if (groupWhole || slot === RECORD_SLOT_WHOLE_V3 || slot !== nextSlot) return false;
    nextSlot += 1;
  }
  return true;
}

/** SHA-256("pacspace:record:v3" || 0x00 || u16be(n) || item_1 || ... || item_n); throws on items that do not validate. */
export async function computeRecordHashV3(items: readonly RecordItemV3[]): Promise<string> {
  if (!validateRecordItemsV3(items)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'record items must be well formed, strictly ascending and grouped');
  }
  const count = new Uint8Array([(items.length >> 8) & 0xff, items.length & 0xff]);
  return toHex0x(await sha256(concatBytes(utf8(LABEL_RECORD), SEP, count, ...items.map(itemBytes))));
}

function itemBytes([tag, slot, leafHash]: RecordItemV3): Uint8Array {
  return concatBytes(fromHex32(tag), new Uint8Array([(slot >> 8) & 0xff, slot & 0xff]), fromHex32(leafHash));
}

async function itemOf(leaf: RevealedLeafV2): Promise<RecordItemV3 | null> {
  const parsed = parsePointerV3(leaf.pointer);
  if (!parsed) return null;
  return [await memberTagV3(parsed.key), parsed.index ?? RECORD_SLOT_WHOLE_V3, await computeLeafHashV3(leaf)];
}

/** Everything a v3 entry needs: the record hash, every item (sorted), every leaf with its salt (by pointer). */
export async function commitRecordContentV3(
  content: Record<string, unknown>,
  saltKey: string,
): Promise<{ recordHash: string; items: RecordItemV3[]; revealed: RevealedLeafV2[] }> {
  const fields = recordLeavesV2(content);
  const revealed: RevealedLeafV2[] = [];
  const items: RecordItemV3[] = [];
  for (const field of fields) {
    if (!parsePointerV3(field.pointer)) throw new RecordIntakeError('RECORD_CONTENT_INVALID', NOT_CANONICAL);
    const leaf = { pointer: field.pointer, value: field.value, salt: await deriveLeafSaltV3(saltKey, field.pointer) };
    revealed.push(leaf);
    items.push((await itemOf(leaf)) as RecordItemV3);
  }
  items.sort(comparePrefix);
  return { recordHash: await computeRecordHashV3(items), items, revealed };
}

export type OpenRecordEntryV3Result =
  | { ok: true; recordHash: string; fields: RecordLeafV2[]; withheld: number; content: Record<string, unknown> | null }
  | { ok: false; failure: 'malformed' | 'leaf-mismatch' | 'not-canonical'; reason: string };

/**
 * Opens a v3 entry. Every group is checked, shown or not. Each shown leaf's
 * recomputed (memberTag, slot, leafHash) must equal one item exactly. A whole
 * leaf holding a non-empty array is refused. `every` requires all items shown
 * and the content canonical.
 */
export async function openRecordEntryV3(
  entry: { items: readonly RecordItemV3[]; revealed: readonly RevealedLeafV2[] },
  options: { every: boolean },
): Promise<OpenRecordEntryV3Result> {
  const malformed = { ok: false as const, failure: 'malformed' as const, reason: NOT_CANONICAL };
  const items = entry?.items;
  const revealed = entry?.revealed;
  if (!validateRecordItemsV3(items) || !Array.isArray(revealed) || revealed.length > items.length) return malformed;
  for (let i = 0; i < revealed.length; i += 1) {
    const leaf = revealed[i];
    if (!isPlainObject(leaf) || !isHex32(leaf.salt) || leaf.value === undefined) return malformed;
    const parsed = parsePointerV3(leaf.pointer);
    if (!parsed) return malformed;
    if (i > 0 && !(revealed[i - 1].pointer < (leaf.pointer as string))) return malformed;
    if (parsed.index === null && Array.isArray(leaf.value) && leaf.value.length > 0) return malformed;
    if (hasLoneSurrogate(leaf.value)) return malformed;
    try {
      canonicalizeJcs(leaf.value);
    } catch {
      return malformed;
    }
  }
  const byPrefix = new Map(items.map((it) => [`${it[0]}:${it[1]}`, it[2]] as const));
  for (const leaf of revealed) {
    const item = (await itemOf(leaf)) as RecordItemV3;
    if (byPrefix.get(`${item[0]}:${item[1]}`) !== item[2]) return { ok: false, failure: 'leaf-mismatch', reason: SHOWN_FIELD_MISMATCH };
  }
  const fields = revealed.map((l) => ({ pointer: l.pointer, value: l.value }));
  const full = revealed.length === items.length;
  const content = full ? recordContentFromLeavesV2(fields) : null;
  if (options.every && (!full || content === null)) return { ok: false, failure: 'not-canonical', reason: NOT_CANONICAL };
  return { ok: true, recordHash: await computeRecordHashV3(items), fields, withheld: items.length - revealed.length, content };
}

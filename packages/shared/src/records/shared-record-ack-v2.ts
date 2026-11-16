/**
 * `shared-record-ack/v2` (records prototype build, R7; HANDOFF "Read this first", fact 4; D-5, D-22, D-45): a trail
 * link reader's acknowledgment of a check, signed like BF's `signed-acknowledgment/v2`: ES256 and ML-DSA-65 over the
 * same message, both required, by a confirmed device's v2 pair, with the pair's key id
 * (`acknowledgmentKeyIdV2`, `SHA-256("pacspace:ack-key-id:v1" || both public keys)`) carried as `keyId`, the
 * acknowledgment's `actorId`.
 *
 * The body names the seal history digest and the disclosure digest the reader checked, and holds the check's
 * reference and day, its counts, the seeded samples (seed, method and picks), how many answered entries were shown and
 * declined, the entries that did not match their seals, the flags (`{record, entry, result, note}`), each opened
 * answer's declared-field result, and the note. A mismatch is carried, never refused. Records are numbered as on the
 * link and entries from 1, as the reader reads them. Nothing here names the reader, a person, or the workspace's own
 * name for what is shared.
 *
 * Each note (every flag's, and the acknowledgment's own) is the reader's words in a plaintext workspace, and in an
 * encrypted one a `sealed-note/v1` made in the reader's browser (David, 2026-10-26): every note of one body under one
 * fresh key, wrapped to the link's confirmed devices and the workspace identity beside the body, never in it
 * (`ackFlagNoteNameV1`, `ackNoteNameV1`). Both signatures cover the sealed form, so PacSpace keeps and commits what it
 * cannot read. One body never mixes the two forms.
 *
 * Like v2 this module holds only what every side must agree on byte for byte, and loads no signing library: the
 * message is the label, a line break and the body's JCS, so two writers that order members differently sign the same
 * bytes, and no other message PacSpace signs starts with this label.
 */
import { canonicalizeJcs } from '../proof/jcs';
import { readSealedNoteShapeV1, type SealedNoteV1 } from './reader-crypto-v1';

export const SHARED_RECORD_ACK_SCHEMA_V2 = 'shared-record-ack/v2' as const;
export const SHARED_RECORD_ACK_SIGNING_LABEL_V2 = 'pacspace:shared-record-ack:v2';
/** The body as JSON, with every flag's note sealed. */
export const SHARED_RECORD_ACK_MAX_CHARS_V2 = 256 * 1024;
export const SHARED_RECORD_ACK_NOTE_MAX_V2 = 2000;
export const SHARED_RECORD_ACK_FLAG_NOTE_MAX_V2 = 500;
/** A sealed flag note's ciphertext as base64url: 500 UTF-16 units are at most 1,500 bytes of UTF-8, and the tag 16. */
export const SHARED_RECORD_ACK_SEALED_FLAG_NOTE_MAX_CHARS_V2 = Math.ceil(((SHARED_RECORD_ACK_FLAG_NOTE_MAX_V2 * 3 + 16) * 4) / 3);
/** The acknowledgment's own note sealed, by the same count at its 2,000-unit bound. */
export const SHARED_RECORD_ACK_SEALED_NOTE_MAX_CHARS_V2 = Math.ceil(((SHARED_RECORD_ACK_NOTE_MAX_V2 * 3 + 16) * 4) / 3);
export const SHARED_RECORD_ACK_LIST_MAX_V2 = 100;
export const SHARED_RECORD_ACK_SAMPLES_MAX_V2 = 20;

/** A flagged entry's result as the reader's check found it: matches its seal, does not, or an export's copy differs. */
export const SHARED_RECORD_ACK_FLAG_RESULTS_V2 = ['matches', 'does-not-match', 'copy-differs'] as const;
export type SharedRecordAckFlagResultV2 = (typeof SHARED_RECORD_ACK_FLAG_RESULTS_V2)[number];

export interface SharedRecordAckEntryV2 {
  record: number;
  entry: number;
}

export interface SharedRecordAckBodyV2 {
  schema: typeof SHARED_RECORD_ACK_SCHEMA_V2;
  /** The link's reference (`SR-` and 8 characters, unique across workspaces), so the signature speaks for this link only, never naming its handle. */
  reference: string;
  /** D-1's device id of the signing device, 64 lowercase hex. */
  deviceId: string;
  /** `acknowledgmentKeyIdV2` of the device's P-256 and ML-DSA-65 keys, 64 lowercase hex: the actorId. */
  keyId: string;
  check: { ref: string; on: string };
  /** The digest of the seal histories the check read, and of the disclosures it opened (null when none). */
  sealHistoryDigest: string;
  disclosureDigest: string | null;
  counts: { records: number; entries: number; matched: number; notMatched: number };
  sample: Array<{ request: string; method: 'pacspace-sample/v1'; seed: string; picks: SharedRecordAckEntryV2[] }>;
  answers: { shown: number; declined: number };
  mismatches: SharedRecordAckEntryV2[];
  /** Each note: the words (plaintext workspace), a `sealed-note/v1` (encrypted workspace), or null. */
  flags: Array<SharedRecordAckEntryV2 & { result: SharedRecordAckFlagResultV2; note: string | SealedNoteV1 | null }>;
  /** D-22: per opened answer, whether it showed exactly the fields it declared. */
  declaredFields: Array<{ request: string; asDeclared: boolean }>;
  /** The acknowledgment's own note, in the same form as the flags' notes. */
  note: string | SealedNoteV1 | null;
  signedAt: string;
}

/** What `POST /api/v1/s/:handle/acknowledgments` takes: the body and both signatures over its message, base64url. */
export interface SharedRecordAckEnvelopeV2 {
  body: SharedRecordAckBodyV2;
  signature: string;
  mldsaSignature: string;
}

const MEMBERS = ['schema', 'reference', 'deviceId', 'keyId', 'check', 'sealHistoryDigest', 'disclosureDigest', 'counts', 'sample', 'answers', 'mismatches', 'flags', 'declaredFields', 'note', 'signedAt'] as const;
const HEX64 = /^[0-9a-f]{64}$/;
const DIGEST = /^(0x)?[0-9a-f]{64}$/;
const REFERENCE = /^SR-[0-9A-Za-z]{8}$/;
const CHECK_REF = /^CHK-\d{4,8}$/;
const REQUEST_REF = /^Q-\d{4,8}$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
/** Free text: no control characters but the line break and tab. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;

class Problem extends Error {}

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function exact(value: unknown, members: readonly string[], path: string): Record<string, unknown> {
  if (!isPlain(value)) throw new Problem(path || 'body');
  const at = (k: string) => (path ? `${path}.${k}` : k);
  for (const key of Object.keys(value)) if (!members.includes(key)) throw new Problem(`${at(key)}: not allowed`);
  for (const key of members) if (value[key] === undefined) throw new Problem(`${at(key)}: missing`);
  return value;
}

function natural(value: unknown, path: string, min = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < min) throw new Problem(path);
  return value as number;
}

function text(value: unknown, path: string, pattern: RegExp): string {
  if (typeof value !== 'string' || !pattern.test(value)) throw new Problem(path);
  return value;
}

function note(value: unknown, path: string, max: number): string | null {
  if (value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > max || CONTROL.test(value) || value.trim() !== value) throw new Problem(path);
  return value;
}

function wordsOrSealed(value: unknown, path: string, max: number, sealedMax: number): string | SealedNoteV1 | null {
  if (value === null || typeof value === 'string') return note(value, path, max);
  const shape = readSealedNoteShapeV1(value);
  const v = value as SealedNoteV1;
  if (!shape.ok || v.ct.length > sealedMax) throw new Problem(path);
  return { schema: v.schema, iv: v.iv, ct: v.ct };
}

/** A flag note's words as a plaintext body carries them, or null when they are not (empty, too long, untrimmed, control characters). */
export function readSharedRecordAckFlagTextV2(value: unknown): string | null {
  try {
    return typeof value === 'string' ? note(value, 'note', SHARED_RECORD_ACK_FLAG_NOTE_MAX_V2) : null;
  } catch {
    return null;
  }
}

/** The acknowledgment's own note's words, read by the same rules at its own bound, or null. */
export function readSharedRecordAckNoteTextV2(value: unknown): string | null {
  try {
    return typeof value === 'string' ? note(value, 'note', SHARED_RECORD_ACK_NOTE_MAX_V2) : null;
  } catch {
    return null;
  }
}

/** Whether a note (a flag's, or the acknowledgment's own) is sealed. */
export const isSealedFlagNoteV2 = (n: string | SealedNoteV1 | null): n is SealedNoteV1 => n !== null && typeof n === 'object';

/** Every note a body carries, the acknowledgment's own first, then each flag's. */
export const ackNotesV2 = (body: Pick<SharedRecordAckBodyV2, 'note' | 'flags'>): Array<string | SealedNoteV1 | null> => [body.note, ...body.flags.map((f) => f.note)];

function list<T>(value: unknown, path: string, max: number, item: (v: unknown, p: string) => T): T[] {
  if (!Array.isArray(value) || value.length > max) throw new Problem(path);
  return value.map((v, i) => item(v, `${path}[${i}]`));
}

function entry(value: unknown, path: string, members: readonly string[] = ['record', 'entry']): SharedRecordAckEntryV2 & Record<string, unknown> {
  const v = exact(value, members, path);
  return { ...v, record: natural(v.record, `${path}.record`, 1), entry: natural(v.entry, `${path}.entry`, 1) };
}

function unique(items: SharedRecordAckEntryV2[], path: string): void {
  if (new Set(items.map((i) => `${i.record}:${i.entry}`)).size !== items.length) throw new Problem(path);
}

function parse(value: unknown): SharedRecordAckBodyV2 {
  if (!isPlain(value)) throw new Problem('body');
  let json: string;
  try {
    json = JSON.stringify(value);
  } catch {
    throw new Problem('body');
  }
  if (json.length > SHARED_RECORD_ACK_MAX_CHARS_V2) throw new Problem('too large');
  const v = exact(value, MEMBERS, '');
  if (v.schema !== SHARED_RECORD_ACK_SCHEMA_V2) throw new Problem('schema');
  const check = exact(v.check, ['ref', 'on'], 'check');
  const counts = exact(v.counts, ['records', 'entries', 'matched', 'notMatched'], 'counts');
  const answers = exact(v.answers, ['shown', 'declined'], 'answers');
  const mismatches = list(v.mismatches, 'mismatches', SHARED_RECORD_ACK_LIST_MAX_V2, (x, p) => {
    const e = entry(x, p);
    return { record: e.record, entry: e.entry };
  });
  unique(mismatches, 'mismatches');
  const flags = list(v.flags, 'flags', SHARED_RECORD_ACK_LIST_MAX_V2, (x, p) => {
    const e = entry(x, p, ['record', 'entry', 'result', 'note']);
    if (!SHARED_RECORD_ACK_FLAG_RESULTS_V2.includes(e.result as SharedRecordAckFlagResultV2)) throw new Problem(`${p}.result`);
    return { record: e.record, entry: e.entry, result: e.result as SharedRecordAckFlagResultV2, note: wordsOrSealed(e.note, `${p}.note`, SHARED_RECORD_ACK_FLAG_NOTE_MAX_V2, SHARED_RECORD_ACK_SEALED_FLAG_NOTE_MAX_CHARS_V2) };
  });
  unique(flags, 'flags');
  const ownNote = wordsOrSealed(v.note, 'note', SHARED_RECORD_ACK_NOTE_MAX_V2, SHARED_RECORD_ACK_SEALED_NOTE_MAX_CHARS_V2);
  const notes = [ownNote, ...flags.map((f) => f.note)];
  if (notes.some(isSealedFlagNoteV2) && notes.some((n) => typeof n === 'string')) throw new Problem('notes: sealed and plain notes together');
  const sample = list(v.sample, 'sample', SHARED_RECORD_ACK_SAMPLES_MAX_V2, (x, p) => {
    const s = exact(x, ['request', 'method', 'seed', 'picks'], p);
    if (s.method !== 'pacspace-sample/v1') throw new Problem(`${p}.method`);
    const picks = list(s.picks, `${p}.picks`, SHARED_RECORD_ACK_LIST_MAX_V2, (y, q) => {
      const e = entry(y, q);
      return { record: e.record, entry: e.entry };
    });
    unique(picks, `${p}.picks`);
    return { request: text(s.request, `${p}.request`, REQUEST_REF), method: 'pacspace-sample/v1' as const, seed: text(s.seed, `${p}.seed`, HEX64), picks };
  });
  const declaredFields = list(v.declaredFields, 'declaredFields', SHARED_RECORD_ACK_LIST_MAX_V2, (x, p) => {
    const d = exact(x, ['request', 'asDeclared'], p);
    if (typeof d.asDeclared !== 'boolean') throw new Problem(`${p}.asDeclared`);
    return { request: text(d.request, `${p}.request`, REQUEST_REF), asDeclared: d.asDeclared };
  });
  if (v.disclosureDigest !== null && (typeof v.disclosureDigest !== 'string' || !DIGEST.test(v.disclosureDigest))) throw new Problem('disclosureDigest');
  return {
    schema: SHARED_RECORD_ACK_SCHEMA_V2,
    reference: text(v.reference, 'reference', REFERENCE),
    deviceId: text(v.deviceId, 'deviceId', HEX64),
    keyId: text(v.keyId, 'keyId', HEX64),
    check: { ref: text(check.ref, 'check.ref', CHECK_REF), on: text(check.on, 'check.on', DAY) },
    sealHistoryDigest: text(v.sealHistoryDigest, 'sealHistoryDigest', DIGEST),
    disclosureDigest: v.disclosureDigest as string | null,
    counts: {
      records: natural(counts.records, 'counts.records'),
      entries: natural(counts.entries, 'counts.entries'),
      matched: natural(counts.matched, 'counts.matched'),
      notMatched: natural(counts.notMatched, 'counts.notMatched'),
    },
    sample,
    answers: { shown: natural(answers.shown, 'answers.shown'), declined: natural(answers.declined, 'answers.declined') },
    mismatches,
    flags,
    declaredFields,
    note: ownNote,
    signedAt: text(v.signedAt, 'signedAt', RFC3339_UTC),
  };
}

/** The body read member by member into a fresh object, or the first problem by its path. Never throws. */
export function readSharedRecordAckV2(value: unknown): { ok: true; body: SharedRecordAckBodyV2 } | { ok: false; problem: string } {
  try {
    return { ok: true, body: parse(value) };
  } catch (error) {
    if (error instanceof Problem) return { ok: false, problem: error.message };
    return { ok: false, problem: 'body' };
  }
}

/** The exact text both signatures cover: the label, a line break, and the body's JCS. */
export function sharedRecordAckMessageV2(body: SharedRecordAckBodyV2): string {
  return `${SHARED_RECORD_ACK_SIGNING_LABEL_V2}\n${canonicalizeJcs(body)}`;
}

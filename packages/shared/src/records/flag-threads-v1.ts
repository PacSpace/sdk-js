/**
 * Flag threads (records prototype build, FL1; HANDOFF "Flags"; ADR 0019; D-1): what the reader, the lab's side and
 * PacSpace agree on for a thread `FL-0001` and up on a trail link, and for the team's flags not sent yet.
 *
 * A thread's notes are sealed in the browser that writes them with `sealed-note/v1` under `flagNoteNameV1`: the lab's
 * answer to every confirmed device of the link and to the workspace identity, the reader's reply to the workspace
 * identity and the link's confirmed devices, so both sides read the whole thread and PacSpace reads neither. In a
 * plaintext workspace PacSpace keeps the entries' words itself, so a thread's notes are kept as `plain-note/v1`, each
 * with a salt of its own so the digest the reader record commits can't be matched against guessed words.
 *
 * The team's flags not sent yet (`flag-drafts/v1`) are sealed to the link's confirmed devices only, never to the
 * workspace identity: the lab never sees a flag before the team sends it.
 *
 * Nothing here logs, and no refusal carries a note.
 */
import { canonicalizeJcs } from '../proof/jcs';
import { fromBase64Url, toBase64Url } from '../records-crypto/base64url';
import { randomBytes, sha256, utf8 } from '../records-crypto/platform-crypto';
import { ReaderCryptoError, readSealedNoteShapeV1, type NoteNameV1, type SealedNoteV1 } from './reader-crypto-v1';
import { SHARE_REFERENCE_PATTERN } from './reader-link-v1';

/** A thread's reference on its link. */
export const FLAG_REF_PATTERN_V1 = /^FL-\d{4,6}$/;
/** A flagged entry's result as the reader's check found it (R7's `shared-record-ack/v2` flags carry the same three). */
export const FLAG_RESULTS_V1 = ['matches', 'does-not-match', 'copy-differs'] as const;
export type FlagResultV1 = (typeof FLAG_RESULTS_V1)[number];
export type FlagStatusV1 = 'open' | 'answered' | 'closed';

/** An answer's or a reply's words, before they are sealed. */
export const FLAG_TEXT_MAX_V1 = 2000;
/** A sealed answer or reply at most this long as text: 2000 characters of four UTF-8 bytes, with the tag. */
export const FLAG_SEALED_NOTE_MAX_CHARS_V1 = Math.ceil(((FLAG_TEXT_MAX_V1 * 4 + 16) * 4) / 3);
/** As many flags as one acknowledgment carries, each note as long as one there. */
export const FLAG_DRAFTS_MAX_V1 = 100;
export const FLAG_DRAFT_NOTE_MAX_V1 = 500;

export const PLAIN_NOTE_SCHEMA_V1 = 'plain-note/v1' as const;
export const FLAG_DRAFTS_SCHEMA_V1 = 'flag-drafts/v1' as const;
const PLAIN_NOTE_SALT_BYTES = 16;

const HEX = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
/** Free text: no control characters but the line break and tab. */
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;
const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const exactly = (v: Record<string, unknown>, keys: readonly string[]) => Object.keys(v).length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));
const counting = (n: unknown, min: number): n is number => Number.isSafeInteger(n) && (n as number) >= min;

/** `FL-0001` for the first thread on a link. */
export function flagRefV1(n: number): string {
  if (!counting(n, 1) || n > 999_999) throw new ReaderCryptoError('READER_BINDING_INVALID');
  return `FL-${String(n).padStart(4, '0')}`;
}

/**
 * A thread note's name: `{handle}:flag-answer:{FL-ref}:{n}` or `{handle}:flag-reply:{FL-ref}:{n}`, `n` the message's
 * number on its thread, so a note opens under its own link, thread, kind and place, and no other.
 */
export function flagNoteNameV1(input: { handle: string; kind: 'answer' | 'reply'; ref: string; n: number }): NoteNameV1 {
  if ((input?.kind !== 'answer' && input?.kind !== 'reply') || typeof input.ref !== 'string' || !FLAG_REF_PATTERN_V1.test(input.ref) || !counting(input.n, 1)) {
    throw new ReaderCryptoError('READER_BINDING_INVALID');
  }
  const name: NoteNameV1 = { scope: { handle: input.handle }, kind: `flag-${input.kind}`, ref: input.ref, n: input.n };
  assertHandle(input.handle);
  return name;
}

/** The team's drafts' name: `{handle}:flag-drafts:{SR-reference}:{version}`, the version they are saved as. */
export function flagDraftsNoteNameV1(input: { handle: string; reference: string; version: number }): NoteNameV1 {
  if (typeof input?.reference !== 'string' || !SHARE_REFERENCE_PATTERN.test(input.reference) || !counting(input.version, 1)) {
    throw new ReaderCryptoError('READER_BINDING_INVALID');
  }
  assertHandle(input.handle);
  return { scope: { handle: input.handle }, kind: 'flag-drafts', ref: input.reference, n: input.version };
}

function assertHandle(handle: unknown): void {
  if (typeof handle !== 'string' || !/^csh1_[A-Za-z0-9_-]{1,80}$/.test(handle)) throw new ReaderCryptoError('READER_BINDING_INVALID');
}

/** An answer's or reply's words as they are sent: trimmed, not empty, at most 2000 characters; null otherwise. */
export function readFlagTextV1(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text || text.length > FLAG_TEXT_MAX_V1 || CONTROL.test(text)) return null;
  return text;
}

// ------------------------------------------------------------------ plain-note/v1 (a plaintext workspace)

export interface PlainNoteV1 {
  schema: typeof PLAIN_NOTE_SCHEMA_V1;
  text: string;
  salt: string;
}

/** A plaintext workspace's note, with a fresh 16-byte salt; refuses words `readFlagTextV1` refuses. */
export function plainNoteV1(value: string): PlainNoteV1 {
  const text = readFlagTextV1(value);
  if (text === null) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  return { schema: PLAIN_NOTE_SCHEMA_V1, text, salt: toBase64Url(randomBytes(PLAIN_NOTE_SALT_BYTES)) };
}

/** The keyless checks of a plain note: its three members, its words, and a 16-byte salt. Never throws. */
export function readPlainNoteV1(value: unknown): { ok: true; text: string } | { ok: false } {
  if (!isPlain(value) || !exactly(value, ['schema', 'text', 'salt']) || value.schema !== PLAIN_NOTE_SCHEMA_V1) return { ok: false };
  const text = readFlagTextV1(value.text);
  const salt = typeof value.salt === 'string' ? fromBase64Url(value.salt) : null;
  if (text === null || text !== value.text || !salt || salt.length !== PLAIN_NOTE_SALT_BYTES || toBase64Url(salt) !== value.salt) return { ok: false };
  return { ok: true, text };
}

/** A sealed answer or reply's keyless checks, within the size its words allow. */
export function readFlagSealedNoteV1(value: unknown): SealedNoteV1 | null {
  if (!readSealedNoteShapeV1(value).ok) return null;
  const v = value as SealedNoteV1;
  if (v.ct.length > FLAG_SEALED_NOTE_MAX_CHARS_V1) return null;
  return { schema: v.schema, iv: v.iv, ct: v.ct };
}

/** SHA-256 of a thread note's JCS, 64 lowercase hex: what the reader record commits for it. */
export async function flagNoteDigestV1(note: SealedNoteV1 | PlainNoteV1): Promise<string> {
  return HEX(await sha256(utf8(canonicalizeJcs(note))));
}

// ------------------------------------------------------------------ flag-drafts/v1 (the team's, sealed to its devices)

export interface FlagDraftV1 {
  /** The record's number on the link. */
  record: number;
  /** The entry, from 1, as the reader reads it. */
  entry: number;
  note: string | null;
}

export interface FlagDraftsV1 {
  schema: typeof FLAG_DRAFTS_SCHEMA_V1;
  flags: FlagDraftV1[];
}

/** The drafts read member by member into a fresh object; each entry flagged once. Never throws. */
export function readFlagDraftsV1(value: unknown): { ok: true; drafts: FlagDraftsV1 } | { ok: false } {
  const bad = { ok: false as const };
  if (!isPlain(value) || !exactly(value, ['schema', 'flags']) || value.schema !== FLAG_DRAFTS_SCHEMA_V1) return bad;
  if (!Array.isArray(value.flags) || value.flags.length > FLAG_DRAFTS_MAX_V1) return bad;
  const seen = new Set<string>();
  const flags: FlagDraftV1[] = [];
  for (const raw of value.flags) {
    if (!isPlain(raw) || !exactly(raw, ['record', 'entry', 'note']) || !counting(raw.record, 1) || !counting(raw.entry, 1)) return bad;
    const key = `${raw.record}:${raw.entry}`;
    if (seen.has(key)) return bad;
    seen.add(key);
    let note: string | null = null;
    if (raw.note !== null) {
      if (typeof raw.note !== 'string' || !raw.note || raw.note.length > FLAG_DRAFT_NOTE_MAX_V1 || CONTROL.test(raw.note)) return bad;
      note = raw.note;
    }
    flags.push({ record: raw.record as number, entry: raw.entry as number, note });
  }
  return { ok: true, drafts: { schema: FLAG_DRAFTS_SCHEMA_V1, flags } };
}

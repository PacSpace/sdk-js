/**
 * An acknowledgment's notes, its flags' and its own, sealed in the reader's browser (records prototype build, R7; David,
 * 2026-10-26; ADR 0019's R7 addendum): one fresh key for every note in the body, each note a `sealed-note/v1` under it
 * with its own additional data and a random IV, and the key wrapped with BF's `wrapDisclosureKeyV1` to each of the
 * link's confirmed devices and to the workspace identity, then zeroed. The wraps travel beside the signed body, never
 * in it. Reached through the asymmetric subpath only, as BF's layer is.
 */
import { readSharedRecordAckFlagTextV2, readSharedRecordAckNoteTextV2 } from '../../records/shared-record-ack-v2';
import {
  ReaderCryptoError,
  ackFlagNoteNameV1,
  ackFlagNotesKeyNameV1,
  ackNoteNameV1,
  openNoteV1,
  sealNoteWithV1,
  LINK_KEY_BYTES_V1,
  type NoteNameV1,
  type SealedNoteV1,
} from '../../records/reader-crypto-v1';
import { randomBytes } from '../platform-crypto';
import { unwrapNoteKeyV1, wrapNoteKeyV1 } from './reader-wraps-v1';
import type { KeyWrapV1, WorkspaceSeedV1 } from './records-asymmetric-v1';

/** A confirmed device the notes are sealed to: its D-1 id and its X-Wing public key. */
export interface AckFlagNoteDeviceV1 {
  deviceId: string;
  xwingPublicKey: Uint8Array;
}

/** What `POST /acknowledgments` carries beside the body when its flag notes are sealed. */
export interface AckFlagNoteKeysV1 {
  devices: Array<{ deviceId: string; wrap: KeyWrapV1 }>;
  workspace: KeyWrapV1;
}

/**
 * Seals each flag's words, and the acknowledgment's own note when given, to every device given and to the workspace
 * identity's X-Wing key, which the caller has checked against the link's tag (`servedWorkspaceKeyV1` and
 * `workspaceKeyTagCommittedV1`). Returns the flags' notes in the order given, and the own note or null.
 */
export async function sealAckFlagNotesV1(input: {
  handle: string;
  checkRef: string;
  flags: ReadonlyArray<{ record: number; entry: number; text: string }>;
  note?: string | null;
  devices: readonly AckFlagNoteDeviceV1[];
  workspace: Uint8Array;
}): Promise<{ notes: SealedNoteV1[]; note: SealedNoteV1 | null; keys: AckFlagNoteKeysV1 }> {
  const devices = input?.devices;
  if (!Array.isArray(devices) || devices.length === 0 || new Set(devices.map((d) => d?.deviceId)).size !== devices.length || !(input.workspace instanceof Uint8Array)) {
    throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  }
  const own = input.note ?? null;
  if (!Array.isArray(input.flags) || input.flags.some((f) => readSharedRecordAckFlagTextV2(f?.text) === null)) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  if (own !== null && readSharedRecordAckNoteTextV2(own) === null) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  if (input.flags.length === 0 && own === null) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  const keyName = ackFlagNotesKeyNameV1(input.handle, input.checkRef);
  const key = randomBytes(LINK_KEY_BYTES_V1);
  try {
    const notes: SealedNoteV1[] = [];
    for (const f of input.flags) notes.push(await sealNoteWithV1(f.text, ackFlagNoteNameV1(input.handle, input.checkRef, f.record, f.entry), key, randomBytes(12)));
    const note = own === null ? null : await sealNoteWithV1(own, ackNoteNameV1(input.handle, input.checkRef), key, randomBytes(12));
    const wraps: AckFlagNoteKeysV1['devices'] = [];
    for (const d of devices) wraps.push({ deviceId: d.deviceId, wrap: await wrapNoteKeyV1(d.xwingPublicKey, key, keyName) });
    return { notes, note, keys: { devices: wraps, workspace: await wrapNoteKeyV1(input.workspace, key, keyName) } };
  } finally {
    key.fill(0);
  }
}

/** Opens the acknowledgment's own note with the wrap sealed to `seed`. Never throws. */
export async function openAckNoteV1(input: { note: unknown; wrap: unknown; seed: WorkspaceSeedV1; handle: string; checkRef: string }): Promise<{ ok: true; text: string } | { ok: false; code: string }> {
  return openUnder(input, () => ackNoteNameV1(input.handle, input.checkRef));
}

async function openUnder(input: { note: unknown; wrap: unknown; seed: WorkspaceSeedV1; handle: string; checkRef: string }, name: () => NoteNameV1): Promise<{ ok: true; text: string } | { ok: false; code: string }> {
  try {
    const unwrapped = await unwrapNoteKeyV1({ seed: input.seed, wrap: input.wrap, name: ackFlagNotesKeyNameV1(input.handle, input.checkRef) });
    if (!unwrapped.ok) return { ok: false, code: unwrapped.code };
    try {
      return await openNoteV1({ note: input.note, key: unwrapped.disclosureKey, name: name() });
    } finally {
      unwrapped.disclosureKey.fill(0);
    }
  } catch {
    return { ok: false, code: 'SEALED_NOTE_AUTH_FAILED' };
  }
}

/** Opens one flagged entry's note with the wrap sealed to `seed`, under that entry's name only. Never throws. */
export async function openAckFlagNoteV1(input: {
  note: unknown;
  wrap: unknown;
  seed: WorkspaceSeedV1;
  handle: string;
  checkRef: string;
  record: number;
  entry: number;
}): Promise<{ ok: true; text: string } | { ok: false; code: string }> {
  return openUnder(input, () => ackFlagNoteNameV1(input.handle, input.checkRef, input.record, input.entry));
}

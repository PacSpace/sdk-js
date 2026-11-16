/**
 * Flag notes and the team's drafts, sealed where they are written (records prototype build, FL1; ADR 0019; D-1):
 * `sealed-note/v1` under a fresh key, the key wrapped with BF's `wrapDisclosureKeyV1` under the note's own typed
 * binding (`wrapNoteKeyV1`), then zeroed. A thread's answer or reply is wrapped to the link's confirmed devices and,
 * in an encrypted workspace, to the workspace identity; the team's drafts to the link's confirmed devices only, and
 * this module offers no way to wrap them to anything else. Reached through the asymmetric subpath only, as BF's layer is.
 */
import { flagDraftsNoteNameV1, readFlagDraftsV1, readFlagTextV1, type FlagDraftsV1 } from '../../records/flag-threads-v1';
import { ReaderCryptoError, openNoteV1, sealNoteV1, type NoteNameV1, type SealedNoteV1 } from '../../records/reader-crypto-v1';
import { unwrapNoteKeyV1, wrapNoteKeyV1 } from './reader-wraps-v1';
import type { KeyWrapV1, WorkspaceSeedV1 } from './records-asymmetric-v1';

/** A confirmed device a note is sealed to: its D-1 id and its X-Wing public key. */
export interface FlagNoteDeviceV1 {
  deviceId: string;
  xwingPublicKey: Uint8Array;
}

export interface SealedFlagNoteV1 {
  note: SealedNoteV1;
  wraps: Array<{ deviceId: string; wrap: KeyWrapV1 }>;
}

async function sealTo(text: string, name: NoteNameV1, devices: readonly FlagNoteDeviceV1[], workspace: Uint8Array | null) {
  if (!Array.isArray(devices) || new Set(devices.map((d) => d?.deviceId)).size !== devices.length || (devices.length === 0 && workspace === null)) {
    throw new ReaderCryptoError('READER_DEVICE_KEYS_INVALID');
  }
  const { note, key } = await sealNoteV1(text, name);
  try {
    const wraps: SealedFlagNoteV1['wraps'] = [];
    for (const d of devices) wraps.push({ deviceId: d.deviceId, wrap: await wrapNoteKeyV1(d.xwingPublicKey, key, name) });
    return { note, wraps, workspace: workspace ? await wrapNoteKeyV1(workspace, key, name) : null };
  } finally {
    key.fill(0);
  }
}

/** An answer or a reply, sealed to each device given and, when given, the workspace identity's X-Wing key. */
export async function sealFlagNoteV1(input: { text: string; name: NoteNameV1; devices: readonly FlagNoteDeviceV1[]; workspace: Uint8Array | null }): Promise<SealedFlagNoteV1 & { workspace: KeyWrapV1 | null }> {
  const text = readFlagTextV1(input?.text);
  if (text === null) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  return sealTo(text, input.name, input.devices, input.workspace ?? null);
}

/** Opens a thread note with the wrap sealed to `seed`, under the note's own name. Never throws. */
export async function openFlagNoteV1(input: { note: unknown; wrap: unknown; seed: WorkspaceSeedV1; name: NoteNameV1 }): Promise<{ ok: true; text: string } | { ok: false; code: string }> {
  try {
    const unwrapped = await unwrapNoteKeyV1({ seed: input.seed, wrap: input.wrap, name: input.name });
    if (!unwrapped.ok) return { ok: false, code: unwrapped.code };
    try {
      return await openNoteV1({ note: input.note, key: unwrapped.disclosureKey, name: input.name });
    } finally {
      unwrapped.disclosureKey.fill(0);
    }
  } catch {
    return { ok: false, code: 'SEALED_NOTE_AUTH_FAILED' };
  }
}

/** The team's drafts, as `flag-drafts/v1` JSON, sealed to each of the link's confirmed devices and to nothing else. */
export async function sealFlagDraftsV1(input: { drafts: FlagDraftsV1; handle: string; reference: string; version: number; devices: readonly FlagNoteDeviceV1[] }): Promise<SealedFlagNoteV1> {
  const read = readFlagDraftsV1(input?.drafts);
  if (!read.ok || !Array.isArray(input.devices) || input.devices.length === 0) throw new ReaderCryptoError('SEALED_NOTE_MALFORMED');
  const name = flagDraftsNoteNameV1({ handle: input.handle, reference: input.reference, version: input.version });
  const { note, wraps } = await sealTo(JSON.stringify(read.drafts), name, input.devices, null);
  return { note, wraps };
}

/** Opens the team's drafts as saved at `version`, and reads them member by member. Never throws. */
export async function openFlagDraftsV1(input: { note: unknown; wrap: unknown; seed: WorkspaceSeedV1; handle: string; reference: string; version: number }): Promise<{ ok: true; drafts: FlagDraftsV1 } | { ok: false; code: string }> {
  let name: NoteNameV1;
  try {
    name = flagDraftsNoteNameV1({ handle: input.handle, reference: input.reference, version: input.version });
  } catch {
    return { ok: false, code: 'READER_BINDING_INVALID' };
  }
  const opened = await openFlagNoteV1({ note: input.note, wrap: input.wrap, seed: input.seed, name });
  if (!opened.ok) return opened;
  try {
    const read = readFlagDraftsV1(JSON.parse(opened.text));
    return read.ok ? read : { ok: false, code: 'SEALED_NOTE_MALFORMED' };
  } catch {
    return { ok: false, code: 'SEALED_NOTE_MALFORMED' };
  }
}

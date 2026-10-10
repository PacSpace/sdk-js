import { RecordIntakeError, packStateV1, type StateFieldValues } from '../proof/layout-document-v1';
import type { RegisteredLayout } from '../proof/slot-encoding-v1';
import { RECORD_LEAVES_TOO_MANY_V2, recordLeavesV2 } from '../records-crypto/record-hash-v2';
import { buildRecord } from './build-record';
import { validateRecordContentV1 } from './record-content-v1';

/**
 * The checks intake makes on an entry before it is queued, in intake's
 * order: no caller-set state field PacSpace sets itself, the layout's sealed
 * content schema, the record hash's leaf cap, then the report as the Worker
 * builds it (Rule B included). Intake calls this for every write; a client
 * calls it before it encrypts, because intake cannot read encrypted content.
 * Layout admission stays with intake: it is a per-deployment setting.
 */
export interface RecordEntryInputV1 {
  lifecycle: string;
  fields?: StateFieldValues;
  flags?: string[];
  content: Record<string, unknown>;
}

export type RecordEntryAdmissionV1 =
  | { ok: true }
  | { ok: false; code: 'RECORD_FIELD_RESERVED'; field: string }
  | { ok: false; code: RecordIntakeError['code']; error: RecordIntakeError };

const PACSPACE_SET_FIELDS = new Set(['layoutId', 'layoutVersion', 'seq']);

/** The first state field in `fields` a caller may not supply, or null. */
export function reservedRecordFieldV1(layout: RegisteredLayout, fields: StateFieldValues | undefined): string | null {
  for (const name of Object.keys(fields ?? {})) {
    if (PACSPACE_SET_FIELDS.has(name) || name === layout.doc.lifecycle.field || name === 'flags') return name;
  }
  return null;
}

/**
 * The leaf cap, applied to every entry. Only the count is refused here;
 * content the leaf rule cannot form is refused by the Worker for a v2 entry,
 * and a v1 entry never forms leaves.
 */
function assertRecordLeafCount(content: unknown): void {
  if (!content || typeof content !== 'object' || Array.isArray(content)) return;
  try {
    recordLeavesV2(content as Record<string, unknown>);
  } catch (error) {
    if (error instanceof RecordIntakeError && error.message === RECORD_LEAVES_TOO_MANY_V2) throw error;
  }
}

export function admitRecordEntryV1(layout: RegisteredLayout, entry: RecordEntryInputV1): RecordEntryAdmissionV1 {
  const reserved = reservedRecordFieldV1(layout, entry.fields);
  if (reserved !== null) return { ok: false, code: 'RECORD_FIELD_RESERVED', field: reserved };
  try {
    validateRecordContentV1(layout.doc.sealedRecordSchema, entry.content);
    assertRecordLeafCount(entry.content);
    buildRecord({ layout, lifecycle: entry.lifecycle, fields: entry.fields ?? {}, flags: entry.flags ?? [], content: entry.content, seq: 0 });
  } catch (error) {
    if (error instanceof RecordIntakeError) return { ok: false, code: error.code, error };
    throw error;
  }
  return { ok: true };
}

/**
 * Intake's checks on an encrypted entry (ADR 0015 section 7): the public
 * state only, since intake never sees the content. The client ran
 * admitRecordEntryV1 on the content before it encrypted.
 */
export function admitEncryptedRecordStateV1(
  layout: RegisteredLayout,
  entry: Omit<RecordEntryInputV1, 'content'>,
): RecordEntryAdmissionV1 {
  const reserved = reservedRecordFieldV1(layout, entry.fields);
  if (reserved !== null) return { ok: false, code: 'RECORD_FIELD_RESERVED', field: reserved };
  const { doc } = layout;
  try {
    packStateV1(doc, {
      layoutId: doc.layoutId,
      layoutVersion: doc.layoutVersion,
      [doc.lifecycle.field]: entry.lifecycle,
      flags: entry.flags ?? [],
      seq: 0,
      ...(entry.fields ?? {}),
    });
  } catch (error) {
    if (error instanceof RecordIntakeError) return { ok: false, code: error.code, error };
    throw error;
  }
  return { ok: true };
}

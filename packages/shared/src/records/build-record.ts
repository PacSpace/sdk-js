import { canonicalizeJcs } from '../proof/jcs';
import {
  DecodedState,
  RecordIntakeError,
  StateFieldValues,
  decodeStateV1,
  packStateV1,
} from '../proof/layout-document-v1';
import { validatePayloadRefsInContent } from '../proof/payload-ref-v1';
import { RegisteredLayout, computeRecordHashV1, hex96 } from '../proof/slot-encoding-v1';
import { getPublishedLayout, getPublishedLayoutByName } from './layouts';
import { validateRecordContentV1 } from './record-content-v1';

/**
 * Tenant helper (RECORD_BUILDING_AND_VERIFICATION.md section 4a).
 *
 * `buildRecord` lets a tenant compute, before submitting, exactly what
 * PacSpace will seal: the canonical record bytes, their fingerprint, and the
 * public state their report packs to. It needs no key and no seed; the seal
 * itself is only computable once PacSpace assigns a batch position.
 *
 * For a record created with record hash v2, PacSpace draws the entry's salt
 * key when the entry arrives, so `buildRecord` cannot compute that record's
 * hash in advance: its `recordHash` is the v1 hash of the same content. Its
 * `state96` and `recordBytes` still match what PacSpace seals.
 */
export interface BuildRecordInput {
  /** Layout id (number) or layout name such as `geoint-tracked-entity/v1`. */
  layout: number | string | RegisteredLayout;
  /** Target lifecycle state by name. */
  lifecycle: string;
  /** Other state field values (counters, quantities). */
  fields?: StateFieldValues;
  /** Flag names to set. */
  flags?: string[];
  /** Sealed record content. */
  content: Record<string, unknown>;
  /** Sequence number of this record (0 for genesis); only affects the public state preview. */
  seq?: number;
}

export interface BuiltRecordPreview {
  layoutId: number;
  layoutVersion: number;
  layoutDigest: string;
  recordBytes: string;
  recordHash: string;
  /** Public state the report packs to (with the supplied seq). */
  state96: string;
  decodedState: DecodedState;
}

export function resolveLayout(layout: BuildRecordInput['layout']): RegisteredLayout {
  if (typeof layout === 'object' && layout && 'doc' in layout) return layout;
  const found = typeof layout === 'number' ? getPublishedLayout(layout) : getPublishedLayoutByName(String(layout));
  if (!found) throw new RecordIntakeError('LAYOUT_NOT_FOUND', `layout ${String(layout)} is not published`);
  return found;
}

export function buildRecord(input: BuildRecordInput): BuiltRecordPreview {
  const layout = resolveLayout(input.layout);
  const { doc, digest } = layout;
  if (!input.content || typeof input.content !== 'object' || Array.isArray(input.content)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'content must be an object');
  }
  validatePayloadRefsInContent(input.content);
  const values: StateFieldValues = {
    layoutId: doc.layoutId,
    layoutVersion: doc.layoutVersion,
    [doc.lifecycle.field]: input.lifecycle,
    flags: input.flags ?? [],
    seq: input.seq ?? 0,
    ...(input.fields ?? {}),
  };
  const state96 = packStateV1(doc, values);
  // The layout's sealed-content schema, after the state so a wrong lifecycle
  // word reports RECORD_STATE_UNKNOWN first (section 9 of the tenant guide).
  validateRecordContentV1(doc.sealedRecordSchema, input.content);
  return {
    layoutId: doc.layoutId,
    layoutVersion: doc.layoutVersion,
    layoutDigest: digest,
    recordBytes: canonicalizeJcs(input.content),
    recordHash: computeRecordHashV1(input.content),
    state96: hex96(state96),
    decodedState: decodeStateV1(doc, state96),
  };
}

import { decodeStateV1 } from '../proof/layout-document-v1';
import { RegisteredLayout, splitWordV1 } from '../proof/slot-encoding-v1';

/**
 * Record references (ADR 0012 section 4; records buyer posture plan, D3).
 *
 * A sealed record may name one entry of another record as
 * `{ recordKey, seq }`: `modelRecordRef` on the GeoINT layouts, and the
 * general `references[]` and `amends` on machine-action-record/v1. A verifier
 * holding the referenced record's word history resolves the referenced seq
 * and reports that record's lifecycle word at that point. The general
 * resolver below reports the word and whether the entry was there; the
 * model-record resolver keeps its accepted-states reading on top of it. Every
 * other state is reported, never silently accepted.
 */
export const MODEL_LINK_ACCEPTED_STATES = ['approved', 'deployed'] as const;
export const MODEL_NOT_APPROVED_AT_TIME = 'MODEL_NOT_APPROVED_AT_TIME';
export const MODEL_RECORD_SEQ_UNKNOWN = 'MODEL_RECORD_SEQ_UNKNOWN';
/** The referenced record's history at hand does not reach the referenced seq. */
export const RECORD_REFERENCE_SEQ_UNKNOWN = 'RECORD_REFERENCE_SEQ_UNKNOWN';

/** `{ recordKey, seq }`: one entry of one record. */
export interface RecordRef {
  recordKey: string;
  seq: number;
}

/** The GeoINT name for a reference to a model-version-record entry. */
export type ModelRecordRef = RecordRef;

export interface RecordRefResolution {
  /** The referenced record's lifecycle word at the referenced seq, or null when the history does not reach it. */
  lifecycle: string | null;
  /** True when the referenced record's history at hand carries the referenced entry (its word at that seq). */
  found: boolean;
  /**
   * True when the referenced entry preceded the referencing one. Within one
   * record (a `referencing` entry with the same recordKey) that is
   * `found && ref.seq < referencing.seq`. Across records the words alone do
   * not order the two entries, so `preceded` equals `found`: the referenced
   * entry was committed by the time the words at hand were read.
   */
  preceded: boolean;
  /** True when the referenced word is one of the referenced layout's terminal states (closed); null when not found. */
  terminal: boolean | null;
  /** Number of entries the referenced record has in the words at hand. */
  entries: number;
  reported?: string;
}

/**
 * `words[i]` is the word written at seq i for the referenced record key;
 * `layout` is the referenced record's layout (read from the word's layoutId
 * when the caller has a registry, or known from the reference's context).
 * `referencing` names the entry that carries the reference, when the caller
 * wants the same-record ordering check.
 */
export function resolveRecordRefV1(
  layout: RegisteredLayout,
  words: Array<string | bigint>,
  ref: RecordRef,
  referencing?: RecordRef,
): RecordRefResolution {
  const entries = words.length;
  const word = words[ref.seq];
  if (word === undefined) {
    return { lifecycle: null, found: false, preceded: false, terminal: null, entries, reported: RECORD_REFERENCE_SEQ_UNKNOWN };
  }
  const state = decodeStateV1(layout.doc, splitWordV1(word).state96);
  const lifecycle = state[layout.doc.lifecycle.field] as string;
  const seqInWord = Number(state.seq);
  if (seqInWord !== ref.seq) {
    return { lifecycle, found: false, preceded: false, terminal: null, entries, reported: RECORD_REFERENCE_SEQ_UNKNOWN };
  }
  const sameRecord = referencing !== undefined && referencing.recordKey.toLowerCase() === ref.recordKey.toLowerCase();
  const preceded = sameRecord ? ref.seq < (referencing as RecordRef).seq : true;
  const terminal = layout.doc.lifecycle.terminal.includes(lifecycle);
  return { lifecycle, found: true, preceded, terminal, entries };
}

export interface ModelRecordLinkResolution {
  lifecycle: string | null;
  accepted: boolean;
  reported?: string;
}

/**
 * `modelChainWords[i]` is the word written at seq i for the model record key.
 * The GeoINT reading of the general resolver: only `approved` and `deployed`
 * are accepted.
 */
export function resolveModelRecordRefV1(
  modelLayout: RegisteredLayout,
  modelChainWords: Array<string | bigint>,
  ref: ModelRecordRef,
): ModelRecordLinkResolution {
  const resolved = resolveRecordRefV1(modelLayout, modelChainWords, ref);
  if (!resolved.found) {
    return { lifecycle: resolved.lifecycle, accepted: false, reported: MODEL_RECORD_SEQ_UNKNOWN };
  }
  const lifecycle = resolved.lifecycle as string;
  const accepted = (MODEL_LINK_ACCEPTED_STATES as readonly string[]).includes(lifecycle);
  return accepted ? { lifecycle, accepted } : { lifecycle, accepted, reported: MODEL_NOT_APPROVED_AT_TIME };
}

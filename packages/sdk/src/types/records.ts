import type { Blinding } from '../blinding';
import type { FingerprintInput, PayloadRef } from '../fingerprint';

export type RecordLifecycle = 'recorded' | 'amended' | 'closed';
export type RecordEntryStatus = 'queued' | 'committed' | 'failed';

/**
 * An entry's number in its record, counted from 1 as every PacSpace page
 * counts it: the first entry is entry 1. The HTTP API and the history file
 * carry the same position as `seq`, counted from 0 (`seq = entry - 1`); the
 * SDK converts at its boundary, so a caller never sends or reads a `seq`.
 */
export type EntryNumber = number;

/** Names a committed entry of a record: by the record's key and the entry's number. */
export interface RecordEntryRef {
  recordKey: string;
  /** Counted from 1, as the pages count. */
  entry: EntryNumber;
}

export interface RecordEmitInput {
  record: string;
  recordType?: string;
  lifecycle?: RecordLifecycle;
  title: string;
  kind?: string;
  occurredAt: string;
  actorId: string;
  instructedBy?: string;
  payloads: PayloadRef[];
  /** Committed entries this entry refers to, in this record or another. */
  references?: RecordEntryRef[];
  /** The committed entry this entry corrects. The original stays visible. */
  amends?: RecordEntryRef;
  description?: string;
  note?: string;
  idempotencyKey?: string;
  /**
   * With a workspace secret set, entries are encrypted by default; `false`
   * writes plaintext, for a record that was started in plaintext.
   */
  encrypt?: boolean;
}

/**
 * How a read reaches a record. With a workspace secret set, a record is read
 * by its wire id, worked out here from `record`; `encrypted: false` reads a
 * plaintext record by its own id. A holder or a grant reader, who has no way
 * to work out another workspace's wire ids, passes `wireRecordId`.
 */
export interface RecordReadOptions {
  encrypted?: boolean;
  wireRecordId?: string;
  /** A grant on the record, sent in the X-PacSpace-Grant header. */
  grant?: string;
  /** The owning workspace's id: required with `grant` on an encrypted record; its wrap is bound to it. */
  owner?: string;
  /** The record's key, as `records.recordKey()` exports it, for a reader with no workspace. */
  recordKey?: string;
  /** The owning workspace's id, when this workspace reads as one of its holders. */
  holderFor?: string;
}

/** One entry of an encrypted record, opened and checked against its sealed record hash. */
export interface OpenedRecordEntry {
  /** Counted from 1. */
  entry: EntryNumber;
  recordHash: string;
  content: Record<string, unknown>;
}

export interface RecordEmitResponse {
  intakeId?: string;
  receiptId: string;
  recordType: string;
  entityId: string;
  recordKey: string;
  layoutId?: number;
  layoutVersion?: number;
  lifecycle?: string;
  status: string;
  referenceId?: string;
  receivedAt?: string;
  queuedViaOverflow?: boolean;
  message?: string;
  code?: string;
  retryAfterSeconds?: number;
  /** Encrypted writes: the record's own id, as passed. */
  recordId?: string;
  /** Encrypted writes: the id PacSpace knows the record by. A webhook names this one. */
  wireRecordId?: string;
  /** Encrypted writes: the reference id PacSpace knows the entry by. */
  wireReferenceId?: string;
  encrypted?: boolean;
}

export interface RecordReceiptInput extends RecordReadOptions {
  /** The record's own id; may be left out when `wireRecordId` is given. */
  record?: string;
  /** Counted from 1, as the pages count. */
  entry: EntryNumber;
  recordType?: string;
}

export interface RecordReceiptResponse {
  recordType: string;
  entityId: string;
  receipt: Record<string, unknown>;
  verify?: Record<string, unknown>;
  /** An encrypted entry, opened. */
  opened?: OpenedRecordEntry;
}

export interface RecordHistoryInput extends RecordReadOptions {
  /** The record's own id; may be left out when `wireRecordId` is given. */
  record?: string;
  /** First entry to read, counted from 1. */
  fromEntry?: EntryNumber;
  /** Last entry to read, counted from 1. */
  toEntry?: EntryNumber;
  recordType?: string;
}

/**
 * One line of the history as the API serves it. The history is the wire
 * document the check verifies by its digest, so it keeps the wire's `seq`
 * (counted from 0); the entry's number as the pages count it is `seq + 1`.
 */
export interface RecordHistoryEntry {
  seq: number | null;
  status: RecordEntryStatus;
  code?: string;
  sentence?: string;
  receiptId?: string;
}

export interface RecordHistory {
  schema: string;
  recordKey: string;
  chain?: { chainId?: number; contractAddress?: string };
  /**
   * semantic-receipt/v2 (`recordContent`) or, for a record created with record
   * hash v2, semantic-receipt/v3 (`leaves` and the `revealed` fields).
   */
  receipts: Array<
    Record<string, unknown> & {
      schema?: string;
      status?: RecordEntryStatus;
      seq?: number;
      recordContent?: Record<string, unknown>;
      leaves?: string[];
      revealed?: Array<{ pointer: string; value: unknown; salt: string }>;
      receiptId?: string;
    }
  >;
  pendingEntries?: RecordHistoryEntry[];
  entries?: RecordHistoryEntry[];
  nextFromSeq?: number | null;
  bundleDigest?: string;
  /** An encrypted record's entries, opened and checked; attempt and failure rows are not listed. */
  opened?: OpenedRecordEntry[];
  [key: string]: unknown;
}

/** A file you hold, with its blinding when the entry's fingerprint is blinded. */
export interface RecordCheckFile {
  source: FingerprintInput;
  blinding?: Blinding | null;
}

export interface RecordCheckExpect {
  /** Counted from 1, as the pages count. */
  entry: EntryNumber;
  payloads?: PayloadRef[];
  /** Files the entry should name, checked from their bytes. */
  files?: RecordCheckFile[];
}

export interface RecordCheckSource {
  kind: 'mirror' | 'direct';
  url?: string;
  address?: string;
}

export interface RecordCheckInput {
  history: RecordHistory;
  expect?: RecordCheckExpect[];
  source?: RecordCheckSource;
}

export interface RecordCheckEntryResult {
  /** Counted from 1, as the pages count; null for a queued write that has no place yet. */
  entry: EntryNumber | null;
  status: RecordEntryStatus;
  expected?: boolean;
  /** Read from the entry's verified word; null for an entry that did not verify, has no receipt, or is queued or failed. */
  kind?: 'transition' | 'attempt' | 'failure' | null;
  code?: string;
  sentence?: string;
}

/** Which fields of one entry a disclosure reveals: every field, or the listed fields by their pointers. */
export interface RecordDiscloseEntry {
  /** Counted from 1, as the pages count. */
  entry: EntryNumber;
  reveal: 'all' | string[];
}

export interface RecordDiscloseInput {
  record: string;
  recordType?: string;
  entries: RecordDiscloseEntry[];
  /** The public ledger the file is checked against, as in `records.check`. */
  source: RecordCheckSource;
}

/** A kept copy: the record's seal history and the disclosure, for the caller to write. */
export interface RecordDisclosureFile {
  bytes: Uint8Array;
  schema: 'record-link-copy/v1';
}

export interface RecordHistoryCheck {
  ok: boolean;
  entries: RecordCheckEntryResult[];
  failedCheck: string | null;
  sourceChecked: boolean;
  reason?: string;
  /** Entries with a blinded fingerprint that a file was passed for without its blinding. */
  blindingFileNeeded?: EntryNumber[];
  note?: string;
}

export const DEFAULT_RECORD_TYPE = 'machine-action-record';

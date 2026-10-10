import { ethers } from 'ethers';
import { canonicalizeJcs } from '../proof/jcs';
import {
  verifyRecordHistoryCoreV1,
  verifySlotReceiptCoreV1,
  type OpenedRecordContentV1,
  type SlotReceiptCoreV1,
  type SlotReceiptVerificationV2,
  type VerifySlotReceiptOptionsV2,
} from '../proof/semantic-receipt-v2';
import { SEMANTIC_RECEIPT_SCHEMA_V3, type SemanticReceiptV3 } from '../proof/semantic-receipt-v3';
import { fromBase64Url, toBase64Url } from '../records-crypto/base64url';
import { isHex32 } from '../records-crypto/platform-crypto';
import { commitRecordContentV2, openRecordEntryV2 } from '../records-crypto/record-hash-v2';
import {
  RecordKeyV1,
  entryRefsMatchV1,
  exportKeyBytesV1,
  openRecordEntryEnvelopeV1,
  readRecordEnvelopeShapeV1,
  recordKeyFromBytesV1,
  type RecordEntryEnvelopeV1,
  type RecordsEncryptionCodeV1,
} from '../records-crypto/records-encryption-v1';
import { recordEntryKindV1 } from './record-entry-kind-v1';
import {
  applyReferenceRuleV1,
  digestableHistoryBundleV1,
  finishHistoryBundleV1,
  prepareHistoryBundleV1,
  type BundleVerificationV1,
  type RecordHistoryBundleV1,
  type VerifyBundleOptionsV1,
} from './record-history-bundle-v1';

/**
 * The reading side of an encrypted record (ADR 0015, formats note N7 and
 * N8): `semantic-receipt/v4` carries the record hash and the envelopes where
 * v3 carried the leaves; `record-history-bundle/v3` holds v4 receipts for
 * transitions and v3 receipts for the attempt and failure rows PacSpace
 * writes from facts, with the refused envelopes beside them; and
 * `pacspace-record-copy/v1` is one record's history with its record key.
 * Reading needs the record key: every envelope is opened and its record hash
 * recomputed before the seal checks, which are v3's through the shared core.
 * Refusals carry a code and, where an entry is at fault, its seq.
 */
export const SEMANTIC_RECEIPT_SCHEMA_V4 = 'semantic-receipt/v4' as const;
export const RECORD_HISTORY_BUNDLE_SCHEMA_V3 = 'record-history-bundle/v3' as const;
export const RECORD_COPY_SCHEMA_V1 = 'pacspace-record-copy/v1' as const;
/** A reader declares it reads encrypted records with this header set to `1` (ADR 0015 section 7). */
export const RECORDS_ENCRYPTION_SUPPORT_HEADER = 'X-PacSpace-Records-Encryption' as const;

export interface SemanticReceiptV4 extends SlotReceiptCoreV1 {
  schema: typeof SEMANTIC_RECEIPT_SCHEMA_V4;
  recordHash: string;
  envelopes: RecordEntryEnvelopeV1[];
  amends?: unknown;
  references?: unknown;
}

export interface RefusedEnvelopeV1 {
  seq: number;
  recordHash: string;
  envelope: RecordEntryEnvelopeV1;
}

export interface RecordHistoryBundleV3 extends Omit<RecordHistoryBundleV1, 'schema' | 'receipts'> {
  schema: typeof RECORD_HISTORY_BUNDLE_SCHEMA_V3;
  receipts: Array<SemanticReceiptV4 | SemanticReceiptV3>;
  recordType: string;
  /** The wire record id. */
  entityId: string;
  refused: RefusedEnvelopeV1[];
}

export interface RecordCopyV1 {
  schema: typeof RECORD_COPY_SCHEMA_V1;
  /** `RK`, base64url. */
  recordKey: string;
  history: RecordHistoryBundleV3;
}

export type EncryptedReadCodeV1 =
  | RecordsEncryptionCodeV1
  | 'RECORD_HISTORY_RECEIPT_FORM'
  | 'RECORD_HISTORY_WRONG_RECORD'
  | 'RECORD_HISTORY_DIGEST'
  | 'RECORD_COPY_MALFORMED';

export type EncryptedReadRefusalV1 = { ok: false; code: EncryptedReadCodeV1; seq?: number };

export type OpenedEntryV1 =
  | { seq: number; recordHash: string; content: Record<string, unknown>; saltKey: string }
  | { seq: number; plaintext: true };

const refuse = (code: EncryptedReadCodeV1, seq?: number): EncryptedReadRefusalV1 => (seq === undefined ? { ok: false, code } : { ok: false, code, seq });
const keysAre = (value: unknown, keys: string) =>
  !!value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === keys;

export function isSlotReceiptV4(value: unknown): value is SemanticReceiptV4 {
  const r = value as Partial<SemanticReceiptV4> | null;
  return !!r && r.schema === SEMANTIC_RECEIPT_SCHEMA_V4 && r.itemKind === 'slot-v1';
}

/**
 * Opens a v4 receipt: the envelope this record key opens (each in turn),
 * the record hash recomputed from the content and salt key, and the outside
 * copies of `amends` and `references` against the content's.
 */
export async function openReceiptV4(
  receipt: unknown,
  input: { recordKey: RecordKeyV1; recordType: string; wireRecordId: string },
): Promise<{ ok: true; recordHash: string; content: Record<string, unknown>; saltKey: string } | EncryptedReadRefusalV1> {
  const r = receipt as SemanticReceiptV4;
  const seq = typeof r?.seq === 'number' ? r.seq : undefined;
  if (!isSlotReceiptV4(r) || !isHex32(r.recordHash) || !Array.isArray(r.envelopes) || r.envelopes.length === 0) {
    return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
  }
  const kids = r.envelopes.map((e) => (e as { kid?: unknown })?.kid);
  if (new Set(kids).size !== kids.length) return refuse('RECORD_ENVELOPE_MALFORMED', seq);
  let last: EncryptedReadRefusalV1 = refuse('RECORD_ENVELOPE_AUTH_FAILED', seq);
  for (const envelope of r.envelopes) {
    const opened = await openRecordEntryEnvelopeV1({ envelope, recordType: input.recordType, wireRecordId: input.wireRecordId, recordKey: input.recordKey });
    if (!opened.ok) {
      if (opened.code !== 'RECORD_ENVELOPE_AUTH_FAILED') return refuse(opened.code, seq);
      last = refuse(opened.code, seq);
      continue;
    }
    let recordHash: string;
    try {
      recordHash = (await commitRecordContentV2(opened.content, opened.saltKey)).recordHash;
    } catch {
      return refuse('RECORD_ENTRY_HASH_MISMATCH', seq);
    }
    if (recordHash !== r.recordHash) return refuse('RECORD_ENTRY_HASH_MISMATCH', seq);
    const refs = entryRefsMatchV1(opened.content, { amends: r.amends, references: r.references });
    if (!refs.ok) return refuse(refs.code, seq);
    return { ok: true, recordHash, content: opened.content, saltKey: opened.saltKey };
  }
  return last;
}

/**
 * What a reader without the key checks of a v4 receipt (formats note N7):
 * the receipt's form and every envelope's shape, then v3's checks with the
 * stated record hash, so the seal, the chain and the inclusion are checked
 * and the content is not. A v4 receipt is always a transition, whose rule
 * check reads the words alone. Never throws.
 */
export function checkSlotReceiptV4Sealed(
  receipt: unknown,
  options: VerifySlotReceiptOptionsV2,
): { ok: true; verification: SlotReceiptVerificationV2 } | EncryptedReadRefusalV1 {
  const r = receipt as SemanticReceiptV4;
  const seq = typeof r?.seq === 'number' ? r.seq : undefined;
  if (!isSlotReceiptV4(r) || !isHex32(r.recordHash) || !Array.isArray(r.envelopes) || r.envelopes.length === 0) {
    return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
  }
  const kids = new Set<string>();
  for (const envelope of r.envelopes) {
    const shape = readRecordEnvelopeShapeV1(envelope);
    if (!shape.ok) return refuse(shape.code, seq);
    if (kids.has(shape.kid)) return refuse('RECORD_ENVELOPE_MALFORMED', seq);
    kids.add(shape.kid);
  }
  try {
    const verification = verifySlotReceiptCoreV1(r, () => ({ ok: true, recordHash: r.recordHash, recordContent: {} }), options);
    return { ok: true, verification };
  } catch {
    return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
  }
}

/** A v4 receipt opened, then checked as v3 checks a receipt. */
export async function verifySlotReceiptV4(
  receipt: unknown,
  options: VerifySlotReceiptOptionsV2 & { recordKey: RecordKeyV1; recordType: string; wireRecordId: string },
): Promise<{ ok: true; opened: OpenedEntryV1; verification: SlotReceiptVerificationV2 } | EncryptedReadRefusalV1> {
  const opened = await openReceiptV4(receipt, options);
  if (!opened.ok) return opened;
  const r = receipt as SemanticReceiptV4;
  const verification = verifySlotReceiptCoreV1(r, () => ({ ok: true, recordHash: opened.recordHash, recordContent: opened.content }), options);
  return { ok: true, opened: { seq: r.seq, recordHash: opened.recordHash, content: opened.content, saltKey: opened.saltKey }, verification };
}

/** keccak256(utf8(JCS(bundle without digest-ignored status fields))), as v1 and v2; `refused` and the ids included. */
export function computeBundleDigestV3(bundle: RecordHistoryBundleV3): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalizeJcs(digestableHistoryBundleV1(bundle as unknown as RecordHistoryBundleV1))));
}

/** Which receipt form each entry must take: v3 for attempt and failure rows, v4 for every transition. */
function receiptFormRefusal(bundle: RecordHistoryBundleV3): EncryptedReadRefusalV1 | null {
  const layout = bundle.layout;
  for (const receipt of bundle.receipts as unknown[]) {
    const r = receipt as { schema?: unknown; seq?: unknown; newWord?: unknown; itemKind?: unknown };
    const seq = typeof r?.seq === 'number' ? r.seq : undefined;
    let kind: string;
    try {
      kind = recordEntryKindV1(layout, r.newWord as string).kind;
    } catch {
      return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
    }
    const plaintextRow = kind === 'attempt' || kind === 'failure';
    if (r.itemKind !== 'slot-v1') return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
    if (plaintextRow ? r.schema !== SEMANTIC_RECEIPT_SCHEMA_V3 : r.schema !== SEMANTIC_RECEIPT_SCHEMA_V4) {
      return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
    }
  }
  return null;
}

export type VerifyBundleV3Result =
  | {
      ok: true;
      opened: OpenedEntryV1[];
      /**
       * An attempt's refused envelope is opened with the held key its `kid`
       * names; one no held key opens (a re-key leaves attempts under their
       * original version) is `opened: false`, and the history still verifies.
       */
      refused: Array<{ seq: number; recordHash: string; opened: boolean }>;
      verification: BundleVerificationV1;
    }
  | EncryptedReadRefusalV1;

/**
 * Verifies a v3 bundle with the record's key. `expect` is the record the
 * reader asked for, by its own derivation of the wire id; a history for
 * another record is refused before anything is opened.
 */
export async function verifyRecordHistoryBundleV3(
  bundle: unknown,
  options: VerifyBundleOptionsV1 & {
    recordKey: RecordKeyV1;
    /** This record's keys under other versions, for refused envelopes a re-key left behind. */
    recordKeys?: RecordKeyV1[];
    expect?: { recordType: string; wireRecordId: string };
  },
): Promise<VerifyBundleV3Result> {
  const b = bundle as RecordHistoryBundleV3;
  if (!b || b.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3 || !Array.isArray(b.receipts) || !Array.isArray(b.refused)) {
    return refuse('RECORD_HISTORY_RECEIPT_FORM');
  }
  if (typeof b.recordType !== 'string' || typeof b.entityId !== 'string') return refuse('RECORD_HISTORY_RECEIPT_FORM');
  if (options.expect && (b.recordType !== options.expect.recordType || b.entityId !== options.expect.wireRecordId)) {
    return refuse('RECORD_HISTORY_WRONG_RECORD');
  }
  if (b.bundleDigest !== undefined && computeBundleDigestV3(b).toLowerCase() !== String(b.bundleDigest).toLowerCase()) {
    return refuse('RECORD_HISTORY_DIGEST');
  }
  const form = receiptFormRefusal(b);
  if (form) return form;

  const ids = { recordKey: options.recordKey, recordType: b.recordType, wireRecordId: b.entityId };
  const openedBy = new Map<unknown, OpenedRecordContentV1>();
  const opened: OpenedEntryV1[] = [];
  for (const receipt of [...b.receipts].sort((x, y) => x.seq - y.seq)) {
    if (receipt.schema === SEMANTIC_RECEIPT_SCHEMA_V4) {
      const open = await openReceiptV4(receipt, ids);
      if (!open.ok) return open;
      openedBy.set(receipt, { ok: true, recordHash: open.recordHash, recordContent: open.content });
      opened.push({ seq: receipt.seq, recordHash: open.recordHash, content: open.content, saltKey: open.saltKey });
    } else {
      const open = await openRecordEntryV2(receipt as SemanticReceiptV3, { every: true });
      openedBy.set(receipt, open.ok ? { ok: true, recordHash: open.recordHash, recordContent: open.content as Record<string, unknown> } : { ok: false, reason: open.reason });
      opened.push({ seq: receipt.seq, plaintext: true });
    }
  }

  const rowSeqs = new Set(b.receipts.filter((r) => r.schema === SEMANTIC_RECEIPT_SCHEMA_V3).map((r) => r.seq));
  const held = [options.recordKey, ...(options.recordKeys ?? [])].filter((k): k is RecordKeyV1 => k instanceof RecordKeyV1);
  const refused: Array<{ seq: number; recordHash: string; opened: boolean }> = [];
  for (const item of b.refused as unknown[]) {
    const x = item as RefusedEnvelopeV1;
    const seq = typeof x?.seq === 'number' ? x.seq : undefined;
    if (!keysAre(x, 'envelope,recordHash,seq') || !rowSeqs.has(x.seq) || !isHex32(x.recordHash)) return refuse('RECORD_HISTORY_RECEIPT_FORM', seq);
    const shape = readRecordEnvelopeShapeV1(x.envelope);
    if (!shape.ok) return refuse(shape.code, x.seq);
    const named = held.filter((k) => k.recordsKeyId === shape.kid);
    let open: Awaited<ReturnType<typeof openRecordEntryEnvelopeV1>> | null = null;
    for (const recordKey of named.length > 0 ? named : held.filter((k) => k.recordsKeyId === null)) {
      open = await openRecordEntryEnvelopeV1({ envelope: x.envelope, recordType: b.recordType, wireRecordId: b.entityId, recordKey });
      if (open.ok || open.code !== 'RECORD_ENVELOPE_AUTH_FAILED') break;
    }
    if (!open || (!open.ok && open.code === 'RECORD_ENVELOPE_AUTH_FAILED' && named.length === 0)) {
      refused.push({ seq: x.seq, recordHash: x.recordHash, opened: false });
      continue;
    }
    if (!open.ok) return refuse(open.code, x.seq);
    let recordHash: string;
    try {
      recordHash = (await commitRecordContentV2(open.content, open.saltKey)).recordHash;
    } catch {
      return refuse('RECORD_ENTRY_HASH_MISMATCH', x.seq);
    }
    if (recordHash !== x.recordHash) return refuse('RECORD_ENTRY_HASH_MISMATCH', x.seq);
    refused.push({ seq: x.seq, recordHash, opened: true });
  }

  const prepared = prepareHistoryBundleV1(b, options, {
    schema: RECORD_HISTORY_BUNDLE_SCHEMA_V3,
    notThisForm: 'RECORD_HISTORY_RECEIPT_FORM',
    receiptsRefusal: () => null,
    digest: computeBundleDigestV3,
  });
  if (prepared.done) return { ok: true, opened, refused, verification: prepared.done };
  const receipts: SlotReceiptCoreV1[] = b.receipts;
  const history = applyReferenceRuleV1(
    receipts,
    verifyRecordHistoryCoreV1(
      receipts,
      (receipt, opts) => verifySlotReceiptCoreV1(receipt, () => openedBy.get(receipt) as OpenedRecordContentV1, opts),
      prepared.historyOptions,
    ),
    {
      layouts: options.layouts,
      referencedWords: options.referencedWords,
      contentOf: (receipt) => {
        const open = openedBy.get(receipt);
        return open && open.ok ? open.recordContent : null;
      },
    },
  );
  return { ok: true, opened, refused, verification: finishHistoryBundleV1(prepared, history) };
}

/** A copy of one record: its v3 history, which must carry its digest, and its record key. */
export function buildRecordCopyV1(input: { recordKey: RecordKeyV1; history: RecordHistoryBundleV3 }): RecordCopyV1 {
  if (!(input.recordKey instanceof RecordKeyV1) || typeof input.history?.bundleDigest !== 'string') {
    throw new Error('RECORD_COPY_MALFORMED');
  }
  return { schema: RECORD_COPY_SCHEMA_V1, recordKey: toBase64Url(exportKeyBytesV1(input.recordKey)), history: input.history };
}

/** Reads a copy file's shape and its key. Never throws. */
export async function readRecordCopyV1(file: unknown): Promise<{ ok: true; recordKey: RecordKeyV1; history: RecordHistoryBundleV3 } | EncryptedReadRefusalV1> {
  const f = file as RecordCopyV1;
  if (!keysAre(f, 'history,recordKey,schema') || f.schema !== RECORD_COPY_SCHEMA_V1 || typeof f.recordKey !== 'string') {
    return refuse('RECORD_COPY_MALFORMED');
  }
  const bytes = fromBase64Url(f.recordKey);
  if (!bytes || bytes.length !== 32) return refuse('RECORD_COPY_MALFORMED');
  if (!f.history || typeof f.history !== 'object' || typeof f.history.bundleDigest !== 'string') return refuse('RECORD_COPY_MALFORMED');
  return { ok: true, recordKey: await recordKeyFromBytesV1(bytes), history: f.history };
}

/** Verifies a copy file: its history with its own key. */
export async function verifyRecordCopyV1(
  file: unknown,
  options: VerifyBundleOptionsV1 & { expect?: { recordType: string; wireRecordId: string } } = {},
): Promise<VerifyBundleV3Result> {
  const read = await readRecordCopyV1(file);
  if (!read.ok) return read;
  return verifyRecordHistoryBundleV3(read.history, { ...options, recordKey: read.recordKey });
}

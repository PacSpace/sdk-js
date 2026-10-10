import { openRecordEntryV2, recordContentFromLeavesV2, type RevealedLeafV2 } from '../records-crypto/record-hash-v2';
import {
  SEMANTIC_RECEIPT_SCHEMA_V2,
  verifyRecordHistoryCoreV1,
  verifyRecordHistoryV2,
  verifySlotReceiptCoreV1,
  verifySlotReceiptV2,
  type OpenedRecordContentV1,
  type RecordHistoryCheckV2,
  type SemanticReceiptV2,
  type SlotReceiptVerificationV2,
  type VerifySlotReceiptOptionsV2,
} from './semantic-receipt-v2';
import { SLOT_ENCODING_VERSION_V1, SLOT_ITEM_KIND_V1 } from './slot-encoding-v1';

/**
 * semantic-receipt/v3 (ADR 0016; record-hash-v2.md): semantic-receipt/v2
 * with `recordContent` replaced by the entry's salted leaves. A receipt is a
 * full copy: every leaf is revealed, and `leaves` is kept so a receipt entry
 * and a disclosure entry share one shape and one opener. Every other check is
 * semantic-receipt/v2's, through the shared core.
 */
export const SEMANTIC_RECEIPT_SCHEMA_V3 = 'semantic-receipt/v3' as const;

export interface SemanticReceiptV3 extends Omit<SemanticReceiptV2, 'schema' | 'recordContent'> {
  schema: typeof SEMANTIC_RECEIPT_SCHEMA_V3;
  leaves: string[];
  revealed: RevealedLeafV2[];
}

export type RecordReceipt = SemanticReceiptV2 | SemanticReceiptV3;

const MIXED_VERSIONS = 'This history mixes two record hash versions; every entry of a record uses one.';
const FORM_NAME = /^[a-z0-9-]{1,64}\/v[0-9]{1,3}$/;

/** The refusal for a form this version cannot read; a name that is not a plain form name is never echoed. */
export function unreadableFormReason(schema: unknown): string {
  return typeof schema === 'string' && FORM_NAME.test(schema)
    ? `This file names a form this version cannot read: ${schema}.`
    : 'This file names a form this version cannot read.';
}

export function isSlotReceiptV3(value: unknown): value is SemanticReceiptV3 {
  const r = value as Partial<SemanticReceiptV3> | null;
  return !!r && r.schema === SEMANTIC_RECEIPT_SCHEMA_V3 && r.itemKind === SLOT_ITEM_KIND_V1;
}

function schemaFailure(reason: string): SlotReceiptVerificationV2 {
  return {
    verified: false,
    level: null,
    failedCheck: 'schema',
    checks: { schema: false },
    decodedState: null,
    recomputedRecordHash: null,
    recomputedSeal: null,
    recomputedSealTag: null,
    expectedSealTag: null,
    recomputedItemHash: null,
    reason,
  };
}

async function openReceiptV3(receipt: SemanticReceiptV3): Promise<OpenedRecordContentV1> {
  const opened = await openRecordEntryV2(receipt, { every: true });
  if (!opened.ok) return { ok: false, reason: opened.reason };
  return { ok: true, recordHash: opened.recordHash, recordContent: opened.content as Record<string, unknown> };
}

export async function verifySlotReceiptV3(
  receipt: SemanticReceiptV3,
  options: VerifySlotReceiptOptionsV2,
): Promise<SlotReceiptVerificationV2> {
  if (!isSlotReceiptV3(receipt) || receipt.encodingVersion !== SLOT_ENCODING_VERSION_V1) {
    return schemaFailure('Receipt is not a semantic-receipt/v3 slot-v1 receipt at encoding version 1.');
  }
  const opened = await openReceiptV3(receipt);
  return verifySlotReceiptCoreV1(receipt, () => opened, options);
}

export async function verifyRecordHistoryV3(
  receipts: SemanticReceiptV3[],
  options: VerifySlotReceiptOptionsV2 & { proofRoots?: Record<string, string> },
): Promise<RecordHistoryCheckV2> {
  const opened = new Map<SemanticReceiptV3, OpenedRecordContentV1>();
  for (const receipt of receipts) {
    if (isSlotReceiptV3(receipt)) opened.set(receipt, await openReceiptV3(receipt));
  }
  return verifyRecordHistoryCoreV1(
    receipts,
    (receipt, opts) => {
      if (!isSlotReceiptV3(receipt) || receipt.encodingVersion !== SLOT_ENCODING_VERSION_V1) {
        return schemaFailure('Receipt is not a semantic-receipt/v3 slot-v1 receipt at encoding version 1.');
      }
      const open = opened.get(receipt) as OpenedRecordContentV1;
      return verifySlotReceiptCoreV1(receipt, () => open, opts);
    },
    options,
  );
}

/** Verifies a receipt of either record hash version. */
export async function verifyRecordReceipt(
  receipt: unknown,
  options: VerifySlotReceiptOptionsV2,
): Promise<SlotReceiptVerificationV2> {
  const schema = (receipt as { schema?: unknown } | null)?.schema;
  if (schema === SEMANTIC_RECEIPT_SCHEMA_V3) return verifySlotReceiptV3(receipt as SemanticReceiptV3, options);
  if (schema === SEMANTIC_RECEIPT_SCHEMA_V2) return verifySlotReceiptV2(receipt as SemanticReceiptV2, options);
  return schemaFailure(unreadableFormReason(schema));
}

function refusedHistory(reason: string): RecordHistoryCheckV2 {
  return {
    complete: false,
    currentSeq: null,
    expectedRecords: null,
    verifiedRecords: 0,
    missingSeq: [],
    failedSeq: [],
    chainBreaks: [{ seq: -1, reason }],
    headMatchesChain: null,
    perReceipt: [],
  };
}

/** Verifies a history of either record hash version; a history of both is refused. */
export async function verifyRecordHistory(
  receipts: unknown[],
  options: VerifySlotReceiptOptionsV2 & { proofRoots?: Record<string, string> },
): Promise<RecordHistoryCheckV2> {
  const schemas = new Set(receipts.map((r) => (r as { schema?: unknown } | null)?.schema));
  for (const schema of schemas) {
    if (schema !== SEMANTIC_RECEIPT_SCHEMA_V2 && schema !== SEMANTIC_RECEIPT_SCHEMA_V3) {
      return refusedHistory(unreadableFormReason(schema));
    }
  }
  if (schemas.size > 1) return refusedHistory(MIXED_VERSIONS);
  if (schemas.has(SEMANTIC_RECEIPT_SCHEMA_V3)) return verifyRecordHistoryV3(receipts as SemanticReceiptV3[], options);
  return verifyRecordHistoryV2(receipts as SemanticReceiptV2[], options);
}

/** A receipt's sealed content for display, of either version; null when it has none that opens. Checking is the verifiers'. */
export function recordContentOfReceipt(receipt: unknown): Record<string, unknown> | null {
  if (!receipt || typeof receipt !== 'object') return null;
  const r = receipt as { schema?: unknown; recordContent?: unknown; revealed?: unknown };
  if (r.schema === SEMANTIC_RECEIPT_SCHEMA_V2) {
    const c = r.recordContent;
    return c && typeof c === 'object' && !Array.isArray(c) ? (c as Record<string, unknown>) : null;
  }
  if (r.schema === SEMANTIC_RECEIPT_SCHEMA_V3 && Array.isArray(r.revealed)) {
    try {
      return recordContentFromLeavesV2(r.revealed.map((l: RevealedLeafV2) => ({ pointer: l?.pointer, value: l?.value })));
    } catch {
      return null;
    }
  }
  return null;
}

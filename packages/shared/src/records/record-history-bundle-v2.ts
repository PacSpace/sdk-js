import { ethers } from 'ethers';
import { canonicalizeJcs } from '../proof/jcs';
import { SEMANTIC_RECEIPT_SCHEMA_V2 } from '../proof/semantic-receipt-v2';
import {
  isSlotReceiptV3,
  recordContentOfReceipt,
  unreadableFormReason,
  verifyRecordHistoryV3,
  type SemanticReceiptV3,
} from '../proof/semantic-receipt-v3';
import {
  RECORD_HISTORY_BUNDLE_SCHEMA_V1,
  applyReferenceRuleV1,
  digestableHistoryBundleV1,
  finishHistoryBundleV1,
  prepareHistoryBundleV1,
  verifyRecordHistoryBundleV1,
  type BundleVerificationV1,
  type RecordHistoryBundleV1,
  type VerifyBundleOptionsV1,
} from './record-history-bundle-v1';

/**
 * record-history-bundle/v2 (ADR 0016): record-history-bundle/v1 for a record
 * created with record hash v2. Its receipts are semantic-receipt/v3; every
 * other member, the digest construction and every check are v1's, and the
 * reference rule reads the content opened from each receipt's leaves.
 */
export const RECORD_HISTORY_BUNDLE_SCHEMA_V2 = 'record-history-bundle/v2' as const;

export interface RecordHistoryBundleV2 extends Omit<RecordHistoryBundleV1, 'schema' | 'receipts'> {
  schema: typeof RECORD_HISTORY_BUNDLE_SCHEMA_V2;
  receipts: SemanticReceiptV3[];
}

export type RecordHistoryBundle = RecordHistoryBundleV1 | RecordHistoryBundleV2;

const MIXED_VERSIONS = 'This history mixes two record hash versions; every entry of a record uses one.';

/** keccak256(utf8(JCS(bundle without digest-ignored status fields))), as computeBundleDigestV1. */
export function computeBundleDigestV2(bundle: RecordHistoryBundleV2): string {
  return ethers.keccak256(
    ethers.toUtf8Bytes(canonicalizeJcs(digestableHistoryBundleV1(bundle as unknown as RecordHistoryBundleV1))),
  );
}

function receiptsRefusalV2(receipts: unknown[]): string | null {
  if (receipts.length === 0) return unreadableFormReason(undefined);
  for (const receipt of receipts) {
    if (isSlotReceiptV3(receipt)) continue;
    const schema = (receipt as { schema?: unknown } | null)?.schema;
    return schema === SEMANTIC_RECEIPT_SCHEMA_V2 ? MIXED_VERSIONS : unreadableFormReason(schema);
  }
  return null;
}

export async function verifyRecordHistoryBundleV2(
  bundle: RecordHistoryBundleV2,
  options: VerifyBundleOptionsV1 = {},
): Promise<BundleVerificationV1> {
  const prepared = prepareHistoryBundleV1(bundle, options, {
    schema: RECORD_HISTORY_BUNDLE_SCHEMA_V2,
    notThisForm: unreadableFormReason((bundle as { schema?: unknown } | null)?.schema),
    receiptsRefusal: receiptsRefusalV2,
    digest: computeBundleDigestV2,
  });
  if (prepared.done) return prepared.done;
  const history = applyReferenceRuleV1(
    bundle.receipts,
    await verifyRecordHistoryV3(bundle.receipts, prepared.historyOptions),
    { layouts: options.layouts, referencedWords: options.referencedWords, contentOf: recordContentOfReceipt },
  );
  return finishHistoryBundleV1(prepared, history);
}

/** Verifies a bundle of either form; any other form is refused by name. */
export async function verifyRecordHistoryBundle(
  bundle: unknown,
  options: VerifyBundleOptionsV1 = {},
): Promise<BundleVerificationV1> {
  const schema = (bundle as { schema?: unknown } | null)?.schema;
  if (schema === RECORD_HISTORY_BUNDLE_SCHEMA_V1) return verifyRecordHistoryBundleV1(bundle as RecordHistoryBundleV1, options);
  if (schema === RECORD_HISTORY_BUNDLE_SCHEMA_V2) return verifyRecordHistoryBundleV2(bundle as RecordHistoryBundleV2, options);
  return { verified: false, schemaOk: false, digestOk: false, layoutDigest: null, layoutOk: false, history: null, reason: unreadableFormReason(schema) };
}

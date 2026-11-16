import { verifyHiddenItemProofV1 } from './hiding-commitment-v1';
import { DecodedState, decodeStateV1 } from './layout-document-v1';
import { LedgerBatchRef, verifyLedgerChainV1 } from './ledger-head-v1';
import { normalizeProofHash } from './merkle-v2';
import { sealInputHash, type SealedRecordHashVersion } from './seal-input';
import {
  LayoutRegistry,
  SLOT_ENCODING_VERSION_V1,
  SLOT_ITEM_KIND_V1,
  checkTransitionRuleV1,
  computeRecordHashV1,
  computeSealV1,
  computeSlotItemHashV1,
  hex256,
  sealTagOfV1,
  splitWordV1,
} from './slot-encoding-v1';

/**
 * semantic-receipt/v2 for slot items (ADR 0012 section 9; slot-encoding-v1
 * section 12). A holder verifies it locally: the sealed record content is
 * recomputed into the seal, the seal tag is compared with the word (the one
 * read from the contract when available), the item is recomputed and folded
 * through its proof path to the published root, and the seq chain and the
 * layout's transition table are re-applied. The receipt never carries the
 * batch seed. A bare word is never accepted as proof of a record.
 */
export const SEMANTIC_RECEIPT_SCHEMA_V2 = 'semantic-receipt/v2';

export interface SemanticReceiptV2 {
  schema: typeof SEMANTIC_RECEIPT_SCHEMA_V2;
  itemKind: typeof SLOT_ITEM_KIND_V1;
  encodingVersion: number;
  derivationVersion: number;
  recordKey: string;
  seq: number;
  previousWord: string;
  newWord: string;
  layoutId: number;
  layoutVersion: number;
  layoutDigest: string;
  recordContent: Record<string, unknown>;
  recordOpening: string;
  itemIndex: number;
  itemOpening: string;
  merkleProof: string[];
  proofRoot: string;
  batchId: number;
  previousHead: string;
  ledgerHead: string;
  /** Non-root handle; never the proof root. */
  receiptId?: string;
}

export type SlotVerificationCheck =
  | 'schema'
  | 'layout'
  | 'state-read'
  | 'semantic'
  | 'chain'
  | 'rule'
  | 'inclusion'
  | 'ledger';

export type SlotVerificationLevel = 'state-read' | 'semantic' | 'ledger';

export interface SlotReceiptVerificationV2 {
  verified: boolean;
  /** Highest level that was evaluated and passed, or null. */
  level: SlotVerificationLevel | null;
  failedCheck: SlotVerificationCheck | null;
  checks: Partial<Record<SlotVerificationCheck, boolean>>;
  decodedState: DecodedState | null;
  recomputedRecordHash: string | null;
  recomputedSeal: string | null;
  recomputedSealTag: string | null;
  expectedSealTag: string | null;
  recomputedItemHash: string | null;
  reason: string;
}

export interface VerifySlotReceiptOptionsV2 {
  layouts: LayoutRegistry;
  /** The word read from the contract for this record key (state-read level). */
  chainWord?: string | bigint;
  /** The batch root read from the contract; the receipt's own root is used when absent. */
  expectedProofRoot?: string;
  /** Ledger material read from the contract (ledger level). */
  ledger?: { genesisHead: string; batches: LedgerBatchRef[]; expectedHead: string };
}

function fail(
  partial: Partial<SlotReceiptVerificationV2>,
  failedCheck: SlotVerificationCheck,
  reason: string,
): SlotReceiptVerificationV2 {
  return {
    verified: false,
    level: null,
    failedCheck,
    checks: {},
    decodedState: null,
    recomputedRecordHash: null,
    recomputedSeal: null,
    recomputedSealTag: null,
    expectedSealTag: null,
    recomputedItemHash: null,
    ...partial,
    reason,
  };
}

export function isSlotReceiptV2(value: unknown): value is SemanticReceiptV2 {
  const r = value as Partial<SemanticReceiptV2> | null;
  return !!r && r.schema === SEMANTIC_RECEIPT_SCHEMA_V2 && r.itemKind === SLOT_ITEM_KIND_V1;
}

export function verifySlotReceiptV2(
  receipt: SemanticReceiptV2,
  options: VerifySlotReceiptOptionsV2,
): SlotReceiptVerificationV2 {
  if (!isSlotReceiptV2(receipt) || receipt.encodingVersion !== SLOT_ENCODING_VERSION_V1) {
    return fail({ checks: { schema: false } }, 'schema', 'Receipt is not a semantic-receipt/v2 slot-v1 receipt at encoding version 1.');
  }
  return verifySlotReceiptCoreV1(receipt, () => openRecordContentV1(receipt.recordContent), options);
}

/** Every member of a slot receipt but its schema and its sealed content (semantic-receipt/v2 and /v3 share them). */
export type SlotReceiptCoreV1 = Omit<SemanticReceiptV2, 'schema' | 'recordContent'>;

/** A receipt's sealed content opened to its record hash, or the semantic step's refusal reason. */
export type OpenedRecordContentV1 =
  | {
      ok: true;
      recordHash: string;
      recordContent: Record<string, unknown>;
      /** 3 only for a hash recomputed under record hash v3 (or a seal-only path claiming no content); the seal is over sealInputHash. */
      sealedVersion?: SealedRecordHashVersion;
    }
  | { ok: false; reason: string };

function openRecordContentV1(recordContent: Record<string, unknown>): OpenedRecordContentV1 {
  try {
    return { ok: true, recordHash: computeRecordHashV1(recordContent), recordContent };
  } catch (error) {
    return { ok: false, reason: `Record content is not canonicalizable: ${(error as Error).message}` };
  }
}

/**
 * The receipt checks after the schema, for either record hash version. The
 * record hash and content are read from `opened` at the semantic step only,
 * so every earlier refusal is the one semantic-receipt/v2 has always given.
 */
export function verifySlotReceiptCoreV1(
  receipt: SlotReceiptCoreV1,
  opened: () => OpenedRecordContentV1,
  options: VerifySlotReceiptOptionsV2,
): SlotReceiptVerificationV2 {
  const checks: Partial<Record<SlotVerificationCheck, boolean>> = { schema: true };

  // layout
  const layout = options.layouts.get(receipt.layoutId);
  if (!layout) {
    checks.layout = false;
    return fail({ checks }, 'layout', `Layout ${receipt.layoutId} is not registered (LAYOUT_NOT_FOUND).`);
  }
  let layoutDigest: string;
  try {
    layoutDigest = normalizeProofHash(receipt.layoutDigest, 'layoutDigest');
  } catch (error) {
    checks.layout = false;
    return fail({ checks }, 'layout', `Receipt layoutDigest is malformed: ${(error as Error).message}`);
  }
  if (layoutDigest !== layout.digest || receipt.layoutVersion !== layout.doc.layoutVersion) {
    checks.layout = false;
    return fail({ checks }, 'layout', 'Receipt layout digest or version does not match the published layout document.');
  }
  checks.layout = true;

  // words
  let receiptWord: bigint;
  let previousWord: bigint;
  try {
    receiptWord = BigInt(receipt.newWord);
    previousWord = BigInt(receipt.previousWord);
  } catch {
    checks.schema = false;
    return fail({ checks }, 'schema', 'Receipt words are not integers.');
  }
  const receiptSplit = splitWordV1(receiptWord);
  const decodedState = decodeStateV1(layout.doc, receiptSplit.state96);

  // state-read: the public state on chain agrees with the receipt
  let targetWord = receiptWord;
  if (options.chainWord !== undefined) {
    const chainSplit = splitWordV1(BigInt(options.chainWord));
    if (chainSplit.state96 !== receiptSplit.state96) {
      checks['state-read'] = false;
      return fail(
        { checks, decodedState },
        'state-read',
        'The public state read from the contract differs from the state in the receipt.',
      );
    }
    checks['state-read'] = true;
    targetWord = BigInt(options.chainWord);
  }
  const expectedSealTag = splitWordV1(targetWord).sealTag;

  // semantic: recompute recordHash -> seal -> sealTag and compare with the word
  const open = opened();
  if (!open.ok) {
    checks.semantic = false;
    return fail({ checks, decodedState, expectedSealTag }, 'semantic', open.reason);
  }
  const recomputedRecordHash = open.recordHash;
  const recomputedSeal = computeSealV1({
    layoutId: receipt.layoutId,
    layoutVersion: receipt.layoutVersion,
    layoutDigest,
    state96: receiptSplit.state96,
    recordHash: sealInputHash(open.sealedVersion ?? 1, recomputedRecordHash),
    recordOpening: receipt.recordOpening,
  });
  const recomputedSealTag = sealTagOfV1(recomputedSeal);
  const base = { checks, decodedState, recomputedRecordHash, recomputedSeal, recomputedSealTag, expectedSealTag };
  if (recomputedSealTag !== expectedSealTag || recomputedSealTag !== receiptSplit.sealTag) {
    checks.semantic = false;
    return fail(base, 'semantic', 'The sealed record does not recompute to the seal tag carried by the word.');
  }
  checks.semantic = true;

  // chain: seq follows the previous word
  if (previousWord === 0n) {
    if (receipt.seq !== 0) {
      checks.chain = false;
      return fail(base, 'chain', 'A record with a zero previous word must be seq 0.');
    }
  } else {
    const prevSplit = splitWordV1(previousWord);
    if (prevSplit.layoutId !== receipt.layoutId) {
      checks.chain = false;
      return fail(base, 'chain', 'The previous word belongs to a different layout.');
    }
    const prevState = decodeStateV1(layout.doc, prevSplit.state96);
    if (Number(prevState.seq) + 1 !== receipt.seq) {
      checks.chain = false;
      return fail(base, 'chain', `The previous word is seq ${prevState.seq}; the receipt claims seq ${receipt.seq}.`);
    }
  }
  if (Number(decodedState.seq) !== receipt.seq) {
    checks.chain = false;
    return fail(base, 'chain', 'The seq in the public state differs from the receipt seq.');
  }
  checks.chain = true;

  // rule: re-apply the layout's transition table
  const rule = checkTransitionRuleV1(layout.doc, {
    previousWord,
    newWord: receiptWord,
    recordContent: open.recordContent,
  });
  if (!rule.ok) {
    checks.rule = false;
    return fail(base, 'rule', `Transition rule recompute failed: ${rule.reason}`);
  }
  checks.rule = true;

  // inclusion: item hash -> hidden leaf -> proof path -> root
  const recomputedItemHash = computeSlotItemHashV1({
    recordKey: receipt.recordKey,
    seq: receipt.seq,
    previousWord,
    newWord: receiptWord,
    seal: recomputedSeal,
  });
  const root = options.expectedProofRoot ?? receipt.proofRoot;
  let included = false;
  try {
    included = verifyHiddenItemProofV1({
      itemHash: recomputedItemHash,
      itemIndex: receipt.itemIndex,
      itemOpening: receipt.itemOpening,
      proof: receipt.merkleProof,
      expectedRoot: root,
    });
  } catch {
    included = false;
  }
  if (!included) {
    checks.inclusion = false;
    return fail({ ...base, recomputedItemHash }, 'inclusion', 'The recomputed item does not fold to the published root.');
  }
  checks.inclusion = true;

  // ledger (optional)
  let level: SlotVerificationLevel = 'semantic';
  if (options.ledger) {
    const ledger = verifyLedgerChainV1({
      genesisHead: options.ledger.genesisHead,
      batches: options.ledger.batches,
      expectedHead: options.ledger.expectedHead,
      receipt: { batchId: receipt.batchId, proofRoot: root },
    });
    checks.ledger = ledger.verified;
    if (!ledger.verified) {
      return fail({ ...base, recomputedItemHash }, 'ledger', `Ledger level failed: ${ledger.reason}`);
    }
    level = 'ledger';
  }

  return {
    verified: true,
    level,
    failedCheck: null,
    checks,
    decodedState,
    recomputedRecordHash,
    recomputedSeal,
    recomputedSealTag,
    expectedSealTag,
    recomputedItemHash,
    reason:
      level === 'ledger'
        ? 'Sealed record, public state, position, root, and ledger chain all recompute.'
        : 'Sealed record recomputes to the seal tag on the word and folds to the published root.',
  };
}

// ----------------------------------------------------------------- history

export interface RecordHistoryCheckV2 {
  complete: boolean;
  currentSeq: number | null;
  expectedRecords: number | null;
  verifiedRecords: number;
  missingSeq: number[];
  failedSeq: number[];
  chainBreaks: Array<{ seq: number; reason: string }>;
  headMatchesChain: boolean | null;
  perReceipt: Array<{ seq: number; result: SlotReceiptVerificationV2 }>;
}

/**
 * Verify a set of receipts for one record key as a history: each receipt on
 * its own, the previousWord chain between presented neighbours, and
 * completeness against the word read from the contract (seq gaps are
 * reported as INCOMPLETE, never as failure of the presented records).
 */
export function verifyRecordHistoryV2(
  receipts: SemanticReceiptV2[],
  options: VerifySlotReceiptOptionsV2 & { proofRoots?: Record<string, string> },
): RecordHistoryCheckV2 {
  return verifyRecordHistoryCoreV1(receipts, verifySlotReceiptV2, options);
}

/** verifyRecordHistoryV2's history checks, with each receipt verified by `verifyOne`. */
export function verifyRecordHistoryCoreV1<R extends SlotReceiptCoreV1>(
  receipts: R[],
  verifyOne: (receipt: R, options: VerifySlotReceiptOptionsV2) => SlotReceiptVerificationV2,
  options: VerifySlotReceiptOptionsV2 & { proofRoots?: Record<string, string> },
): RecordHistoryCheckV2 {
  const sorted = [...receipts].sort((a, b) => a.seq - b.seq);
  const perReceipt: RecordHistoryCheckV2['perReceipt'] = [];
  const failedSeq: number[] = [];
  const chainBreaks: RecordHistoryCheckV2['chainBreaks'] = [];
  const keys = new Set(sorted.map((r) => r.recordKey.toLowerCase()));
  if (keys.size > 1) {
    chainBreaks.push({ seq: -1, reason: 'receipts belong to more than one record key' });
  }

  let currentSeq: number | null = null;
  let headMatchesChain: boolean | null = null;
  if (options.chainWord !== undefined && sorted.length > 0) {
    const layout = options.layouts.get(sorted[0].layoutId);
    if (layout) {
      const split = splitWordV1(BigInt(options.chainWord));
      currentSeq = Number(decodeStateV1(layout.doc, split.state96).seq);
    }
  }

  for (let i = 0; i < sorted.length; i += 1) {
    const r = sorted[i];
    // Only the receipt at the current seq is compared against the chain word.
    const isHead = currentSeq !== null && r.seq === currentSeq;
    const result = verifyOne(r, {
      layouts: options.layouts,
      chainWord: isHead ? options.chainWord : undefined,
      expectedProofRoot: options.proofRoots?.[String(r.batchId)],
      ledger: options.ledger,
    });
    if (isHead) headMatchesChain = result.verified && hex256(BigInt(options.chainWord as string | bigint)) === hex256(BigInt(r.newWord));
    perReceipt.push({ seq: r.seq, result });
    if (!result.verified) failedSeq.push(r.seq);
    const prev = sorted[i - 1];
    if (prev && prev.seq === r.seq - 1 && hex256(BigInt(prev.newWord)) !== hex256(BigInt(r.previousWord))) {
      chainBreaks.push({ seq: r.seq, reason: `previousWord does not equal the newWord of seq ${prev.seq}` });
    }
    if (prev && prev.seq === r.seq) {
      chainBreaks.push({ seq: r.seq, reason: 'duplicate seq presented' });
    }
  }

  const presented = new Set(sorted.map((r) => r.seq));
  const maxSeq = currentSeq ?? (sorted.length ? sorted[sorted.length - 1].seq : -1);
  const missingSeq: number[] = [];
  for (let s = 0; s <= maxSeq; s += 1) if (!presented.has(s)) missingSeq.push(s);

  const verifiedRecords = perReceipt.filter((p) => p.result.verified).length;
  const expectedRecords = currentSeq === null ? null : currentSeq + 1;
  const complete =
    missingSeq.length === 0 &&
    failedSeq.length === 0 &&
    chainBreaks.length === 0 &&
    (currentSeq === null || headMatchesChain === true);

  return {
    complete,
    currentSeq,
    expectedRecords,
    verifiedRecords,
    missingSeq,
    failedSeq,
    chainBreaks,
    headMatchesChain,
    perReceipt,
  };
}

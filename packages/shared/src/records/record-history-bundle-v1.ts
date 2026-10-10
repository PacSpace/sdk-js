import { ethers } from 'ethers';
import { canonicalizeJcs } from '../proof/jcs';
import { LayoutDocumentV1, computeLayoutDigestV1, validateLayoutDocumentV1 } from '../proof/layout-document-v1';
import { LedgerBatchRef } from '../proof/ledger-head-v1';
import {
  RecordHistoryCheckV2,
  SemanticReceiptV2,
  SlotReceiptCoreV1,
  SlotReceiptVerificationV2,
  isSlotReceiptV2,
  verifyRecordHistoryV2,
} from '../proof/semantic-receipt-v2';
import { LayoutRegistry, buildLayoutRegistry, splitWordV1 } from '../proof/slot-encoding-v1';
import { isAdjustsRefV1, isRecordRefV1 } from './record-content-v1';
import { RecordRef, resolveRecordRefV1 } from './model-record-link-v1';

/**
 * record-history-bundle/v1: everything a relying party needs to verify one
 * record's history offline, in a single file a holder can hand over. The
 * bundle carries the layout document (so the verifier does not need to
 * trust PacSpace's copy), every receipt for the record key, and, when the
 * holder chose to include it, the ledger material read from the contract at
 * export time. It never carries a batch seed.
 */
export const RECORD_HISTORY_BUNDLE_SCHEMA_V1 = 'record-history-bundle/v1';

export interface RecordHistoryBundleV1 {
  schema: typeof RECORD_HISTORY_BUNDLE_SCHEMA_V1;
  recordKey: string;
  chain: {
    chainId: number;
    contractAddress: string;
  };
  layout: LayoutDocumentV1;
  /** The word read from the contract at export time, if the holder read it. */
  currentWord?: string;
  receipts: SemanticReceiptV2[];
  /** Ledger material at export time; the verifier may replace it with a live read. */
  ledger?: {
    genesisHead: string;
    head: string;
    batches: LedgerBatchRef[];
  };
  /** Batch roots at export time keyed by batchId (decimal string). */
  batchRoots?: Record<string, string>;
  /**
   * The latest per-tenant ledger statement at or before export (ADR 0012
   * addition 4). An offline verifier compares the recomputed head to this
   * line when no chain reader is available.
   */
  ledgerStatement?: LedgerStatementRefV1;
  exportedAt?: string;
  /**
   * keccak256 of the JCS form of every other field of the bundle. Present on
   * bundles the API issues; a verifier that finds it recomputes it first.
   */
  bundleDigest?: string;
  /**
   * Queued or failed writes that are not yet receipts (Slice C5). Outside
   * the sealed history; the digest and verifier ignore this field.
   */
  pendingEntries?: RecordHistoryPendingEntryV1[];
  /**
   * Status view of committed receipts plus pending writes. Outside the
   * sealed history; the digest and verifier ignore this field.
   */
  entries?: RecordHistoryEntryV1[];
  /**
   * Pagination cursor copied from X-Next-From-Seq. The API keeps it off the
   * issued bundle body; the SDK may attach it. Outside the sealed history.
   */
  nextFromSeq?: number | null;
}

export type RecordHistoryEntryStatusV1 = 'queued' | 'committed' | 'failed';

export interface RecordHistoryPendingEntryV1 {
  seq: number | null;
  status: 'queued' | 'failed';
  code?: string;
  sentence?: string;
  receiptId?: string;
}

export interface RecordHistoryEntryV1 {
  seq: number | null;
  status: RecordHistoryEntryStatusV1;
  code?: string;
  sentence?: string;
  receiptId?: string;
}

const DIGEST_IGNORED_BUNDLE_KEYS = new Set(['bundleDigest', 'pendingEntries', 'entries', 'nextFromSeq']);
const DIGEST_IGNORED_RECEIPT_KEYS = new Set(['status', 'code', 'sentence']);

/** Bundle fields the digest and verifier ignore (status lives outside sealed content). */
export function digestableHistoryBundleV1(bundle: RecordHistoryBundleV1): Record<string, unknown> {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(bundle as unknown as Record<string, unknown>)) {
    if (DIGEST_IGNORED_BUNDLE_KEYS.has(key)) continue;
    rest[key] = value;
  }
  const receipts = Array.isArray(rest.receipts) ? rest.receipts : [];
  rest.receipts = receipts.map((receipt) => {
    if (!receipt || typeof receipt !== 'object') return receipt;
    const stripped: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(receipt as Record<string, unknown>)) {
      if (DIGEST_IGNORED_RECEIPT_KEYS.has(key)) continue;
      stripped[key] = value;
    }
    return stripped;
  });
  return rest;
}

export interface LedgerStatementRefV1 {
  /** UTC calendar date the statement is for (YYYY-MM-DD). */
  statementDate: string;
  asOfBatchId: number;
  ledgerHead: string;
  blockNumber: number;
  blockTime: string;
}

/** keccak256(utf8(JCS(bundle without digest-ignored status fields))). */
export function computeBundleDigestV1(bundle: RecordHistoryBundleV1): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalizeJcs(digestableHistoryBundleV1(bundle))));
}

export interface BundleVerificationV1 {
  verified: boolean;
  schemaOk: boolean;
  /** True when the bundle carries no digest or the digest recomputes. */
  digestOk: boolean;
  layoutDigest: string | null;
  layoutOk: boolean;
  history: RecordHistoryCheckV2 | null;
  reason: string;
}

export interface VerifyBundleOptionsV1 {
  /** Override the bundle's current word with a live read from the contract. */
  chainWord?: string | bigint;
  /** Override the bundle's ledger material with a live read. */
  ledger?: { genesisHead: string; batches: LedgerBatchRef[]; expectedHead: string };
  /** Override the bundle's batch roots with live reads. */
  batchRoots?: Record<string, string>;
  /**
   * Registry to check the bundled layout against. When supplied, the bundled
   * document must match the registry entry with the same layoutId. It also
   * decodes the words of referenced records (`referencedWords`).
   */
  layouts?: LayoutRegistry;
  /**
   * Word histories of records this record's entries reference, keyed by
   * record key (`words[i]` is the word at seq i). When an `amends` names an
   * entry of another record and that record's words are here, the D17 rule
   * checks that the record is closed; without them the cross-record case is
   * admitted on the references[] check alone.
   */
  referencedWords?: Record<string, Array<string | bigint>>;
}

export const LINK_TARGET_UNKNOWN = 'LINK_TARGET_UNKNOWN';
export const LINK_TARGET_NOT_COMMITTED = 'LINK_TARGET_NOT_COMMITTED';
export const LINK_TARGET_NOT_PRECEDING = 'LINK_TARGET_NOT_PRECEDING';

export type LinkedEntryReasonCodeV1 =
  | typeof LINK_TARGET_UNKNOWN
  | typeof LINK_TARGET_NOT_COMMITTED
  | typeof LINK_TARGET_NOT_PRECEDING;

/**
 * Outcome of the D17 reference rule for one presented entry. Failures carry
 * a structured code; the history still reports `failedCheck: 'rule'`.
 */
export interface LinkedEntryCheckV1 {
  ok: boolean;
  reason: string | null;
  code: LinkedEntryReasonCodeV1 | null;
}

export type ReferenceRuleCheckV1 = LinkedEntryCheckV1;

export interface ReferenceRuleContextV1<R extends SlotReceiptCoreV1 = SemanticReceiptV2> {
  /** Every receipt presented for the record, in any order. */
  presented: R[];
  layouts?: LayoutRegistry;
  referencedWords?: Record<string, Array<string | bigint>>;
  /** A receipt's sealed content; `recordContent` when absent (semantic-receipt/v2). */
  contentOf?: (receipt: R) => Record<string, unknown> | null | undefined;
}

function contentOfV1<R extends SlotReceiptCoreV1>(receipt: R, context: { contentOf?: (receipt: R) => Record<string, unknown> | null | undefined }) {
  return context.contentOf ? context.contentOf(receipt) : (receipt as unknown as SemanticReceiptV2).recordContent;
}

function sameKey(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/**
 * The D17 rule (records buyer posture plan, D17; DfD-42 (A)): `amends` on
 * machine-action-record/v1 and `adjusts` on balance-account/v2 are checked by
 * one rule, at the `rule` level of the referencing entry, so a bad reference
 * reports `failedCheck: 'rule'` exactly like a forbidden transition.
 *
 *   amends { recordKey, seq }
 *     same record:  the named seq precedes this entry. A named entry that is
 *                   not presented is a completeness gap (INCOMPLETE), never a
 *                   failure of this entry.
 *     other record: this entry also names that entry in references[], and,
 *                   when that record's words are at hand, the record is
 *                   closed (its latest word is a terminal state).
 *   adjusts { referenceId } | { recordId }
 *     { referenceId }: an earlier presented entry of this record carries that
 *                      referenceId; when none does and no earlier seq is
 *                      missing, the reference is bad. An entry that carries
 *                      it only at or after this seq does not precede.
 *     { recordId }:    the record id is PacSpace's handle for the earlier
 *                      delta and is not sealed content, so the verifier
 *                      checks the shape and leaves the lookup to intake.
 */
export function verifyLinkedEntryV1<R extends SlotReceiptCoreV1 = SemanticReceiptV2>(
  receipt: R,
  context: ReferenceRuleContextV1<R>,
): LinkedEntryCheckV1 {
  const content = contentOfV1(receipt, context) ?? {};
  const pass = (): LinkedEntryCheckV1 => ({ ok: true, reason: null, code: null });
  const fail = (code: LinkedEntryReasonCodeV1, reason: string): LinkedEntryCheckV1 => ({ ok: false, reason, code });

  if ('amends' in content && content.amends !== undefined) {
    const amends = content.amends;
    if (!isRecordRefV1(amends)) return fail(LINK_TARGET_UNKNOWN, 'amends is not { recordKey, seq }.');
    if (sameKey(amends.recordKey, receipt.recordKey)) {
      if (amends.seq >= receipt.seq) {
        return fail(
          LINK_TARGET_NOT_PRECEDING,
          `amends names seq ${amends.seq}, which does not precede this entry (seq ${receipt.seq}).`,
        );
      }
    } else {
      const references = Array.isArray(content.references) ? content.references : [];
      const named = references.some((r) => isRecordRefV1(r) && sameKey(r.recordKey, amends.recordKey) && r.seq === amends.seq);
      if (!named) {
        return fail(LINK_TARGET_UNKNOWN, 'amends names an entry of another record that this entry does not carry in references[].');
      }
      const words = context.referencedWords?.[amends.recordKey.toLowerCase()] ?? context.referencedWords?.[amends.recordKey];
      if (words && words.length > 0 && context.layouts) {
        const layout = context.layouts.get(splitWordV1(words[words.length - 1]).layoutId);
        if (!layout) return fail(LINK_TARGET_UNKNOWN, 'The referenced record is under a layout this verifier does not know.');
        const resolved = resolveRecordRefV1(layout, words, amends as RecordRef);
        if (!resolved.found) {
          return fail(
            LINK_TARGET_UNKNOWN,
            `amends names seq ${amends.seq} of a record whose history at hand has ${resolved.entries} entries.`,
          );
        }
        const latest = resolveRecordRefV1(layout, words, { recordKey: amends.recordKey, seq: words.length - 1 });
        if (latest.terminal !== true) {
          return fail(
            LINK_TARGET_NOT_COMMITTED,
            `amends names an entry of another record that is not closed (${latest.lifecycle ?? 'unknown'}).`,
          );
        }
      }
    }
  }

  if ('adjusts' in content && content.adjusts !== undefined) {
    const adjusts = content.adjusts;
    if (!isAdjustsRefV1(adjusts)) return fail(LINK_TARGET_UNKNOWN, 'adjusts is not { referenceId } or { recordId }.');
    if ('referenceId' in adjusts) {
      const carriers = context.presented.filter(
        (r) => sameKey(r.recordKey, receipt.recordKey) && r.seq !== receipt.seq && contentOfV1(r, context)?.referenceId === adjusts.referenceId,
      );
      if (carriers.some((r) => r.seq < receipt.seq)) return pass();
      if (carriers.length > 0) {
        return fail(
          LINK_TARGET_NOT_PRECEDING,
          `adjusts names referenceId ${adjusts.referenceId}, which only a later entry of this record carries.`,
        );
      }
      const presentedSeqs = new Set(context.presented.map((r) => r.seq));
      let gapBelow = false;
      for (let s = 0; s < receipt.seq; s += 1) if (!presentedSeqs.has(s)) gapBelow = true;
      if (!gapBelow) {
        return fail(
          LINK_TARGET_UNKNOWN,
          `adjusts names referenceId ${adjusts.referenceId}, which no earlier entry of this record carries.`,
        );
      }
    }
  }

  return pass();
}

/** Slice B name. Same rule as `verifyLinkedEntryV1`. */
export const checkReferenceRuleV1 = verifyLinkedEntryV1;

/**
 * Apply the D17 rule to a verified history. A rule failure is reported on the
 * referencing entry as `failedCheck: 'rule'`; an entry that already failed an
 * earlier check (schema, layout, state-read, semantic, chain) keeps that
 * report, since the ruled order puts those checks first.
 */
export function applyReferenceRuleV1<R extends SlotReceiptCoreV1 = SemanticReceiptV2>(
  receipts: R[],
  history: RecordHistoryCheckV2,
  context: Omit<ReferenceRuleContextV1<R>, 'presented'>,
): RecordHistoryCheckV2 {
  const bySeq = new Map(receipts.map((r) => [r.seq, r] as const));
  const failedSeq = [...history.failedSeq];
  let changed = false;
  const perReceipt = history.perReceipt.map((entry) => {
    const receipt = bySeq.get(entry.seq);
    if (!receipt) return entry;
    const rule = verifyLinkedEntryV1(receipt, { ...context, presented: receipts });
    if (rule.ok) return entry;
    const earlierFailure = !entry.result.verified && entry.result.checks.rule !== true;
    if (earlierFailure) return entry;
    changed = true;
    if (!failedSeq.includes(entry.seq)) failedSeq.push(entry.seq);
    const result: SlotReceiptVerificationV2 = {
      ...entry.result,
      verified: false,
      level: null,
      failedCheck: 'rule',
      checks: { ...entry.result.checks, rule: false },
      reason: rule.reason ?? 'The entry fails the reference rule.',
    };
    return { seq: entry.seq, result };
  });
  if (!changed) return history;
  failedSeq.sort((a, b) => a - b);
  return {
    ...history,
    perReceipt,
    failedSeq,
    verifiedRecords: perReceipt.filter((p) => p.result.verified).length,
    complete: false,
  };
}

export function verifyRecordHistoryBundleV1(
  bundle: RecordHistoryBundleV1,
  options: VerifyBundleOptionsV1 = {},
): BundleVerificationV1 {
  const prepared = prepareHistoryBundleV1(bundle, options, {
    schema: RECORD_HISTORY_BUNDLE_SCHEMA_V1,
    notThisForm: 'Not a record-history-bundle/v1.',
    receiptsRefusal: (receipts) => (receipts.length > 0 && receipts.every(isSlotReceiptV2) ? null : 'Bundle receipts must be semantic-receipt/v2 slot-v1 receipts.'),
    digest: computeBundleDigestV1,
  });
  if (prepared.done) return prepared.done;
  const history = applyReferenceRuleV1(
    bundle.receipts,
    verifyRecordHistoryV2(bundle.receipts, prepared.historyOptions),
    { layouts: options.layouts, referencedWords: options.referencedWords },
  );
  return finishHistoryBundleV1(prepared, history);
}

/** How one bundle form names itself and its receipts (record-history-bundle/v1 and /v2 share every other check). */
export interface HistoryBundleFormV1 {
  schema: string;
  notThisForm: string;
  /** The refusal for the bundle's receipts, or null when every receipt is this form's. */
  receiptsRefusal: (receipts: unknown[]) => string | null;
  digest: (bundle: never) => string;
}

export type PreparedHistoryBundleV1 =
  | { done: BundleVerificationV1 }
  | {
      done: null;
      layoutDigest: string;
      chainWord: string | bigint | undefined;
      historyOptions: {
        layouts: LayoutRegistry;
        chainWord: string | bigint | undefined;
        ledger: { genesisHead: string; batches: LedgerBatchRef[]; expectedHead: string } | undefined;
        proofRoots: Record<string, string> | undefined;
      };
    };

/** Every bundle check before the history: schema, receipts, digest, record key and layout. */
export function prepareHistoryBundleV1(
  bundle: Omit<RecordHistoryBundleV1, 'schema' | 'receipts'> & { schema: string; receipts: unknown[] },
  options: VerifyBundleOptionsV1,
  form: HistoryBundleFormV1,
): PreparedHistoryBundleV1 {
  if (!bundle || bundle.schema !== form.schema || !Array.isArray(bundle.receipts)) {
    return { done: { verified: false, schemaOk: false, digestOk: false, layoutDigest: null, layoutOk: false, history: null, reason: form.notThisForm } };
  }
  const digest = form.digest as (bundle: unknown) => string;
  const pendingEntries = Array.isArray(bundle.pendingEntries) ? bundle.pendingEntries : [];
  if (bundle.receipts.length === 0) {
    if (pendingEntries.length === 0) {
      return { done: { verified: false, schemaOk: false, digestOk: false, layoutDigest: null, layoutOk: false, history: null, reason: form.receiptsRefusal([]) as string } };
    }
    const digestOk =
      bundle.bundleDigest === undefined ||
      digest(bundle).toLowerCase() === String(bundle.bundleDigest).toLowerCase();
    return {
      done: {
        verified: false,
        schemaOk: true,
        digestOk,
        layoutDigest: null,
        layoutOk: false,
        history: null,
        reason: 'No committed entries. Pending or failed writes are listed outside the sealed history.',
      },
    };
  }
  const receiptsRefusal = form.receiptsRefusal(bundle.receipts);
  if (receiptsRefusal !== null) {
    return { done: { verified: false, schemaOk: false, digestOk: false, layoutDigest: null, layoutOk: false, history: null, reason: receiptsRefusal } };
  }
  if (bundle.bundleDigest !== undefined && digest(bundle).toLowerCase() !== String(bundle.bundleDigest).toLowerCase()) {
    return { done: { verified: false, schemaOk: true, digestOk: false, layoutDigest: null, layoutOk: false, history: null, reason: 'Bundle digest does not match the bundle contents.' } };
  }
  const key = bundle.recordKey.toLowerCase();
  if (!(bundle.receipts as SlotReceiptCoreV1[]).every((r) => r.recordKey.toLowerCase() === key)) {
    return { done: { verified: false, schemaOk: false, digestOk: true, layoutDigest: null, layoutOk: false, history: null, reason: 'Bundle receipts do not all belong to the bundle record key.' } };
  }

  let layoutDigest: string;
  try {
    validateLayoutDocumentV1(bundle.layout);
    layoutDigest = computeLayoutDigestV1(bundle.layout);
  } catch (error) {
    return { done: { verified: false, schemaOk: true, digestOk: true, layoutDigest: null, layoutOk: false, history: null, reason: `Bundled layout is invalid: ${(error as Error).message}` } };
  }
  if (options.layouts) {
    const published = options.layouts.get(bundle.layout.layoutId);
    if (!published || published.digest !== layoutDigest) {
      return { done: { verified: false, schemaOk: true, digestOk: true, layoutDigest, layoutOk: false, history: null, reason: 'Bundled layout does not match the published layout with the same id.' } };
    }
  }

  const registry = buildLayoutRegistry([bundle.layout]);
  const chainWord = options.chainWord ?? bundle.currentWord;
  const ledger =
    options.ledger ??
    (bundle.ledger
      ? { genesisHead: bundle.ledger.genesisHead, batches: bundle.ledger.batches, expectedHead: bundle.ledger.head }
      : undefined);
  return {
    done: null,
    layoutDigest,
    chainWord,
    historyOptions: { layouts: registry, chainWord, ledger, proofRoots: options.batchRoots ?? bundle.batchRoots },
  };
}

/** The bundle result from a history with the reference rule applied. */
export function finishHistoryBundleV1(
  prepared: Extract<PreparedHistoryBundleV1, { done: null }>,
  history: RecordHistoryCheckV2,
): BundleVerificationV1 {
  const { layoutDigest, chainWord } = prepared;
  const verified = history.complete;
  return {
    verified,
    schemaOk: true,
    digestOk: true,
    layoutDigest,
    layoutOk: true,
    history,
    reason: verified
      ? `All ${history.verifiedRecords} records verify and the history is complete${chainWord !== undefined ? ' against the current word' : ''}.`
      : history.missingSeq.length
        ? `INCOMPLETE: seq ${history.missingSeq.join(', ')} not presented.`
        : history.failedSeq.length
          ? `Records at seq ${history.failedSeq.join(', ')} do not verify.`
          : history.chainBreaks.length
            ? history.chainBreaks.map((c) => `seq ${c.seq}: ${c.reason}`).join('; ')
            : 'The latest presented record does not match the current word.',
  };
}

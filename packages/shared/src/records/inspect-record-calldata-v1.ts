/**
 * Record-lane transaction inspection, shared by the API, the browser views,
 * and `scripts/records/inspect-calldata.mjs`.
 *
 * One implementation decodes a `writeRecordBatchAndCommit` transaction input
 * into per-record rows (public state decoded under the published layout, and
 * the seal), and recomputes each seal from a disclosed record (a
 * `semantic-receipt/v2`) so that a viewer can see, per record, whether
 * "the sealed record reproduces this seal".
 *
 * Nothing here talks to PacSpace: the transaction input comes from a public
 * mirror node (or is passed in), and the receipt is the holder's own copy.
 */
import {
  computeRecordHashV1,
  computeSealV1,
  decodeWordV1,
  decodeWriteRecordBatchCalldataV1,
  sealTagOfV1,
  splitWordV1,
  type LayoutRegistry,
} from '../proof/slot-encoding-v1';
import { SEMANTIC_RECEIPT_SCHEMA_V2, type SemanticReceiptV2 } from '../proof/semantic-receipt-v2';
import { SEMANTIC_RECEIPT_SCHEMA_V3, type RecordReceipt, type SemanticReceiptV3 } from '../proof/semantic-receipt-v3';
import { openRecordEntryV2 } from '../records-crypto/record-hash-v2';
import { SEMANTIC_RECEIPT_SCHEMA_V4, type SemanticReceiptV4 } from './record-history-bundle-v3';
import { getPublishedLayoutRegistry } from './layouts';

/** Public mirror nodes by chain id; never a PacSpace endpoint. */
export const MIRROR_NODE_BY_CHAIN: Readonly<Record<number, string>> = Object.freeze({
  296: 'https://testnet.mirrornode.hedera.com',
  295: 'https://mainnet-public.mirrornode.hedera.com',
});

export type DecodedRecordState = Record<string, string | string[]>;

export interface InspectedRecordV1 {
  itemIndex: number;
  recordKey: string;
  /** The word the writer expected to find before this write. */
  expectedWord: string;
  /** The word written by this transaction. */
  newWord: string;
  layoutId: number;
  layoutVersion: number;
  layoutName: string | null;
  /** Public state decoded under the published layout; null when the layout is unknown. */
  state: DecodedRecordState | null;
  /** Lower-case 0x + 40 hex; the public seal. */
  sealTag: string;
  decodeError: string | null;
}

export interface RecordCalldataInspectionV1 {
  selector: string;
  functionSignature: string;
  encodingVersion: number;
  itemCount: number;
  proofRoot: string;
  records: InspectedRecordV1[];
}

export type SealComparisonVerdict = 'MATCH' | 'MISMATCH' | 'NOT_IN_TRANSACTION';

export interface SealComparisonV1 {
  itemIndex: number | null;
  recordKey: string;
  seq: number | null;
  sealTagInTransaction: string | null;
  recomputedSealTag: string | null;
  verdict: SealComparisonVerdict;
  reason: string | null;
}

export interface MirrorTransactionInputV1 {
  txHash: string;
  chainId: number | null;
  mirror: string;
  to: string | null;
  from: string | null;
  blockNumber: number | null;
  timestamp: string | null;
  status: string | null;
  calldata: string;
}

function normalizeState(state: Record<string, unknown> | null | undefined): DecodedRecordState {
  const out: DecodedRecordState = {};
  for (const [key, value] of Object.entries(state ?? {})) {
    if (typeof value === 'bigint') out[key] = value.toString();
    else if (Array.isArray(value)) out[key] = value.map((x) => (typeof x === 'bigint' ? x.toString() : String(x)));
    else out[key] = String(value);
  }
  return out;
}

/** Decode a record-lane transaction input into per-record rows with the public state and the seal. */
export function inspectRecordCalldataV1(
  calldata: string,
  registry: LayoutRegistry = getPublishedLayoutRegistry(),
): RecordCalldataInspectionV1 {
  const decoded = decodeWriteRecordBatchCalldataV1(calldata);
  const records = decoded.recordKeys.map((recordKey, itemIndex): InspectedRecordV1 => {
    const expectedWord = decoded.expectedWords[itemIndex];
    const newWord = decoded.newWords[itemIndex];
    const split = splitWordV1(newWord);
    let layoutName: string | null = null;
    let state: DecodedRecordState | null = null;
    let decodeError: string | null = null;
    try {
      const d = decodeWordV1(registry, newWord);
      layoutName = d.layout.doc.name ?? null;
      state = normalizeState(d.decodedState);
    } catch (error) {
      const e = error as { code?: string; message?: string };
      decodeError = e.code ?? e.message ?? 'decode failed';
    }
    return {
      itemIndex,
      recordKey: recordKey.toLowerCase(),
      expectedWord,
      newWord,
      layoutId: split.layoutId,
      layoutVersion: split.layoutVersion,
      layoutName,
      state,
      sealTag: split.sealTag.toLowerCase(),
      decodeError,
    };
  });
  return {
    selector: decoded.selector,
    functionSignature: decoded.functionSignature,
    encodingVersion: decoded.encodingVersion,
    itemCount: decoded.itemCount,
    proofRoot: decoded.merkleRoot,
    records,
  };
}

/** Accept one receipt, an array, a record-history-bundle/v1, or the receipt-proofs response. */
export function collectSemanticReceiptsV2(doc: unknown): SemanticReceiptV2[] {
  if (Array.isArray(doc)) return doc.flatMap((d) => collectSemanticReceiptsV2(d));
  if (!doc || typeof doc !== 'object') return [];
  const obj = doc as Record<string, unknown>;
  if (obj.schema === SEMANTIC_RECEIPT_SCHEMA_V2) return [obj as unknown as SemanticReceiptV2];
  if (Array.isArray(obj.receipts)) return obj.receipts.flatMap((d) => collectSemanticReceiptsV2(d));
  if (Array.isArray(obj.proofs)) return obj.proofs.flatMap((d) => collectSemanticReceiptsV2(d));
  if (obj.data && typeof obj.data === 'object') return collectSemanticReceiptsV2(obj.data);
  return [];
}

/**
 * Recompute the seal from a disclosed record and compare it with the seal in
 * the word the transaction wrote. The batch seed is never needed: the record
 * opening in the receipt is enough to reproduce the seal.
 */
export function recomputeSealTagFromReceiptV2(receipt: SemanticReceiptV2): string {
  const word = String(receipt.newWord);
  const recordHash = computeRecordHashV1(receipt.recordContent);
  const seal = computeSealV1({
    layoutId: Number(receipt.layoutId),
    layoutVersion: Number(receipt.layoutVersion),
    layoutDigest: receipt.layoutDigest,
    state96: splitWordV1(word).state96,
    recordHash,
    recordOpening: receipt.recordOpening,
  });
  return sealTagOfV1(seal).toLowerCase();
}

/** Accept one receipt of either form, an array, a record-history-bundle/v1 or /v2, or the receipt-proofs response. */
export function collectRecordReceipts(doc: unknown): RecordReceipt[] {
  if (Array.isArray(doc)) return doc.flatMap((d) => collectRecordReceipts(d));
  if (!doc || typeof doc !== 'object') return [];
  const obj = doc as Record<string, unknown>;
  if (obj.schema === SEMANTIC_RECEIPT_SCHEMA_V2 || obj.schema === SEMANTIC_RECEIPT_SCHEMA_V3) return [obj as unknown as RecordReceipt];
  if (Array.isArray(obj.receipts)) return obj.receipts.flatMap((d) => collectRecordReceipts(d));
  if (Array.isArray(obj.proofs)) return obj.proofs.flatMap((d) => collectRecordReceipts(d));
  if (obj.data && typeof obj.data === 'object') return collectRecordReceipts(obj.data);
  return [];
}

/** recomputeSealTagFromReceiptV2 for a receipt of either form; a v3 receipt's leaves are opened first. */
export async function recomputeSealTagFromReceipt(receipt: RecordReceipt | SemanticReceiptV4): Promise<string> {
  let recordHash: string;
  if (receipt?.schema === SEMANTIC_RECEIPT_SCHEMA_V4) {
    // Without the key the seal is recomputed from the stated record hash; the content is unchecked (formats note N7).
    recordHash = (receipt as SemanticReceiptV4).recordHash;
  } else if (receipt?.schema === SEMANTIC_RECEIPT_SCHEMA_V3) {
    const opened = await openRecordEntryV2(receipt as SemanticReceiptV3, { every: true });
    if (!opened.ok) throw new Error(opened.reason);
    recordHash = opened.recordHash;
  } else {
    return recomputeSealTagFromReceiptV2(receipt as SemanticReceiptV2);
  }
  const seal = computeSealV1({
    layoutId: Number(receipt.layoutId),
    layoutVersion: Number(receipt.layoutVersion),
    layoutDigest: receipt.layoutDigest,
    state96: splitWordV1(String(receipt.newWord)).state96,
    recordHash,
    recordOpening: receipt.recordOpening,
  });
  return sealTagOfV1(seal).toLowerCase();
}

/** compareReceiptsToInspectionV1 for receipts of either form. */
export async function compareReceiptsToInspection(
  inspection: RecordCalldataInspectionV1,
  receipts: RecordReceipt[],
): Promise<SealComparisonV1[]> {
  const tags = new Map<RecordReceipt, RecomputedSealTag>();
  for (const receipt of receipts) {
    try {
      tags.set(receipt, { tag: await recomputeSealTagFromReceipt(receipt), reason: null });
    } catch (error) {
      tags.set(receipt, { tag: null, reason: reasonOf(error) });
    }
  }
  return compareReceipts(inspection, receipts, (receipt) => tags.get(receipt) as RecomputedSealTag);
}

type RecomputedSealTag = { tag: string | null; reason: string | null };

function reasonOf(error: unknown): string {
  const e = error as { code?: string; message?: string };
  return e.code ?? e.message ?? 'seal recompute failed';
}

/** Compare every receipt with the records the transaction wrote. */
export function compareReceiptsToInspectionV1(
  inspection: RecordCalldataInspectionV1,
  receipts: SemanticReceiptV2[],
): SealComparisonV1[] {
  return compareReceipts(inspection, receipts, (receipt) => {
    try {
      return { tag: recomputeSealTagFromReceiptV2(receipt), reason: null };
    } catch (error) {
      return { tag: null, reason: reasonOf(error) };
    }
  });
}

function compareReceipts<R extends { recordKey: string; newWord: string; seq: number }>(
  inspection: RecordCalldataInspectionV1,
  receipts: R[],
  recompute: (receipt: R) => RecomputedSealTag,
): SealComparisonV1[] {
  const byKeyAndWord = new Map<string, InspectedRecordV1>();
  for (const r of inspection.records) byKeyAndWord.set(`${r.recordKey}:${r.newWord.toLowerCase()}`, r);
  const results: SealComparisonV1[] = [];
  for (const receipt of receipts) {
    const key = String(receipt.recordKey ?? '').toLowerCase();
    const word = String(receipt.newWord ?? '').toLowerCase();
    const row = byKeyAndWord.get(`${key}:${word}`);
    if (!row) {
      results.push({
        itemIndex: null,
        recordKey: key,
        seq: typeof receipt.seq === 'number' ? receipt.seq : null,
        sealTagInTransaction: null,
        recomputedSealTag: null,
        verdict: 'NOT_IN_TRANSACTION',
        reason: 'no record in this transaction has this record key and new word',
      });
      continue;
    }
    const { tag: recomputedSealTag, reason } = recompute(receipt);
    const match = recomputedSealTag !== null && recomputedSealTag === row.sealTag;
    results.push({
      itemIndex: row.itemIndex,
      recordKey: key,
      seq: typeof receipt.seq === 'number' ? receipt.seq : null,
      sealTagInTransaction: row.sealTag,
      recomputedSealTag,
      verdict: match ? 'MATCH' : 'MISMATCH',
      reason: match ? null : reason ?? 'the sealed record does not reproduce this seal',
    });
  }
  return results;
}

export interface ReadMirrorTransactionOptions {
  chainId?: number;
  mirror?: string | null;
  fetchImpl?: typeof fetch;
  attempts?: number;
}

/**
 * Transaction input and result facts from a public mirror node; never PacSpace.
 * Browser-safe: uses the global `fetch` unless one is supplied.
 */
export async function readTransactionInputFromMirror(
  txHash: string,
  options: ReadMirrorTransactionOptions = {},
): Promise<MirrorTransactionInputV1> {
  const chainId = options.chainId ?? 296;
  const base = options.mirror ?? MIRROR_NODE_BY_CHAIN[chainId];
  if (!base) throw new Error(`No mirror node known for chain ${chainId}; pass a mirror base URL`);
  const hash = String(txHash).toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error('txHash must be a 0x-prefixed 32-byte transaction hash');
  const fetchImpl = options.fetchImpl ?? fetch;
  const attempts = Math.max(1, options.attempts ?? 3);
  const url = new URL(`/api/v1/contracts/results/${hash}`, base).toString();
  let lastError: unknown;
  let result: Record<string, unknown> | null = null;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const res = await fetchImpl(url, { headers: { accept: 'application/json' } });
      if (res.status === 404) throw new Error('contract-result lookup: not found (is the hash right and on this chain?)');
      if (!res.ok) throw new Error(`contract-result lookup: HTTP ${res.status}`);
      result = (await res.json()) as Record<string, unknown>;
      break;
    } catch (error) {
      lastError = error;
      if (String((error as Error)?.message).includes('not found')) throw error;
      if (attempt < attempts) await new Promise((r) => setTimeout(r, 400 * attempt));
    }
  }
  if (!result) throw new Error(`contract-result lookup failed after ${attempts} attempts: ${(lastError as Error)?.message ?? lastError}`);
  const input = result.function_parameters;
  if (typeof input !== 'string' || !input.startsWith('0x')) throw new Error('mirror node returned no function_parameters');
  const to = String(result.to ?? result.address ?? '').toLowerCase();
  const from = String(result.from ?? '').toLowerCase();
  return {
    txHash: hash,
    chainId: options.mirror && options.chainId === undefined ? null : chainId,
    mirror: base,
    to: to || null,
    from: from || null,
    blockNumber: typeof result.block_number === 'number' ? result.block_number : null,
    timestamp: typeof result.timestamp === 'string' ? result.timestamp : null,
    status: typeof result.result === 'string' ? result.result : typeof result.status === 'string' ? result.status : null,
    calldata: input,
  };
}

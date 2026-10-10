import { ethers } from 'ethers';
import { createRpcProvider } from '../chain/rpc-provider';
import { DecodedState } from '../proof/layout-document-v1';
import { LedgerBatchRef } from '../proof/ledger-head-v1';
import { normalizeProofHash } from '../proof/merkle-v2';
import {
  RecordHistoryCheckV2,
  SemanticReceiptV2,
  SlotReceiptVerificationV2,
  SlotVerificationLevel,
  isSlotReceiptV2,
  verifyRecordHistoryV2,
  verifySlotReceiptV2,
} from '../proof/semantic-receipt-v2';
import { LayoutRegistry, decodeWordV1, hex256 } from '../proof/slot-encoding-v1';
import { getPublishedLayoutRegistry } from '../records/layouts';
import {
  BundleVerificationV1,
  RecordHistoryBundleV1,
  verifyRecordHistoryBundleV1,
} from '../records/record-history-bundle-v1';

/**
 * Independent verification of record-lane receipts against the public
 * proof layer (ADR 0012 section 9; tenant guide sections 6 to 8).
 *
 * Three levels, each including the ones before it:
 *   state-read  the word read from the contract carries the public state the
 *               receipt claims, and the layout digest on the contract matches
 *               the published layout document;
 *   semantic    the sealed record recomputes to the seal tag on that word and
 *               the item folds to the batch root read from the contract;
 *   ledger      the batch sits in the head chain that ends at the head read
 *               from the contract.
 *
 * Nothing here calls PacSpace. Only the public RPC of the proof layer is
 * consulted, through a small reader interface so a mirror-node or archive
 * reader can be substituted.
 */

export const RECORD_LANE_ABI_V38 = [
  'function getRecord(bytes32 recordKey) view returns (uint256)',
  'function getRecords(bytes32[] recordKeys) view returns (uint256[])',
  'function getLayout(uint16 layoutId) view returns (bytes32 layoutDigest, uint8 stateBits, uint8 sealBits, bool registered)',
  'function getLedgerHead() view returns (bytes32)',
  'function getBatchRoot(uint256 batchId) view returns (bytes32)',
  'function batchCounter() view returns (uint256)',
  'event RecordWritten(bytes32 indexed recordKey, address indexed operator, uint8 encodingVersion, uint256 previousWord, uint256 newWord)',
  'event LedgerHeadAdvanced(uint256 indexed batchId, bytes32 merkleRoot, bytes32 previousHead, bytes32 newHead)',
] as const;

export const LEDGER_HEAD_ADVANCED_TOPIC = ethers.id('LedgerHeadAdvanced(uint256,bytes32,bytes32,bytes32)');
export const RECORD_WRITTEN_TOPIC = ethers.id('RecordWritten(bytes32,address,uint8,uint256,uint256)');

export interface OnChainLayout {
  layoutDigest: string;
  stateBits: number;
  sealBits: number;
  registered: boolean;
}

/**
 * The one named hard failure of the layout check (plan addition 1): the layout
 * the verifier decodes with is not the one registered on the tenant's contract,
 * either because nothing is registered under that id or because the registered
 * digest differs from the published document. Nothing is decoded on trust when
 * this is set.
 */
export const LAYOUT_NOT_REGISTERED = 'layout-not-registered' as const;
export type LayoutFailure = typeof LAYOUT_NOT_REGISTERED;

export interface LayoutOnChainCheck extends OnChainLayout {
  matchesPublished: boolean;
  /** `layout-not-registered` when `matchesPublished` is false; `null` when the digests agree. */
  failure: LayoutFailure | null;
}

export function checkLayoutOnChain(onChainLayout: OnChainLayout, published: { digest: string } | undefined): LayoutOnChainCheck {
  const matchesPublished = !!published && onChainLayout.registered && onChainLayout.layoutDigest === published.digest;
  return { ...onChainLayout, matchesPublished, failure: matchesPublished ? null : LAYOUT_NOT_REGISTERED };
}

export interface LedgerAdvance extends LedgerBatchRef {
  previousHead: string;
  newHead: string;
  blockNumber?: number;
  transactionHash?: string;
}

export interface RecordWrite {
  previousWord: string;
  newWord: string;
  operator: string;
  encodingVersion: number;
  blockNumber?: number;
  transactionHash?: string;
  logIndex?: number;
}

export interface RecordChainReader {
  contractAddress: string;
  getRecord(recordKey: string): Promise<string>;
  getLayout(layoutId: number): Promise<OnChainLayout>;
  getBatchRoot(batchId: number | string): Promise<string>;
  getLedgerHead(): Promise<string>;
  /** Every LedgerHeadAdvanced in [fromBlock, toBlock], ascending by batchId. */
  getLedgerAdvances(fromBlock?: number, toBlock?: number | 'latest'): Promise<LedgerAdvance[]>;
  /** Every RecordWritten for one record key in [fromBlock, toBlock], in log order. */
  getRecordWrites(recordKey: string, fromBlock?: number, toBlock?: number | 'latest'): Promise<RecordWrite[]>;
}

export interface RpcReaderOptions {
  rpcUrl: string;
  contractAddress: string;
  chainId?: number;
  timeoutMs?: number;
  /** Max block span per eth_getLogs call (Hedera relays cap the range). */
  logsChunkSize?: number;
}

function normalizeRpcUrl(url: string): string {
  const trimmed = String(url || '').trim();
  if (trimmed.startsWith('wss://')) return trimmed.replace(/^wss:\/\//, 'https://');
  if (trimmed.startsWith('ws://')) return trimmed.replace(/^ws:\/\//, 'http://');
  return trimmed;
}

async function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function createRpcRecordChainReader(options: RpcReaderOptions): RecordChainReader {
  const rpcUrl = normalizeRpcUrl(options.rpcUrl);
  if (!rpcUrl) throw new Error('rpcUrl is required.');
  const contractAddress = ethers.getAddress(options.contractAddress).toLowerCase();
  const timeoutMs = Number(options.timeoutMs || 10000);
  const chunk = Math.max(1, Number(options.logsChunkSize || 2000));
  const network = options.chainId != null ? new ethers.Network(`chain-${options.chainId}`, options.chainId) : undefined;
  const provider = network
    ? createRpcProvider(rpcUrl, network, { staticNetwork: network })
    : createRpcProvider(rpcUrl);
  const contract = new ethers.Contract(contractAddress, RECORD_LANE_ABI_V38 as unknown as string[], provider);
  const iface = new ethers.Interface(RECORD_LANE_ABI_V38 as unknown as string[]);

  async function scanLogs(topics: Array<string | null>, fromBlock: number, toBlock: number | 'latest', label: string): Promise<ethers.Log[]> {
    const latest = toBlock === 'latest' ? await withTimeout(provider.getBlockNumber(), timeoutMs, 'getBlockNumber') : toBlock;
    const out: ethers.Log[] = [];
    for (let start = fromBlock; start <= latest; start += chunk) {
      const end = Math.min(latest, start + chunk - 1);
      const logs = await withTimeout(
        provider.getLogs({ address: contractAddress, topics, fromBlock: start, toBlock: end }),
        timeoutMs,
        `getLogs ${label} (${start}-${end})`,
      );
      out.push(...logs);
    }
    return out;
  }

  return {
    contractAddress,
    async getRecord(recordKey) {
      const key = normalizeProofHash(recordKey, 'recordKey');
      const word = await withTimeout(contract.getRecord(key), timeoutMs, 'getRecord');
      return hex256(BigInt(word as bigint));
    },
    async getLayout(layoutId) {
      const l = await withTimeout(contract.getLayout(layoutId), timeoutMs, 'getLayout');
      return {
        layoutDigest: String(l[0]).toLowerCase(),
        stateBits: Number(l[1]),
        sealBits: Number(l[2]),
        registered: Boolean(l[3]),
      };
    },
    async getBatchRoot(batchId) {
      const root = await withTimeout(contract.getBatchRoot(BigInt(batchId)), timeoutMs, 'getBatchRoot');
      return normalizeProofHash(String(root), 'observedProofRoot');
    },
    async getLedgerHead() {
      const head = await withTimeout(contract.getLedgerHead(), timeoutMs, 'getLedgerHead');
      return normalizeProofHash(String(head), 'ledgerHead');
    },
    async getLedgerAdvances(fromBlock = 0, toBlock = 'latest') {
      const logs = await scanLogs([LEDGER_HEAD_ADVANCED_TOPIC], fromBlock, toBlock, 'LedgerHeadAdvanced');
      const out: LedgerAdvance[] = [];
      for (const log of logs) {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (!parsed) continue;
        out.push({
          batchId: parsed.args.batchId.toString(),
          merkleRoot: String(parsed.args.merkleRoot).toLowerCase(),
          previousHead: String(parsed.args.previousHead).toLowerCase(),
          newHead: String(parsed.args.newHead).toLowerCase(),
          blockNumber: log.blockNumber,
          transactionHash: log.transactionHash,
        });
      }
      out.sort((a, b) => Number(BigInt(a.batchId) - BigInt(b.batchId)));
      return out;
    },
    async getRecordWrites(recordKey, fromBlock = 0, toBlock = 'latest') {
      const key = normalizeProofHash(recordKey, 'recordKey');
      const logs = await scanLogs([RECORD_WRITTEN_TOPIC, key], fromBlock, toBlock, 'RecordWritten');
      const out: RecordWrite[] = [];
      for (const log of logs) {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (!parsed) continue;
        out.push({
          previousWord: hex256(BigInt(parsed.args.previousWord)),
          newWord: hex256(BigInt(parsed.args.newWord)),
          operator: String(parsed.args.operator).toLowerCase(),
          encodingVersion: Number(parsed.args.encodingVersion),
          blockNumber: log.blockNumber,
          transactionHash: log.transactionHash,
          logIndex: log.index,
        });
      }
      return out;
    },
  };
}

// ----------------------------------------------------------------- verify

export type RecordVerifyStepName =
  | 'get_record'
  | 'get_layout'
  | 'get_batch_root'
  | 'get_ledger_head'
  | 'get_ledger_advances'
  | 'get_record_writes'
  | 'verify_receipt'
  | 'verify_history'
  | 'verify_bundle';

export interface RecordVerifyStep {
  step: RecordVerifyStepName;
  ok: boolean;
  latencyMs: number;
  detail: string;
}

export interface LedgerMaterial {
  genesisHead: string;
  batches: LedgerBatchRef[];
  expectedHead: string;
  advances?: LedgerAdvance[];
}

export interface VerifyRecordInput {
  reader: RecordChainReader;
  receipt: SemanticReceiptV2;
  level?: SlotVerificationLevel;
  layouts?: LayoutRegistry;
  /** Ledger material already read (for example from a mirror node); read from logs when absent. */
  ledger?: LedgerMaterial;
  /** First block to scan for LedgerHeadAdvanced when `ledger` is not supplied. */
  ledgerFromBlock?: number;
  /** Genesis head the contract was deployed with (zero for a fresh deployment). */
  genesisHead?: string;
}

export interface IndependentRecordVerifyResult {
  verified: boolean;
  level: SlotVerificationLevel;
  recordKey: string;
  contractAddress: string;
  /** The current word for the record key. */
  chainWord: string | null;
  /** Seq carried by the current word (null when the layout is unknown). */
  currentSeq: number | null;
  /**
   * The word the receipt was checked against: the current word for the
   * latest entry, or the `RecordWritten.newWord` at the receipt's position
   * for an earlier entry (read from the event history).
   */
  matchedWord: string | null;
  /** True when the receipt is an earlier entry matched through the event history. */
  historical: boolean;
  decodedState: DecodedState | null;
  layoutOnChain: LayoutOnChainCheck | null;
  observedProofRoot: string | null;
  ledgerHead: string | null;
  ledgerBatchCount: number | null;
  receiptCheck: SlotReceiptVerificationV2 | null;
  requestLog: RecordVerifyStep[];
}

async function timed<T>(
  step: RecordVerifyStepName,
  fn: () => Promise<T>,
  log: RecordVerifyStep[],
  detail: string,
): Promise<T> {
  const started = Date.now();
  try {
    const result = await fn();
    log.push({ step, ok: true, latencyMs: Date.now() - started, detail });
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log.push({ step, ok: false, latencyMs: Date.now() - started, detail: `${detail}: ${message}` });
    throw error;
  }
}

export async function readLedgerMaterial(
  reader: RecordChainReader,
  log: RecordVerifyStep[],
  options: { fromBlock?: number; genesisHead?: string },
): Promise<LedgerMaterial> {
  const expectedHead = await timed('get_ledger_head', () => reader.getLedgerHead(), log, 'eth_call getLedgerHead()');
  const advances = await timed(
    'get_ledger_advances',
    () => reader.getLedgerAdvances(options.fromBlock ?? 0, 'latest'),
    log,
    `eth_getLogs LedgerHeadAdvanced from block ${options.fromBlock ?? 0}`,
  );
  // The first advance's previousHead is the head the contract started from
  // (zero for a fresh deployment, or the inherited head of a prior contract).
  const genesisHead = options.genesisHead ?? (advances[0]?.previousHead ?? ethers.ZeroHash);
  return {
    genesisHead,
    batches: advances.map((a) => ({ batchId: a.batchId, merkleRoot: a.merkleRoot })),
    expectedHead,
    advances,
  };
}

export async function verifyRecordWithPublicLayer(input: VerifyRecordInput): Promise<IndependentRecordVerifyResult> {
  const level: SlotVerificationLevel = input.level ?? 'semantic';
  const layouts = input.layouts ?? getPublishedLayoutRegistry();
  const log: RecordVerifyStep[] = [];
  const receipt = input.receipt;
  if (!isSlotReceiptV2(receipt)) throw new Error('receipt is not a semantic-receipt/v2 slot-v1 receipt.');
  const recordKey = normalizeProofHash(receipt.recordKey, 'recordKey');

  // state-read
  const chainWord = await timed('get_record', () => input.reader.getRecord(recordKey), log, `eth_call getRecord(${recordKey})`);
  const onChainLayout = await timed('get_layout', () => input.reader.getLayout(receipt.layoutId), log, `eth_call getLayout(${receipt.layoutId})`);
  const published = layouts.get(receipt.layoutId);
  const layoutOnChain = checkLayoutOnChain(onChainLayout, published);
  let decodedState: DecodedState | null = null;
  let currentSeq: number | null = null;
  try {
    decodedState = decodeWordV1(layouts, chainWord).decodedState;
    currentSeq = Number(decodedState.seq);
  } catch {
    decodedState = null;
  }

  // An earlier entry is matched through the RecordWritten history: the
  // event at the receipt's position must carry exactly the receipt's
  // previousWord and newWord. The current word cannot vouch for it.
  let matchedWord: string | null = chainWord;
  let historical = false;
  let historyMatched = true;
  if (currentSeq !== null && receipt.seq !== currentSeq) {
    historical = true;
    const writes = await timed(
      'get_record_writes',
      () => input.reader.getRecordWrites(recordKey, input.ledgerFromBlock ?? 0, 'latest'),
      log,
      `eth_getLogs RecordWritten(${recordKey})`,
    );
    const hit = writes.find(
      (w) => BigInt(w.newWord) === BigInt(receipt.newWord) && BigInt(w.previousWord) === BigInt(receipt.previousWord),
    );
    if (hit) {
      matchedWord = hit.newWord;
    } else {
      historyMatched = false;
      matchedWord = null;
    }
  }

  let observedProofRoot: string | null = null;
  let ledger: LedgerMaterial | undefined;
  if (level !== 'state-read') {
    observedProofRoot = await timed('get_batch_root', () => input.reader.getBatchRoot(receipt.batchId), log, `eth_call getBatchRoot(${receipt.batchId})`);
  }
  if (level === 'ledger') {
    ledger = input.ledger ?? (await readLedgerMaterial(input.reader, log, { fromBlock: input.ledgerFromBlock, genesisHead: input.genesisHead }));
  }

  const receiptCheck = await timed(
    'verify_receipt',
    async () =>
      verifySlotReceiptV2(receipt, {
        layouts,
        // For a historical entry with no matching event, fall back to the
        // current word so the state-read check fails visibly.
        chainWord: matchedWord ?? chainWord,
        expectedProofRoot: observedProofRoot ?? undefined,
        ledger: ledger ? { genesisHead: ledger.genesisHead, batches: ledger.batches, expectedHead: ledger.expectedHead } : undefined,
      }),
    log,
    `verify receipt seq ${receipt.seq} at level ${level}${historical ? ' (earlier entry, matched through RecordWritten history)' : ''}`,
  );

  let verified: boolean;
  if (level === 'state-read') {
    verified = layoutOnChain.matchesPublished && historyMatched && receiptCheck.checks['state-read'] === true;
  } else {
    verified = layoutOnChain.matchesPublished && historyMatched && receiptCheck.verified;
  }

  return {
    verified,
    level,
    recordKey,
    contractAddress: input.reader.contractAddress,
    chainWord,
    currentSeq,
    matchedWord,
    historical,
    decodedState,
    layoutOnChain,
    observedProofRoot,
    ledgerHead: ledger?.expectedHead ?? null,
    ledgerBatchCount: ledger ? ledger.batches.length : null,
    receiptCheck,
    requestLog: log,
  };
}

export interface VerifyHistoryInput {
  reader: RecordChainReader;
  receipts: SemanticReceiptV2[];
  level?: SlotVerificationLevel;
  layouts?: LayoutRegistry;
  ledger?: LedgerMaterial;
  ledgerFromBlock?: number;
  genesisHead?: string;
}

export interface IndependentHistoryVerifyResult {
  verified: boolean;
  level: SlotVerificationLevel;
  recordKey: string;
  contractAddress: string;
  chainWord: string;
  decodedState: DecodedState | null;
  layoutOnChain: LayoutOnChainCheck | null;
  batchRoots: Record<string, string>;
  ledgerHead: string | null;
  history: RecordHistoryCheckV2;
  requestLog: RecordVerifyStep[];
}

export async function verifyRecordHistoryWithPublicLayer(input: VerifyHistoryInput): Promise<IndependentHistoryVerifyResult> {
  const level: SlotVerificationLevel = input.level ?? 'semantic';
  const layouts = input.layouts ?? getPublishedLayoutRegistry();
  const log: RecordVerifyStep[] = [];
  if (!input.receipts.length || !input.receipts.every(isSlotReceiptV2)) {
    throw new Error('receipts must be one or more semantic-receipt/v2 slot-v1 receipts.');
  }
  const recordKey = normalizeProofHash(input.receipts[0].recordKey, 'recordKey');
  const layoutId = input.receipts[0].layoutId;

  const chainWord = await timed('get_record', () => input.reader.getRecord(recordKey), log, `eth_call getRecord(${recordKey})`);
  const onChainLayout = await timed('get_layout', () => input.reader.getLayout(layoutId), log, `eth_call getLayout(${layoutId})`);
  const published = layouts.get(layoutId);
  const layoutOnChain = checkLayoutOnChain(onChainLayout, published);
  let decodedState: DecodedState | null = null;
  try {
    decodedState = decodeWordV1(layouts, chainWord).decodedState;
  } catch {
    decodedState = null;
  }

  const batchRoots: Record<string, string> = {};
  if (level !== 'state-read') {
    const ids = [...new Set(input.receipts.map((r) => String(r.batchId)))];
    for (const id of ids) {
      batchRoots[id] = await timed('get_batch_root', () => input.reader.getBatchRoot(id), log, `eth_call getBatchRoot(${id})`);
    }
  }
  let ledger: LedgerMaterial | undefined;
  if (level === 'ledger') {
    ledger = input.ledger ?? (await readLedgerMaterial(input.reader, log, { fromBlock: input.ledgerFromBlock, genesisHead: input.genesisHead }));
  }

  const history = await timed(
    'verify_history',
    async () =>
      verifyRecordHistoryV2(input.receipts, {
        layouts,
        chainWord,
        proofRoots: level === 'state-read' ? undefined : batchRoots,
        ledger: ledger ? { genesisHead: ledger.genesisHead, batches: ledger.batches, expectedHead: ledger.expectedHead } : undefined,
      }),
    log,
    `verify ${input.receipts.length} receipt(s) as a history at level ${level}`,
  );

  return {
    verified: layoutOnChain.matchesPublished && history.complete,
    level,
    recordKey,
    contractAddress: input.reader.contractAddress,
    chainWord,
    decodedState,
    layoutOnChain,
    batchRoots,
    ledgerHead: ledger?.expectedHead ?? null,
    history,
    requestLog: log,
  };
}

export interface VerifyBundleInput {
  reader: RecordChainReader;
  bundle: RecordHistoryBundleV1;
  level?: SlotVerificationLevel;
  layouts?: LayoutRegistry;
  ledgerFromBlock?: number;
  genesisHead?: string;
}

export interface IndependentBundleVerifyResult {
  verified: boolean;
  level: SlotVerificationLevel;
  contractAddress: string;
  contractMatchesBundle: boolean;
  chainWord: string;
  layoutOnChain: (LayoutOnChainCheck & { matchesBundle: boolean }) | null;
  bundleCheck: BundleVerificationV1;
  requestLog: RecordVerifyStep[];
}

/**
 * Bundle mode: everything offline comes from the bundle; the current word,
 * the batch roots, and (at ledger level) the head chain come from the
 * public layer and override whatever the bundle carried.
 */
export async function verifyBundleWithPublicLayer(input: VerifyBundleInput): Promise<IndependentBundleVerifyResult> {
  const level: SlotVerificationLevel = input.level ?? 'semantic';
  const layouts = input.layouts ?? getPublishedLayoutRegistry();
  const log: RecordVerifyStep[] = [];
  const bundle = input.bundle;
  const contractMatchesBundle =
    !!bundle.chain?.contractAddress && bundle.chain.contractAddress.toLowerCase() === input.reader.contractAddress.toLowerCase();
  const recordKey = normalizeProofHash(bundle.recordKey, 'recordKey');

  const chainWord = await timed('get_record', () => input.reader.getRecord(recordKey), log, `eth_call getRecord(${recordKey})`);
  const onChainLayout = await timed('get_layout', () => input.reader.getLayout(bundle.layout.layoutId), log, `eth_call getLayout(${bundle.layout.layoutId})`);
  const published = layouts.get(bundle.layout.layoutId);

  const batchRoots: Record<string, string> = {};
  if (level !== 'state-read') {
    const ids = [...new Set(bundle.receipts.map((r) => String(r.batchId)))];
    for (const id of ids) {
      batchRoots[id] = await timed('get_batch_root', () => input.reader.getBatchRoot(id), log, `eth_call getBatchRoot(${id})`);
    }
  }
  let ledger: LedgerMaterial | undefined;
  if (level === 'ledger') {
    ledger = await readLedgerMaterial(input.reader, log, { fromBlock: input.ledgerFromBlock, genesisHead: input.genesisHead });
  }

  const bundleCheck = await timed(
    'verify_bundle',
    async () =>
      verifyRecordHistoryBundleV1(bundle, {
        layouts,
        chainWord,
        batchRoots: level === 'state-read' ? undefined : batchRoots,
        ledger: ledger ? { genesisHead: ledger.genesisHead, batches: ledger.batches, expectedHead: ledger.expectedHead } : undefined,
      }),
    log,
    `verify bundle of ${bundle.receipts.length} receipt(s) at level ${level}`,
  );
  const layoutOnChain = {
    ...checkLayoutOnChain(onChainLayout, published),
    matchesBundle: onChainLayout.registered && bundleCheck.layoutDigest === onChainLayout.layoutDigest,
  };

  return {
    verified: contractMatchesBundle && layoutOnChain.matchesBundle && bundleCheck.verified,
    level,
    contractAddress: input.reader.contractAddress,
    contractMatchesBundle,
    chainWord,
    layoutOnChain,
    bundleCheck,
    requestLog: log,
  };
}

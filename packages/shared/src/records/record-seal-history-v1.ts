import { ethers } from 'ethers';
import type { RecordChainReader } from '../demo/independent-verify-records';
import { createMirrorNodeRecordChainReader } from '../demo/mirror-node-record-chain-reader';
import { verifyHiddenItemProofV1 } from '../proof/hiding-commitment-v1';
import { canonicalizeJcs } from '../proof/jcs';
import { decodeStateV1 } from '../proof/layout-document-v1';
import { verifyLedgerChainV1 } from '../proof/ledger-head-v1';
import type { RecordReceipt } from '../proof/semantic-receipt-v3';
import {
  FLAG_DELIVERY_FAILED,
  FLAG_TRANSITION_NOT_APPLIED,
  checkTransitionRuleV1,
  computeSlotItemHashV1,
  sealTagOfV1,
  splitWordV1,
  type LayoutRegistry,
} from '../proof/slot-encoding-v1';
import {
  RECORD_DISCLOSURE_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V2,
  buildRecordDisclosureV1,
  verifyRecordDisclosureV1,
  type ChainBatchRootsV1,
  type RecordDisclosure,
  type RecordDisclosureRefusalV1,
  type RecordReceiptV3Items,
  type SealHistoryEntryForDisclosureV1,
  type SealHistoryFormForDisclosureV1,
} from '../records-crypto/record-disclosure-v1';
import type { RecordLeafV2 } from '../records-crypto/record-hash-v2';

/**
 * record-seal-history/v1 (seals-first design, section 4.5): a record's seals
 * with no entry words. Per committed entry it carries the entry number, the
 * previous and new ledger words, the 32-byte seal, the inclusion path and,
 * for a v2 record only, the record hash. It never carries content, an
 * opening, or a v1 record hash. Its digest is keccak256 over the JCS form of
 * every other field, so two reads give the same digest while nothing in the
 * record changed. A record hash v3 record (card 10, F1) carries
 * `recordHashVersion: 3`; no other record carries the member, so v1 and v2
 * forms are unchanged.
 */
export const RECORD_SEAL_HISTORY_SCHEMA_V1 = 'record-seal-history/v1' as const;
/** 5000 entries at about 2 KiB each stay under 10 MiB; a reader refuses a larger file before parsing it. */
export const RECORD_SEAL_HISTORY_MAX_BYTES_V1 = 16777216;

export interface RecordSealHistoryEntryV1 {
  seq: number;
  previousWord: string;
  newWord: string;
  seal: string;
  recordHash?: string;
  itemIndex: number;
  itemOpening: string;
  merkleProof: string[];
  proofRoot: string;
  batchId: number;
}

export interface RecordSealHistoryPendingV1 {
  seq: number | null;
  status: 'queued' | 'failed';
}

export interface RecordSealHistoryLedgerV1 {
  genesisHead: string;
  head: string;
  batches: Array<{ batchId: number; merkleRoot: string; blockTime: string }>;
}

export interface RecordSealHistoryV1 {
  schema: typeof RECORD_SEAL_HISTORY_SCHEMA_V1;
  recordKey: string;
  chain: { chainId: number; contractAddress: string };
  layout: { layoutId: number; layoutVersion: number; layoutDigest: string };
  /** Present, and 3, only for a record hash v3 record. */
  recordHashVersion?: 3;
  currentWord: string | null;
  entries: RecordSealHistoryEntryV1[];
  pending: RecordSealHistoryPendingV1[];
  ledger?: RecordSealHistoryLedgerV1;
  digest: string;
}

export type SealHistoryCheckNameV1 = 'tag' | 'chain' | 'rule' | 'inclusion' | 'ledger';

export interface SealHistoryEntryResultV1 {
  seq: number;
  checks: Record<SealHistoryCheckNameV1, boolean | null>;
  failedCheck: SealHistoryCheckNameV1 | null;
  attemptedTargetUnchecked: boolean;
}

export interface SealHistoryVerificationV1 {
  verified: boolean;
  schemaOk: boolean;
  digestOk: boolean;
  layoutOk: boolean;
  nothingCommitted: boolean;
  complete: boolean;
  settlingSeq: number[];
  missingSeq: number[];
  failedSeq: number[];
  closed: boolean;
  closedAtSeq: number | null;
  perEntry: SealHistoryEntryResultV1[];
  ledgerChecked: boolean;
  chainWordMatches: boolean | null;
  reason: string;
}

const HEX32 = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO32 = '0x' + '0'.repeat(64);
const ENTRY_KEYS = ['seq', 'previousWord', 'newWord', 'seal', 'itemIndex', 'itemOpening', 'merkleProof', 'proofRoot', 'batchId'] as const;

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const isHex32 = (v: unknown): v is string => typeof v === 'string' && HEX32.test(v);
const isNatural = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;
const hasOnly = (v: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []) =>
  required.every((k) => Object.prototype.hasOwnProperty.call(v, k)) &&
  Object.keys(v).every((k) => required.includes(k) || optional.includes(k));

/** keccak256(utf8(JCS(form without `digest`))). */
export function computeSealHistoryDigestV1(form: Omit<RecordSealHistoryV1, 'digest'> & { digest?: string }): string {
  const rest: Record<string, unknown> = { ...form };
  delete rest.digest;
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalizeJcs(rest)));
}

/**
 * The pure assembly step: rows whose seals the caller has already computed
 * and asserted (the API builder holds the batch seed), the pending rows and
 * the ledger rows. `ledger` is passed only when every entry's batch has a
 * ledger row. Returns the form with its digest.
 */
export function buildRecordSealHistoryV1(input: {
  recordKey: string;
  chain: { chainId: number; contractAddress: string };
  layout: { layoutId: number; layoutVersion: number; layoutDigest: string };
  recordHashVersion?: 1 | 2 | 3;
  currentWord: string | null;
  entries: RecordSealHistoryEntryV1[];
  pending: RecordSealHistoryPendingV1[];
  ledger?: RecordSealHistoryLedgerV1;
}): RecordSealHistoryV1 {
  const entries = [...input.entries]
    .sort((a, b) => a.seq - b.seq)
    .map((e) => ({
      seq: e.seq,
      previousWord: e.previousWord.toLowerCase(),
      newWord: e.newWord.toLowerCase(),
      seal: e.seal.toLowerCase(),
      ...(e.recordHash !== undefined ? { recordHash: e.recordHash.toLowerCase() } : {}),
      itemIndex: e.itemIndex,
      itemOpening: e.itemOpening.toLowerCase(),
      merkleProof: e.merkleProof.map((p) => p.toLowerCase()),
      proofRoot: e.proofRoot.toLowerCase(),
      batchId: e.batchId,
    }));
  const body: Omit<RecordSealHistoryV1, 'digest'> = {
    schema: RECORD_SEAL_HISTORY_SCHEMA_V1,
    recordKey: input.recordKey.toLowerCase(),
    chain: { chainId: input.chain.chainId, contractAddress: input.chain.contractAddress.toLowerCase() },
    layout: { layoutId: input.layout.layoutId, layoutVersion: input.layout.layoutVersion, layoutDigest: input.layout.layoutDigest.toLowerCase() },
    ...(input.recordHashVersion === 3 ? { recordHashVersion: 3 as const } : {}),
    currentWord: input.currentWord ? input.currentWord.toLowerCase() : null,
    entries,
    pending: input.pending.map((p) => ({ seq: p.seq, status: p.status })),
    ...(input.ledger
      ? {
          ledger: {
            genesisHead: input.ledger.genesisHead.toLowerCase(),
            head: input.ledger.head.toLowerCase(),
            batches: input.ledger.batches.map((b) => ({ batchId: b.batchId, merkleRoot: b.merkleRoot.toLowerCase(), blockTime: b.blockTime })),
          },
        }
      : {}),
  };
  return { ...body, digest: computeSealHistoryDigestV1(body) };
}

function entryShapeOk(e: unknown): e is RecordSealHistoryEntryV1 {
  if (!isPlainObject(e) || !hasOnly(e, ENTRY_KEYS, ['recordHash'])) return false;
  return (
    isNatural(e.seq) &&
    isHex32(e.previousWord) &&
    isHex32(e.newWord) &&
    isHex32(e.seal) &&
    (e.recordHash === undefined || isHex32(e.recordHash)) &&
    isNatural(e.itemIndex) &&
    isHex32(e.itemOpening) &&
    Array.isArray(e.merkleProof) &&
    e.merkleProof.length <= 32 &&
    e.merkleProof.every(isHex32) &&
    isHex32(e.proofRoot) &&
    isNatural(e.batchId)
  );
}

function formShapeOk(form: unknown): form is RecordSealHistoryV1 {
  if (!isPlainObject(form)) return false;
  if (!hasOnly(form, ['schema', 'recordKey', 'chain', 'layout', 'currentWord', 'entries', 'pending', 'digest'], ['ledger', 'recordHashVersion'])) return false;
  if (form.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1 || !isHex32(form.recordKey) || !isHex32(form.digest)) return false;
  if (form.recordHashVersion !== undefined && form.recordHashVersion !== 3) return false;
  const chain = form.chain;
  if (!isPlainObject(chain) || !hasOnly(chain, ['chainId', 'contractAddress']) || !isNatural(chain.chainId)) return false;
  if (typeof chain.contractAddress !== 'string' || !ADDRESS.test(chain.contractAddress)) return false;
  const layout = form.layout;
  if (!isPlainObject(layout) || !hasOnly(layout, ['layoutId', 'layoutVersion', 'layoutDigest'])) return false;
  if (!isNatural(layout.layoutId) || !isNatural(layout.layoutVersion) || !isHex32(layout.layoutDigest)) return false;
  if (form.currentWord !== null && !isHex32(form.currentWord)) return false;
  if (!Array.isArray(form.entries) || !form.entries.every(entryShapeOk)) return false;
  if (!Array.isArray(form.pending)) return false;
  for (const p of form.pending) {
    if (!isPlainObject(p) || !hasOnly(p, ['seq', 'status'])) return false;
    if (p.seq !== null && !isNatural(p.seq)) return false;
    if (p.status !== 'queued' && p.status !== 'failed') return false;
  }
  if (form.ledger !== undefined) {
    const l = form.ledger;
    if (!isPlainObject(l) || !hasOnly(l, ['genesisHead', 'head', 'batches'])) return false;
    if (!isHex32(l.genesisHead) || !isHex32(l.head) || !Array.isArray(l.batches)) return false;
    for (const b of l.batches) {
      if (!isPlainObject(b) || !hasOnly(b, ['batchId', 'merkleRoot', 'blockTime'])) return false;
      if (!isNatural(b.batchId) || !isHex32(b.merkleRoot) || typeof b.blockTime !== 'string') return false;
    }
  }
  return true;
}

function emptyResult(reason: string, part: Partial<SealHistoryVerificationV1> = {}): SealHistoryVerificationV1 {
  return {
    verified: false,
    schemaOk: false,
    digestOk: false,
    layoutOk: false,
    nothingCommitted: false,
    complete: false,
    settlingSeq: [],
    missingSeq: [],
    failedSeq: [],
    closed: false,
    closedAtSeq: null,
    perEntry: [],
    ledgerChecked: false,
    chainWordMatches: null,
    reason,
    ...part,
  };
}

/**
 * Section 5.1: form, layout, then per entry tag, chain, rule, inclusion and
 * (when `ledger` is present) ledger, then completeness against `currentWord`.
 * Passing proves the served seals, words, batch roots and heads agree with
 * each other and end at the served current word; only a walk of the ledger
 * ties an entry to the ledger itself. Never throws.
 */
export function verifyRecordSealHistoryV1(
  form: unknown,
  options: { layouts: LayoutRegistry; chainWord?: string | null },
): SealHistoryVerificationV1 {
  try {
    return verifySealHistory(form, options);
  } catch {
    return emptyResult('This seal history could not be read.');
  }
}

function verifySealHistory(form: unknown, options: { layouts: LayoutRegistry; chainWord?: string | null }): SealHistoryVerificationV1 {
  if (!isPlainObject(form) || form.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1) {
    return emptyResult('Not a record-seal-history/v1.');
  }
  if (!formShapeOk(form)) return emptyResult('The seal history is not well formed.', { schemaOk: false });
  if (computeSealHistoryDigestV1(form) !== form.digest) {
    return emptyResult('The seal history digest does not match its contents.', { schemaOk: true });
  }
  const registered = options.layouts.get(form.layout.layoutId);
  if (
    !registered ||
    registered.doc.layoutVersion !== form.layout.layoutVersion ||
    registered.digest.toLowerCase() !== form.layout.layoutDigest
  ) {
    return emptyResult('The seal history names a layout that is not published.', { schemaOk: true, digestOk: true });
  }
  const doc = registered.doc;
  const base = { schemaOk: true, digestOk: true, layoutOk: true };
  const chainWordMatches =
    options.chainWord === undefined || options.chainWord === null || form.currentWord === null
      ? null
      : options.chainWord.toLowerCase() === form.currentWord;

  const entries = form.entries;
  for (let i = 1; i < entries.length; i += 1) {
    if (!(entries[i - 1].seq < entries[i].seq)) {
      return emptyResult('The seal history lists its entries out of order.', base);
    }
  }

  const ledger = form.ledger;
  const ledgerChecked = ledger !== undefined;
  const ledgerRoots = new Map((ledger?.batches ?? []).map((b) => [b.batchId, b.merkleRoot] as const));
  const perEntry: SealHistoryEntryResultV1[] = [];
  const failedSeq: number[] = [];
  const bySeq = new Map(entries.map((e) => [e.seq, e] as const));

  for (const e of entries) {
    const checks: Record<SealHistoryCheckNameV1, boolean | null> = { tag: null, chain: null, rule: null, inclusion: null, ledger: null };
    let attemptedTargetUnchecked = false;
    const split = splitWordV1(e.newWord);
    checks.tag =
      sealTagOfV1(e.seal) === split.sealTag && split.layoutId === form.layout.layoutId && split.layoutVersion === form.layout.layoutVersion;

    const state = decodeStateV1(doc, split.state96);
    const prior = bySeq.get(e.seq - 1);
    const linked = e.seq === 0 ? BigInt(e.previousWord) === 0n : prior === undefined || prior.newWord === e.previousWord;
    checks.chain = linked && String(state.seq) === String(e.seq);

    const flags = Array.isArray(state.flags) ? (state.flags as string[]) : [];
    if (flags.includes(FLAG_TRANSITION_NOT_APPLIED) && BigInt(e.previousWord) !== 0n) {
      const before = decodeStateV1(doc, splitWordV1(e.previousWord).state96);
      const field = doc.lifecycle.field;
      checks.rule = Boolean(doc.recordAttempts) && before[field] === state[field];
      attemptedTargetUnchecked = true;
    } else {
      checks.rule = checkTransitionRuleV1(doc, { previousWord: e.previousWord, newWord: e.newWord }).ok;
      if (flags.includes(FLAG_DELIVERY_FAILED)) attemptedTargetUnchecked = true;
    }

    const itemHash = computeSlotItemHashV1({
      recordKey: form.recordKey,
      seq: e.seq,
      previousWord: BigInt(e.previousWord),
      newWord: BigInt(e.newWord),
      seal: e.seal,
    });
    try {
      checks.inclusion = verifyHiddenItemProofV1({
        itemHash,
        itemIndex: e.itemIndex,
        itemOpening: e.itemOpening,
        proof: e.merkleProof,
        expectedRoot: e.proofRoot,
      });
    } catch {
      checks.inclusion = false;
    }

    if (ledger) {
      let onChain = false;
      if (ledgerRoots.get(e.batchId) === e.proofRoot) {
        try {
          onChain = verifyLedgerChainV1({
            genesisHead: ledger.genesisHead,
            batches: ledger.batches,
            expectedHead: ledger.head,
            receipt: { batchId: e.batchId, proofRoot: e.proofRoot },
          }).verified;
        } catch {
          onChain = false;
        }
      }
      checks.ledger = onChain;
    }

    const order: SealHistoryCheckNameV1[] = ['tag', 'chain', 'rule', 'inclusion', 'ledger'];
    const failedCheck = order.find((k) => checks[k] === false) ?? null;
    if (failedCheck) failedSeq.push(e.seq);
    perEntry.push({ seq: e.seq, checks, failedCheck, attemptedTargetUnchecked });
  }

  let closed = false;
  let closedAtSeq: number | null = null;
  const terminal = new Set(doc.lifecycle.terminal ?? []);
  if (form.currentWord !== null) {
    const now = decodeStateV1(doc, splitWordV1(form.currentWord).state96);
    closed = terminal.has(String(now[doc.lifecycle.field]));
  }
  if (closed) {
    for (const e of entries) {
      const s = decodeStateV1(doc, splitWordV1(e.newWord).state96);
      if (terminal.has(String(s[doc.lifecycle.field]))) {
        closedAtSeq = e.seq;
        break;
      }
    }
  }

  if (form.currentWord === null) {
    if (entries.length === 0) {
      return {
        ...emptyResult('Nothing in this record has been committed yet.', base),
        verified: failedSeq.length === 0,
        nothingCommitted: true,
        ledgerChecked,
        chainWordMatches,
      };
    }
    return {
      ...emptyResult('The seal history has entries but no current word.', base),
      failedSeq,
      perEntry,
      ledgerChecked,
      chainWordMatches,
    };
  }

  const current = Number(String(decodeStateV1(doc, splitWordV1(form.currentWord).state96).seq));
  const queued = new Set(form.pending.filter((p) => p.status === 'queued' && p.seq !== null).map((p) => p.seq as number));
  const settlingSeq: number[] = [];
  const missingSeq: number[] = [];
  for (let seq = 0; seq <= current; seq += 1) {
    if (bySeq.has(seq)) continue;
    if (queued.has(seq)) settlingSeq.push(seq);
    else missingSeq.push(seq);
  }
  const atCurrent = bySeq.get(current);
  const headOk = atCurrent ? atCurrent.newWord === form.currentWord : settlingSeq.includes(current);
  const extra = entries.some((e) => e.seq > current);
  const complete = missingSeq.length === 0 && settlingSeq.length === 0 && headOk && !extra;
  const verified = failedSeq.length === 0 && missingSeq.length === 0 && headOk && !extra;
  const reason = failedSeq.length
    ? `Entries failed their checks: ${failedSeq.map((s) => s + 1).join(', ')}.`
    : missingSeq.length
      ? `Entry ${missingSeq[0] + 1} is missing from the seal history.`
      : !headOk || extra
        ? 'The latest entry does not end at the current ledger word.'
        : settlingSeq.length
          ? 'The seals match; some entries are still being recorded.'
          : 'The seals match what was committed.';
  return {
    verified,
    ...base,
    nothingCommitted: false,
    complete,
    settlingSeq,
    missingSeq,
    failedSeq,
    closed,
    closedAtSeq,
    perEntry,
    ledgerChecked,
    chainWordMatches,
    reason,
  };
}

/** The seq an entered value belongs to: 40 hex characters against each seal tag, 64 against each seal and each new word. */
export function findSealV1(form: RecordSealHistoryV1, value: string): number | null {
  const hex = String(value ?? '').trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(hex)) return null;
  if (hex.length === 40) {
    const found = form.entries.find((e) => e.seal.slice(-40) === hex);
    return found ? found.seq : null;
  }
  if (hex.length === 64) {
    const found = form.entries.find((e) => e.seal.slice(2) === hex || e.newWord.slice(2) === hex);
    return found ? found.seq : null;
  }
  return null;
}

/**
 * R2's seal history form for verifyRecordDisclosureV1, from a seal history
 * that verified: exactly the entries whose seq the disclosure names, in seq
 * order, with `recordHash` on a v2 or v3 record's entries only, and the
 * seal history's own `recordHashVersion` (never the disclosure's). Null when
 * a named seq is not in the history, or such an entry has no served record
 * hash.
 */
export function disclosureFormOfV1(
  sealHistory: RecordSealHistoryV1,
  disclosure: Pick<RecordDisclosure, 'recordHashVersion' | 'entries'>,
): SealHistoryFormForDisclosureV1 | null {
  if (!disclosure || !Array.isArray(disclosure.entries)) return null;
  const bySeq = new Map(sealHistory.entries.map((e) => [e.seq, e] as const));
  const seqs = [...new Set(disclosure.entries.map((e) => e?.seq))].sort((a, b) => a - b);
  const v2 = disclosure.recordHashVersion === 2 || disclosure.recordHashVersion === 3;
  const entries: SealHistoryEntryForDisclosureV1[] = [];
  for (const seq of seqs) {
    const e = bySeq.get(seq);
    if (!e) return null;
    if (v2 && e.recordHash === undefined) return null;
    entries.push({
      seq: e.seq,
      previousWord: e.previousWord,
      newWord: e.newWord,
      ...(v2 ? { recordHash: e.recordHash } : {}),
      itemIndex: e.itemIndex,
      itemOpening: e.itemOpening,
      merkleProof: [...e.merkleProof],
      batchId: e.batchId,
    });
  }
  return {
    recordKey: sealHistory.recordKey,
    chain: { ...sealHistory.chain },
    layout: { ...sealHistory.layout },
    ...(sealHistory.recordHashVersion === 3 ? { recordHashVersion: 3 as const } : {}),
    entries,
  };
}

export const CHAIN_ROOT_READ_TIMEOUT_MS_V1 = 8000;
const CHAIN_ROOT_READS_IN_FLIGHT_V1 = 4;

/**
 * One getBatchRoot call per distinct batch on the reader given, at most four
 * in flight, each bounded at 8000 ms here whatever the reader does. A throw,
 * a timeout, the zero root or anything but 32-byte lowercase hex is left
 * out, so R2's verifier answers DISCLOSURE_CHAIN_ROOT_MISSING for it. Never
 * throws, and never reads a root from anything PacSpace served.
 */
export async function readChainRootsV1(
  reader: RecordChainReader | null,
  batchIds: readonly (string | number)[],
): Promise<{ chainRoots: ChainBatchRootsV1; leftOut: string[] }> {
  const ids = [...new Set((batchIds ?? []).map((b) => String(b)))];
  const chainRoots: Record<string, string> = {};
  const leftOut: string[] = [];
  if (!reader) return { chainRoots, leftOut: ids };
  const bounded = (id: string) =>
    new Promise<string | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), CHAIN_ROOT_READ_TIMEOUT_MS_V1);
      let call: Promise<string>;
      try {
        call = Promise.resolve(reader.getBatchRoot(id));
      } catch {
        clearTimeout(timer);
        resolve(null);
        return;
      }
      call.then(
        (root) => {
          clearTimeout(timer);
          resolve(typeof root === 'string' ? root.toLowerCase() : null);
        },
        () => {
          clearTimeout(timer);
          resolve(null);
        },
      );
    });
  let next = 0;
  const worker = async () => {
    while (next < ids.length) {
      const id = ids[next];
      next += 1;
      const root = await bounded(id);
      if (root !== null && HEX32.test(root) && root !== ZERO32) chainRoots[id] = root;
      else leftOut.push(id);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CHAIN_ROOT_READS_IN_FLIGHT_V1, ids.length) }, worker));
  return { chainRoots, leftOut: leftOut.sort() };
}

/** The page's and the card's mirror reader for the served chain, or null when one cannot be made. */
export function mirrorRecordChainReaderV1(chain: { chainId: number; contractAddress: string }): RecordChainReader | null {
  try {
    return createMirrorNodeRecordChainReader({
      chainId: chain.chainId,
      contractAddress: chain.contractAddress,
      timeoutMs: CHAIN_ROOT_READ_TIMEOUT_MS_V1,
      attempts: 2,
    });
  } catch {
    return null;
  }
}

export type HeldEntryResultV1 =
  | {
      seq: number;
      matches: true;
      fields: RecordLeafV2[];
      withheld: number;
      content: Record<string, unknown> | null;
    }
  | { seq: number | null; matches: false; refused: RecordDisclosureRefusalV1 | 'DISCLOSURE_FORM_UNAVAILABLE' };

export type HeldCopyCheckV1 =
  | { kind: 'entries'; entries: HeldEntryResultV1[] }
  | { kind: 'different-record' }
  | { kind: 'file' };

const RECEIPT_SCHEMAS = new Set(['semantic-receipt/v2', 'semantic-receipt/v3', 'semantic-receipt/v6']);
const BUNDLE_SCHEMAS = new Set(['record-history-bundle/v1', 'record-history-bundle/v2']);

async function checkDisclosureAgainst(
  form: RecordSealHistoryV1,
  disclosure: RecordDisclosure,
  chainRoots: ChainBatchRootsV1,
): Promise<HeldEntryResultV1[]> {
  const sub = disclosureFormOfV1(form, disclosure);
  if (!sub) return [{ seq: null, matches: false, refused: 'DISCLOSURE_FORM_UNAVAILABLE' }];
  const result = await verifyRecordDisclosureV1({ form: sub, chainRoots, disclosure });
  if (!result.ok) return [{ seq: result.seq, matches: false, refused: result.code }];
  return result.entries.map((e) => ({
    seq: e.seq,
    matches: true,
    fields: e.fields,
    withheld: e.withheld,
    content: e.content,
  }));
}

async function checkReceipt(
  form: RecordSealHistoryV1,
  receipt: RecordReceipt | RecordReceiptV3Items,
  chainRoots: ChainBatchRootsV1,
): Promise<HeldEntryResultV1[]> {
  let disclosure: RecordDisclosure;
  try {
    disclosure = await buildRecordDisclosureV1({
      recordKey: form.recordKey,
      chain: form.chain,
      layout: form.layout,
      entries: [{ receipt, reveal: 'all' }],
    });
  } catch {
    return [{ seq: typeof receipt?.seq === 'number' ? receipt.seq : null, matches: false, refused: 'DISCLOSURE_MALFORMED' }];
  }
  return checkDisclosureAgainst(form, disclosure, chainRoots);
}

/**
 * Every held copy goes through R2's one verifier (section 5.4): a receipt
 * or a history file is turned into a whole disclosure, one receipt at a
 * time; a disclosure file is verified as it stands; a kept copy by its
 * disclosure, against the served form. Anything else is treated as a file.
 */
export async function checkHeldCopyV1(
  form: RecordSealHistoryV1,
  held: unknown,
  options: { layouts?: LayoutRegistry; chainRoots: ChainBatchRootsV1 },
): Promise<HeldCopyCheckV1> {
  if (!isPlainObject(held) || typeof held.schema !== 'string') return { kind: 'file' };
  const schema = held.schema;
  const sameRecord = (key: unknown) => typeof key === 'string' && key.toLowerCase() === form.recordKey;
  if (RECEIPT_SCHEMAS.has(schema)) {
    if (!sameRecord(held.recordKey)) return { kind: 'different-record' };
    return { kind: 'entries', entries: await checkReceipt(form, held as unknown as RecordReceipt | RecordReceiptV3Items, options.chainRoots) };
  }
  if (BUNDLE_SCHEMAS.has(schema)) {
    if (!sameRecord(held.recordKey)) return { kind: 'different-record' };
    const receipts = Array.isArray(held.receipts) ? (held.receipts as RecordReceipt[]) : [];
    const entries: HeldEntryResultV1[] = [];
    for (const receipt of receipts) entries.push(...(await checkReceipt(form, receipt, options.chainRoots)));
    return { kind: 'entries', entries };
  }
  if (schema === RECORD_DISCLOSURE_SCHEMA_V1 || schema === RECORD_DISCLOSURE_SCHEMA_V2) {
    if (!sameRecord(held.recordKey)) return { kind: 'different-record' };
    return {
      kind: 'entries',
      entries: await checkDisclosureAgainst(form, held as unknown as RecordDisclosure, options.chainRoots),
    };
  }
  if (schema === 'record-link-copy/v1') {
    const disclosure = held.disclosure;
    if (disclosure === null) return { kind: 'entries', entries: [] };
    if (!isPlainObject(disclosure)) return { kind: 'file' };
    if (!sameRecord(disclosure.recordKey)) return { kind: 'different-record' };
    return {
      kind: 'entries',
      entries: await checkDisclosureAgainst(form, disclosure as unknown as RecordDisclosure, options.chainRoots),
    };
  }
  return { kind: 'file' };
}

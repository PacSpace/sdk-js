import { verifyHiddenItemProofV1 } from '../proof/hiding-commitment-v1';
import { canonicalizeJcs } from '../proof/jcs';
import type { RecordReceipt } from '../proof/semantic-receipt-v3';
import { computeRecordHashV1, computeSealV1, computeSlotItemHashV1, sealTagOfV1, splitWordV1 } from '../proof/slot-encoding-v1';
import { concatBytes, isHex32, sha256, toHex0x, utf8 } from './platform-crypto';
import {
  RECORD_LEAVES_MAX_V2,
  openRecordEntryV2,
  parsePointerV2,
  recordLeavesV2,
  type RecordLeafV2,
  type RevealedLeafV2,
} from './record-hash-v2';

/**
 * record-disclosure/v1 (ADR 0016; record-hash-v2.md): chosen entries of one
 * record, each with the fields its owner chose to show. A reader checks each
 * shown field against the entry's leaves, the leaves against the seal, and
 * the seal's item through its Merkle path to a batch root the reader read
 * from the chain itself. The verifier returns a result and never throws.
 */
export const RECORD_DISCLOSURE_SCHEMA_V1 = 'record-disclosure/v1' as const;
export const RECORD_DISCLOSURE_MAX_BYTES_V1 = 1048576;

export type RecordDisclosureEntryV1 =
  | { seq: number; recordOpening: string; leaves: string[]; revealed: RevealedLeafV2[] }
  | { seq: number; recordOpening: string; recordContent: Record<string, unknown> };

export interface RecordDisclosureV1 {
  schema: typeof RECORD_DISCLOSURE_SCHEMA_V1;
  recordKey: string;
  chain: { chainId: number; contractAddress: string };
  layout: { layoutId: number; layoutVersion: number; layoutDigest: string };
  recordHashVersion: 1 | 2;
  entries: RecordDisclosureEntryV1[];
  digest: string;
}

export interface SealHistoryEntryForDisclosureV1 {
  seq: number;
  previousWord: string;
  newWord: string;
  recordHash?: string;
  itemIndex: number;
  itemOpening: string;
  merkleProof: string[];
  batchId: number;
}

export interface SealHistoryFormForDisclosureV1 {
  recordKey: string;
  chain: { chainId: number; contractAddress: string };
  layout: { layoutId: number; layoutVersion: number; layoutDigest: string };
  entries: SealHistoryEntryForDisclosureV1[];
}

/** Batch roots the caller read from the chain itself, by batchId in decimal. Never a root PacSpace served. */
export type ChainBatchRootsV1 = Readonly<Record<string, string>>;

export type RecordDisclosureRefusalV1 =
  | 'DISCLOSURE_MALFORMED'
  | 'DISCLOSURE_TOO_LARGE'
  | 'DISCLOSURE_DIGEST_MISMATCH'
  | 'DISCLOSURE_RECORD_MISMATCH'
  | 'DISCLOSURE_ENTRY_NOT_IN_HISTORY'
  | 'DISCLOSURE_LEAF_MISMATCH'
  | 'DISCLOSURE_SEAL_MISMATCH'
  | 'DISCLOSURE_CHAIN_ROOT_MISSING';

export type RecordDisclosureVerificationV1 =
  | {
      ok: true;
      recordHashVersion: 1 | 2;
      entries: Array<{ seq: number; batchId: number; fields: RecordLeafV2[]; withheld: number; content: Record<string, unknown> | null }>;
    }
  | { ok: false; code: RecordDisclosureRefusalV1; seq: number | null; reason: string };

const REASONS = {
  DISCLOSURE_MALFORMED: () => 'This is not a record disclosure this version can read.',
  DISCLOSURE_TOO_LARGE: () => 'This disclosure is larger than 1 MiB, the most one disclosure may hold.',
  DISCLOSURE_DIGEST_MISMATCH: () => 'This disclosure was changed after it was made: its digest does not match its contents.',
  DISCLOSURE_RECORD_MISMATCH: () => 'This disclosure is for a different record than the history it was checked against.',
  DISCLOSURE_ENTRY_NOT_IN_HISTORY: (n: number) => `Entry ${n} of this disclosure is not in the record's sealed history.`,
  DISCLOSURE_LEAF_MISMATCH: (n: number) => `A shown field of entry ${n} does not match the fields sealed for that entry.`,
  DISCLOSURE_SEAL_MISMATCH: (n: number) => `Entry ${n} of this disclosure does not reproduce the seal recorded on the ledger for it.`,
  DISCLOSURE_CHAIN_ROOT_MISSING: (n: number) =>
    `Entry ${n} could not be checked: the ledger's record of its batch was not available. Try again.`,
} as const;
const RECORD_HASH_MISMATCH = (n: number) => `Entry ${n} of this disclosure does not match the record hash in the record's sealed history.`;

/** Thrown by the builder and the encryption; its message is the refusal's fixed sentence. */
export class RecordDisclosureError extends Error {
  constructor(readonly code: 'DISCLOSURE_MALFORMED' | 'DISCLOSURE_TOO_LARGE') {
    super(REASONS[code]());
    this.name = 'RecordDisclosureError';
  }
}

const DIGEST_LABEL = 'pacspace:record-disclosure-digest:v1';
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO32 = '0x' + '0'.repeat(64);
const UINT32_MAX = 4294967295;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

function hasLoneSurrogate(value: unknown): boolean {
  if (typeof value === 'string') return LONE_SURROGATE.test(value);
  if (Array.isArray(value)) return value.some(hasLoneSurrogate);
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([k, v]) => LONE_SURROGATE.test(k) || hasLoneSurrogate(v));
  }
  return false;
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const hasExactly = (v: Record<string, unknown>, keys: readonly string[]) => {
  const own = Object.keys(v);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));
};
const isUint32 = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= UINT32_MAX;
const isSafeNatural = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/** SHA-256("pacspace:record-disclosure-digest:v1" || 0x00 || utf8(JCS(disclosure without "digest"))). */
export async function computeRecordDisclosureDigestV1(disclosure: Omit<RecordDisclosureV1, 'digest'> & { digest?: string }): Promise<string> {
  const rest: Record<string, unknown> = { ...disclosure };
  delete rest.digest;
  return toHex0x(await sha256(concatBytes(utf8(DIGEST_LABEL), new Uint8Array([0]), utf8(canonicalizeJcs(rest)))));
}

function chainShapeOk(chain: unknown, exact: boolean): chain is { chainId: number; contractAddress: string } {
  return (
    isPlainObject(chain) &&
    (!exact || hasExactly(chain, ['chainId', 'contractAddress'])) &&
    isSafeNatural(chain.chainId) &&
    typeof chain.contractAddress === 'string' &&
    ADDRESS.test(chain.contractAddress)
  );
}

function layoutShapeOk(layout: unknown, exact: boolean): layout is { layoutId: number; layoutVersion: number; layoutDigest: string } {
  return (
    isPlainObject(layout) &&
    (!exact || hasExactly(layout, ['layoutId', 'layoutVersion', 'layoutDigest'])) &&
    isSafeNatural(layout.layoutId) &&
    isSafeNatural(layout.layoutVersion) &&
    isHex32(layout.layoutDigest)
  );
}

function revealedShapeOk(revealed: unknown, leafCount: number): boolean {
  if (!Array.isArray(revealed) || revealed.length > leafCount) return false;
  for (let i = 0; i < revealed.length; i += 1) {
    const leaf = revealed[i];
    if (!isPlainObject(leaf) || !hasExactly(leaf, ['pointer', 'value', 'salt'])) return false;
    if (typeof leaf.pointer !== 'string' || !parsePointerV2(leaf.pointer) || !isHex32(leaf.salt)) return false;
    if (hasLoneSurrogate(leaf.value)) return false;
    if (i > 0 && !((revealed[i - 1] as RevealedLeafV2).pointer < leaf.pointer)) return false;
  }
  return true;
}

function entryShapeOk(entry: unknown, version: 1 | 2): boolean {
  if (!isPlainObject(entry) || !isUint32(entry.seq) || !isHex32(entry.recordOpening)) return false;
  if (version === 1) {
    return hasExactly(entry, ['seq', 'recordOpening', 'recordContent']) && isPlainObject(entry.recordContent) && !hasLoneSurrogate(entry.recordContent);
  }
  if (!hasExactly(entry, ['seq', 'recordOpening', 'leaves', 'revealed'])) return false;
  const leaves = entry.leaves;
  if (!Array.isArray(leaves) || leaves.length > RECORD_LEAVES_MAX_V2) return false;
  for (let i = 0; i < leaves.length; i += 1) {
    if (!isHex32(leaves[i]) || (i > 0 && !(leaves[i - 1] < leaves[i]))) return false;
  }
  return revealedShapeOk(entry.revealed, leaves.length);
}

function disclosureShapeOk(d: Record<string, unknown>): d is Record<string, unknown> & RecordDisclosureV1 {
  if (!hasExactly(d, ['schema', 'recordKey', 'chain', 'layout', 'recordHashVersion', 'entries', 'digest'])) return false;
  if (!isHex32(d.recordKey) || !isHex32(d.digest)) return false;
  if (!chainShapeOk(d.chain, true) || !layoutShapeOk(d.layout, true)) return false;
  if (d.recordHashVersion !== 1 && d.recordHashVersion !== 2) return false;
  const entries = d.entries;
  if (!Array.isArray(entries) || entries.length === 0) return false;
  for (let i = 0; i < entries.length; i += 1) {
    if (!entryShapeOk(entries[i], d.recordHashVersion)) return false;
    if (i > 0 && !(entries[i - 1].seq < entries[i].seq)) return false;
  }
  return true;
}

function formShapeOk(form: unknown): form is SealHistoryFormForDisclosureV1 {
  if (!isPlainObject(form) || !isHex32(form.recordKey)) return false;
  if (!chainShapeOk(form.chain, false) || !layoutShapeOk(form.layout, false)) return false;
  const entries = form.entries;
  if (!Array.isArray(entries)) return false;
  for (let i = 0; i < entries.length; i += 1) {
    const e = entries[i];
    if (!isPlainObject(e) || !isUint32(e.seq) || !isUint32(e.itemIndex) || !isSafeNatural(e.batchId)) return false;
    if (!isHex32(e.previousWord) || !isHex32(e.newWord) || !isHex32(e.itemOpening)) return false;
    if (e.recordHash !== undefined && !isHex32(e.recordHash)) return false;
    if (!Array.isArray(e.merkleProof) || e.merkleProof.length > 32 || !e.merkleProof.every(isHex32)) return false;
    if (i > 0 && !((entries[i - 1] as SealHistoryEntryForDisclosureV1).seq < e.seq)) return false;
  }
  return true;
}

function refuse(code: RecordDisclosureRefusalV1, seq: number | null, reason?: string): RecordDisclosureVerificationV1 {
  const n = seq === null ? 0 : seq + 1;
  return { ok: false, code, seq, reason: reason ?? REASONS[code](n) };
}

/** Section 6's algorithm, in order, stopping at the first refusal. Trusts only `chainRoots`. */
export async function verifyRecordDisclosureV1(input: {
  form: SealHistoryFormForDisclosureV1;
  chainRoots: ChainBatchRootsV1;
  disclosure: unknown;
}): Promise<RecordDisclosureVerificationV1> {
  try {
    return await verifyDisclosure(input);
  } catch {
    return refuse('DISCLOSURE_MALFORMED', null);
  }
}

async function verifyDisclosure(input: {
  form: SealHistoryFormForDisclosureV1;
  chainRoots: ChainBatchRootsV1;
  disclosure: unknown;
}): Promise<RecordDisclosureVerificationV1> {
  const d = input?.disclosure;
  if (!isPlainObject(d) || d.schema !== RECORD_DISCLOSURE_SCHEMA_V1) return refuse('DISCLOSURE_MALFORMED', null);

  let canonical: string;
  try {
    canonical = canonicalizeJcs(d);
  } catch {
    return refuse('DISCLOSURE_MALFORMED', null);
  }
  if (utf8(canonical).length > RECORD_DISCLOSURE_MAX_BYTES_V1) return refuse('DISCLOSURE_TOO_LARGE', null);

  const form = input.form;
  if (!disclosureShapeOk(d) || !formShapeOk(form)) return refuse('DISCLOSURE_MALFORMED', null);

  if ((await computeRecordDisclosureDigestV1(d)) !== d.digest) return refuse('DISCLOSURE_DIGEST_MISMATCH', null);

  if (
    d.recordKey !== form.recordKey ||
    d.chain.chainId !== form.chain.chainId ||
    d.chain.contractAddress !== form.chain.contractAddress ||
    d.layout.layoutId !== form.layout.layoutId ||
    d.layout.layoutVersion !== form.layout.layoutVersion ||
    d.layout.layoutDigest !== form.layout.layoutDigest
  ) {
    return refuse('DISCLOSURE_RECORD_MISMATCH', null);
  }

  const bySeq = new Map(form.entries.map((e) => [e.seq, e] as const));
  const roots: Record<string, unknown> = isPlainObject(input.chainRoots) ? input.chainRoots : {};
  const out: Extract<RecordDisclosureVerificationV1, { ok: true }>['entries'] = [];
  for (const entry of d.entries) {
    const seq = entry.seq;
    const formEntry = bySeq.get(seq);
    if (!formEntry) return refuse('DISCLOSURE_ENTRY_NOT_IN_HISTORY', seq);

    let recordHash: string;
    let fields: RecordLeafV2[];
    let withheld: number;
    let content: Record<string, unknown> | null;
    if ('leaves' in entry) {
      const opened = await openRecordEntryV2(entry, { every: false });
      if (!opened.ok) return refuse(opened.failure === 'leaf-mismatch' ? 'DISCLOSURE_LEAF_MISMATCH' : 'DISCLOSURE_MALFORMED', seq);
      ({ recordHash, fields, withheld, content } = opened);
    } else {
      try {
        recordHash = computeRecordHashV1(entry.recordContent);
        fields = recordLeavesV2(entry.recordContent);
      } catch {
        return refuse('DISCLOSURE_MALFORMED', seq);
      }
      withheld = 0;
      content = entry.recordContent;
    }

    if (formEntry.recordHash !== undefined && formEntry.recordHash !== recordHash) {
      return refuse('DISCLOSURE_SEAL_MISMATCH', seq, RECORD_HASH_MISMATCH(seq + 1));
    }

    const newWord = BigInt(formEntry.newWord);
    const split = splitWordV1(newWord);
    const seal = computeSealV1({
      layoutId: d.layout.layoutId,
      layoutVersion: d.layout.layoutVersion,
      layoutDigest: d.layout.layoutDigest,
      state96: split.state96,
      recordHash,
      recordOpening: entry.recordOpening,
    });
    if (sealTagOfV1(seal) !== split.sealTag) return refuse('DISCLOSURE_SEAL_MISMATCH', seq);

    const root = roots[String(formEntry.batchId)];
    if (!isHex32(root) || root === ZERO32) return refuse('DISCLOSURE_CHAIN_ROOT_MISSING', seq);

    const itemHash = computeSlotItemHashV1({
      recordKey: d.recordKey,
      seq,
      previousWord: BigInt(formEntry.previousWord),
      newWord,
      seal,
    });
    let included = false;
    try {
      included = verifyHiddenItemProofV1({
        itemHash,
        itemIndex: formEntry.itemIndex,
        itemOpening: formEntry.itemOpening,
        proof: formEntry.merkleProof,
        expectedRoot: root,
      });
    } catch {
      included = false;
    }
    if (!included) return refuse('DISCLOSURE_SEAL_MISMATCH', seq);
    out.push({ seq, batchId: formEntry.batchId, fields, withheld, content });
  }
  return { ok: true, recordHashVersion: d.recordHashVersion, entries: out };
}

/**
 * Builds a disclosure from receipts the caller holds (a tenant's receipts or
 * a served bundle's). A semantic-receipt/v3 entry shows the listed fields; a
 * semantic-receipt/v2 entry is shown whole. It never needs a salt key.
 */
export async function buildRecordDisclosureV1(input: {
  recordKey: string;
  chain: { chainId: number; contractAddress: string };
  layout: { layoutId: number; layoutVersion: number; layoutDigest: string };
  entries: Array<{ receipt: RecordReceipt; reveal: 'all' | string[] }>;
}): Promise<RecordDisclosureV1> {
  const malformed = () => new RecordDisclosureError('DISCLOSURE_MALFORMED');
  if (!input || !Array.isArray(input.entries) || input.entries.length === 0) throw malformed();
  const recordKey = String(input.recordKey).toLowerCase();
  const schemas = new Set(input.entries.map((e) => e?.receipt?.schema));
  if (schemas.size !== 1) throw malformed();
  const schema = [...schemas][0];
  if (schema !== 'semantic-receipt/v2' && schema !== 'semantic-receipt/v3') throw malformed();
  const version: 1 | 2 = schema === 'semantic-receipt/v3' ? 2 : 1;

  const seen = new Set<number>();
  const entries: RecordDisclosureEntryV1[] = [];
  for (const { receipt, reveal } of input.entries) {
    if (String(receipt.recordKey).toLowerCase() !== recordKey || seen.has(receipt.seq)) throw malformed();
    seen.add(receipt.seq);
    if (receipt.schema === 'semantic-receipt/v2') {
      if (reveal !== 'all') throw malformed();
      entries.push({ seq: receipt.seq, recordOpening: receipt.recordOpening, recordContent: receipt.recordContent });
      continue;
    }
    let revealed: RevealedLeafV2[];
    if (reveal === 'all') {
      revealed = receipt.revealed.map((l) => ({ pointer: l.pointer, value: l.value, salt: l.salt }));
    } else {
      if (!Array.isArray(reveal) || new Set(reveal).size !== reveal.length) throw malformed();
      const wanted = new Set(reveal);
      const known = new Set(receipt.revealed.map((l) => l.pointer));
      if (reveal.some((p) => !known.has(p))) throw malformed();
      revealed = receipt.revealed.filter((l) => wanted.has(l.pointer)).map((l) => ({ pointer: l.pointer, value: l.value, salt: l.salt }));
    }
    entries.push({ seq: receipt.seq, recordOpening: receipt.recordOpening, leaves: [...receipt.leaves], revealed });
  }
  entries.sort((a, b) => a.seq - b.seq);

  const body: Omit<RecordDisclosureV1, 'digest'> = {
    schema: RECORD_DISCLOSURE_SCHEMA_V1,
    recordKey,
    chain: { chainId: input.chain.chainId, contractAddress: String(input.chain.contractAddress).toLowerCase() },
    layout: { layoutId: input.layout.layoutId, layoutVersion: input.layout.layoutVersion, layoutDigest: input.layout.layoutDigest },
    recordHashVersion: version,
    entries,
  };
  const disclosure: RecordDisclosureV1 = { ...body, digest: await computeRecordDisclosureDigestV1(body) };
  if (utf8(canonicalizeJcs(disclosure)).length > RECORD_DISCLOSURE_MAX_BYTES_V1) {
    throw new RecordDisclosureError('DISCLOSURE_TOO_LARGE');
  }
  return disclosure;
}

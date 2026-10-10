import { ethers } from 'ethers';
import { canonicalizeJcs } from './jcs';
import {
  DecodedState,
  LayoutDocumentV1,
  RecordIntakeError,
  StateFieldValues,
  computeLayoutDigestV1,
  decodeStateV1,
  isTransitionAllowedV1,
  packStateV1,
  readLayoutIdFromState,
} from './layout-document-v1';
import { validatePayloadRefsInContent } from './payload-ref-v1';
import {
  buildHidingCommitmentsV1,
  computePublishedLeafV1,
  deriveItemOpeningV1,
} from './hiding-commitment-v1';
import { buildMerkleProofV2, computeMerkleItemsRootV2, normalizeProofHash } from './merkle-v2';
import { nextLedgerHeadV1 } from './ledger-head-v1';

/**
 * slot-encoding-v1: the byte-exact construction of the additive record lane
 * (ADR 0012; docs/spec/records/slot-encoding-v1.md). Every function here is
 * mirrored by scripts/records/generate-slot-encoding-vectors.mjs and pinned
 * by packages/shared/src/proof/__vectors__/slot-encoding-v1.json.
 *
 * The bitmask lane (canonical-item-v1, hiding-commitment-v1, merkle-v2,
 * semantic-receipt-v1) is not modified; this module composes it.
 */

export const SLOT_ENCODING_VERSION_V1 = 1;
export const SLOT_STATE_BITS = 96;
export const SLOT_SEAL_BITS = 160;
export const SLOT_SEAL_MASK = (1n << 160n) - 1n;
// Upper bound of the state region (2^96 - 1). Written as a mask, not a shift:
// the record lane never shifts a wallet or a raw index into a key (ADR 0008 §2
// gate); the state region is a bounded field under a published layout.
export const SLOT_STATE_MASK = (1n << BigInt(SLOT_STATE_BITS)) - 1n;
export const SLOT_ITEM_KIND_V1 = 'slot-v1';

export const SLOT_DOMAINS_V1 = {
  slotKey: 'pacspace:slot-key:v1',
  slotOpening: 'pacspace:slot-opening:v1',
  slotCommit: 'pacspace:slot-commit:v1',
  record: 'pacspace:record:v1',
  slotItem: 'pacspace:slot-item:v1',
  intake: 'pacspace:record-intake:v1',
} as const;

export const WRITE_RECORD_BATCH_SIGNATURE_V1 =
  'writeRecordBatchAndCommit(bytes32[],uint256[],uint256[],uint8,bytes32,uint256)';

/** Reserved flag names every layout that records attempts or failures carries. */
export const FLAG_TRANSITION_NOT_APPLIED = 'transition_not_applied';
export const FLAG_DELIVERY_FAILED = 'delivery_failed';

const SEP = new Uint8Array([0x00]);
const utf8 = (s: string) => ethers.toUtf8Bytes(s);
const bytes = (h: string) => ethers.getBytes(h);

function uintBe(value: bigint | number | string, bits: number): Uint8Array {
  const v = BigInt(value);
  if (v < 0n || v >= 1n << BigInt(bits)) {
    throw new RecordIntakeError('RECORD_QUANTITY_OVERFLOW', `value ${v} is out of uint${bits} range`);
  }
  return bytes(ethers.toBeHex(v, bits / 8));
}

export const hex256 = (v: bigint | number | string): string => ethers.toBeHex(BigInt(v), 32);
export const hex160 = (v: bigint | number | string): string => ethers.toBeHex(BigInt(v), 20);
export const hex96 = (v: bigint | number | string): string => ethers.toBeHex(BigInt(v), 12);

// ----------------------------------------------------------------- registry

export interface RegisteredLayout {
  doc: LayoutDocumentV1;
  digest: string;
}

export type LayoutRegistry = ReadonlyMap<number, RegisteredLayout>;

export function buildLayoutRegistry(docs: LayoutDocumentV1[]): LayoutRegistry {
  const map = new Map<number, RegisteredLayout>();
  for (const doc of docs) map.set(doc.layoutId, { doc, digest: computeLayoutDigestV1(doc) });
  return map;
}

export function getLayoutOrThrow(registry: LayoutRegistry, layoutId: number): RegisteredLayout {
  const found = registry.get(layoutId);
  if (!found) throw new RecordIntakeError('LAYOUT_NOT_FOUND', `layout 0x${layoutId.toString(16).padStart(4, '0')} is not registered`);
  return found;
}

// ----------------------------------------------------------------- primitives

/** recordKey = HMAC-SHA256(tenantKey, domain || 0x00 || recordTypeId || 0x00 || entityId). */
export function deriveRecordKeyV1(tenantKey: string, recordTypeId: string, entityId: string): string {
  const key = normalizeProofHash(tenantKey, 'tenantKey');
  return ethers.computeHmac(
    'sha256',
    key,
    ethers.concat([utf8(SLOT_DOMAINS_V1.slotKey), SEP, utf8(recordTypeId), SEP, utf8(entityId)]),
  );
}

/** recordHash = keccak256(domain || 0x00 || JCS(content)). */
export function computeRecordHashV1(content: unknown): string {
  return ethers.keccak256(ethers.concat([utf8(SLOT_DOMAINS_V1.record), SEP, utf8(canonicalizeJcs(content))]));
}

/** recordOpening = HMAC-SHA256(batchSeed, domain || 0x00 || uint32be(itemIndex) || recordKey). */
export function deriveRecordOpeningV1(batchSeed: string, itemIndex: number, recordKey: string): string {
  const seed = normalizeProofHash(batchSeed, 'batchSeed');
  const key = normalizeProofHash(recordKey, 'recordKey');
  return ethers.computeHmac(
    'sha256',
    seed,
    ethers.concat([utf8(SLOT_DOMAINS_V1.slotOpening), SEP, uintBe(itemIndex, 32), bytes(key)]),
  );
}

export interface SealInputV1 {
  layoutId: number;
  layoutVersion: number;
  layoutDigest: string;
  state96: bigint;
  recordHash: string;
  recordOpening: string;
}

/** seal = keccak256(domain||0x00||uint16be(layoutId)||uint8(layoutVersion)||layoutDigest||uint96be(state96)||recordHash||recordOpening). */
export function computeSealV1(input: SealInputV1): string {
  return ethers.keccak256(
    ethers.concat([
      utf8(SLOT_DOMAINS_V1.slotCommit),
      SEP,
      uintBe(input.layoutId, 16),
      uintBe(input.layoutVersion, 8),
      bytes(normalizeProofHash(input.layoutDigest, 'layoutDigest')),
      uintBe(input.state96, 96),
      bytes(normalizeProofHash(input.recordHash, 'recordHash')),
      bytes(normalizeProofHash(input.recordOpening, 'recordOpening')),
    ]),
  );
}

export function sealTagOfV1(seal: string): string {
  return hex160(BigInt(normalizeProofHash(seal, 'seal')) & SLOT_SEAL_MASK);
}

export function composeWordV1(state96: bigint, seal: string): bigint {
  if (state96 < 0n || state96 > SLOT_STATE_MASK) throw new RecordIntakeError('RECORD_QUANTITY_OVERFLOW', 'state96 out of range');
  return (state96 << 160n) | (BigInt(normalizeProofHash(seal, 'seal')) & SLOT_SEAL_MASK);
}

export interface SplitWordV1 {
  state96: bigint;
  state96Hex: string;
  sealTag: string;
  layoutId: number;
  layoutVersion: number;
}

/** Shift-and-mask: the public state region and the seal tag of a word. */
export function splitWordV1(word: string | bigint): SplitWordV1 {
  const w = BigInt(word);
  if (w < 0n || w >= 1n << 256n) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'word out of uint256 range');
  const state96 = w >> 160n;
  const { layoutId, layoutVersion } = readLayoutIdFromState(state96);
  return { state96, state96Hex: hex96(state96), sealTag: hex160(w & SLOT_SEAL_MASK), layoutId, layoutVersion };
}

/** Decode the public state of a word under the registry; LAYOUT_NOT_FOUND for unregistered layout ids. */
export function decodeWordV1(registry: LayoutRegistry, word: string | bigint): SplitWordV1 & { layout: RegisteredLayout; decodedState: DecodedState } {
  const split = splitWordV1(word);
  const layout = getLayoutOrThrow(registry, split.layoutId);
  return { ...split, layout, decodedState: decodeStateV1(layout.doc, split.state96) };
}

export interface SlotItemInputV1 {
  recordKey: string;
  seq: number;
  previousWord: string | bigint;
  newWord: string | bigint;
  seal: string;
}

/** itemHash = keccak256(domain||0x00||recordKey||uint32be(seq)||uint256be(previousWord)||uint256be(newWord)||seal). */
export function computeSlotItemHashV1(input: SlotItemInputV1): string {
  return ethers.keccak256(
    ethers.concat([
      utf8(SLOT_DOMAINS_V1.slotItem),
      SEP,
      bytes(normalizeProofHash(input.recordKey, 'recordKey')),
      uintBe(input.seq, 32),
      uintBe(BigInt(input.previousWord), 256),
      uintBe(BigInt(input.newWord), 256),
      bytes(normalizeProofHash(input.seal, 'seal')),
    ]),
  );
}

/** Intake idempotency key over tenant, record type, entity, and the reported event (excludes seq and previousWord). */
export function computeIntakeIdempotencyKeyV1(
  tenantId: string,
  recordTypeId: string,
  entityId: string,
  reportedEvent: unknown,
): string {
  return ethers.keccak256(
    ethers.concat([
      utf8(SLOT_DOMAINS_V1.intake),
      SEP,
      utf8(tenantId),
      SEP,
      utf8(recordTypeId),
      SEP,
      utf8(entityId),
      SEP,
      utf8(canonicalizeJcs(reportedEvent)),
    ]),
  );
}

// ----------------------------------------------------------------- records

export interface RecordReportV1 {
  /** Target lifecycle state by name. */
  lifecycle: string;
  /** Additional state field values (counters, quantities) applied only when the transition is applied. */
  fields?: StateFieldValues;
  /** Flag names to set. */
  flags?: string[];
  /** Sealed record content (validated against the layout's sealedRecordSchema by the caller). */
  content: Record<string, unknown>;
}

export interface PreviousRecordV1 {
  seq: number;
  word: string | bigint;
}

export type SlotRecordKind = 'transition' | 'attempt' | 'failure';

export interface BuiltSlotRecordV1 {
  layoutId: number;
  layoutVersion: number;
  layoutDigest: string;
  recordKey: string;
  seq: number;
  kind: SlotRecordKind;
  applied: boolean;
  ruleId: string | null;
  decodedState: DecodedState;
  state96: string;
  recordContent: Record<string, unknown>;
  recordBytes: string;
  recordHash: string;
  itemIndex: number;
  recordOpening: string;
  seal: string;
  sealTag: string;
  previousWord: string;
  newWord: string;
  itemHash: string;
}

export interface BuildSlotRecordInputV1 {
  layout: RegisteredLayout;
  recordKey: string;
  previous: PreviousRecordV1 | null;
  report: RecordReportV1;
  batchSeed: string;
  itemIndex: number;
  kind?: 'transition' | 'failure';
}

/**
 * Build one record for a slot from the previous word, the report, and the
 * batch position. Rejects malformed input with a registered code; a
 * forbidden transition becomes an attempt record when the layout records
 * attempts, otherwise RECORD_TRANSITION_FORBIDDEN.
 */
export function buildSlotRecordV1(input: BuildSlotRecordInputV1): BuiltSlotRecordV1 {
  const plan = planSlotRecordV1(input);
  return sealSlotRecordV1(plan, computeRecordHashV1(plan.recordContent));
}

/** Everything of one slot record that precedes its record hash (record hash v2 plans once and hashes either way). */
export interface PlannedSlotRecordV1 {
  layout: RegisteredLayout;
  recordKey: string;
  seq: number;
  kind: SlotRecordKind;
  applied: boolean;
  ruleId: string | null;
  state96: bigint;
  recordContent: Record<string, unknown>;
  previousWord: bigint;
  itemIndex: number;
  batchSeed: string;
}

/** The first half of buildSlotRecordV1: validation, the transition rule, the content and state96. */
export function planSlotRecordV1(input: BuildSlotRecordInputV1): PlannedSlotRecordV1 {
  const { doc } = input.layout;
  const kind = input.kind ?? 'transition';
  const lifecycleField = doc.lifecycle.field;
  const recordKey = normalizeProofHash(input.recordKey, 'recordKey');

  let previousWord = 0n;
  let fromLifecycle: string | null = null;
  if (input.previous) {
    previousWord = BigInt(input.previous.word);
    const prevSplit = splitWordV1(previousWord);
    if (prevSplit.layoutId !== doc.layoutId || prevSplit.layoutVersion !== doc.layoutVersion) {
      throw new RecordIntakeError(
        'RECORD_LAYOUT_MISMATCH',
        `previous word is layout ${prevSplit.layoutId}/${prevSplit.layoutVersion}, report targets ${doc.layoutId}/${doc.layoutVersion}`,
      );
    }
    const prevState = decodeStateV1(doc, prevSplit.state96);
    fromLifecycle = prevState[lifecycleField] as string;
    if (String(prevState.seq) !== String(input.previous.seq)) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `previous seq ${input.previous.seq} does not match the previous word`);
    }
  }

  let toLifecycle = input.report.lifecycle;
  const flags = [...(input.report.flags ?? [])];
  let content: Record<string, unknown> = { ...input.report.content };
  let applied = true;
  let ruleId: string | null = null;

  if (!input.previous) {
    if (!doc.lifecycle.genesis.includes(toLifecycle)) {
      throw new RecordIntakeError('RECORD_GENESIS_MISMATCH', `${toLifecycle} is not a genesis state of ${doc.name}`);
    }
  } else if (kind === 'failure') {
    toLifecycle = fromLifecycle as string;
    flags.push(FLAG_DELIVERY_FAILED);
  } else if (!isTransitionAllowedV1(doc, fromLifecycle as string, toLifecycle)) {
    if (!doc.recordAttempts) {
      throw new RecordIntakeError('RECORD_TRANSITION_FORBIDDEN', `${fromLifecycle} -> ${toLifecycle} is not in the ${doc.name} table`);
    }
    applied = false;
    ruleId = `${doc.name}#transitions.${fromLifecycle}`;
    content = { ...content, attemptedTarget: toLifecycle, ruleId };
    toLifecycle = fromLifecycle as string;
    flags.push(FLAG_TRANSITION_NOT_APPLIED);
  }

  validatePayloadRefsInContent(content);

  const seq = input.previous ? input.previous.seq + 1 : 0;
  const values: StateFieldValues = {
    layoutId: doc.layoutId,
    layoutVersion: doc.layoutVersion,
    [lifecycleField]: toLifecycle,
    flags,
    seq,
    ...(applied ? input.report.fields ?? {} : {}),
  };
  const state96 = packStateV1(doc, values);
  return {
    layout: input.layout,
    recordKey,
    seq,
    kind: applied ? kind : 'attempt',
    applied,
    ruleId,
    state96,
    recordContent: content,
    previousWord,
    itemIndex: input.itemIndex,
    batchSeed: input.batchSeed,
  };
}

/** The second half of buildSlotRecordV1: the opening, the seal, the word and the item hash, from a record hash. */
export function sealSlotRecordV1(plan: PlannedSlotRecordV1, recordHash: string): BuiltSlotRecordV1 {
  const { doc, digest } = plan.layout;
  const { recordKey, seq, state96, previousWord } = plan;
  const content = plan.recordContent;
  const recordOpening = deriveRecordOpeningV1(plan.batchSeed, plan.itemIndex, recordKey);
  const seal = computeSealV1({
    layoutId: doc.layoutId,
    layoutVersion: doc.layoutVersion,
    layoutDigest: digest,
    state96,
    recordHash,
    recordOpening,
  });
  const newWord = composeWordV1(state96, seal);
  const itemHash = computeSlotItemHashV1({ recordKey, seq, previousWord, newWord, seal });

  return {
    layoutId: doc.layoutId,
    layoutVersion: doc.layoutVersion,
    layoutDigest: digest,
    recordKey,
    seq,
    kind: plan.kind,
    applied: plan.applied,
    ruleId: plan.ruleId,
    decodedState: decodeStateV1(doc, state96),
    state96: hex96(state96),
    recordContent: content,
    recordBytes: canonicalizeJcs(content),
    recordHash,
    itemIndex: plan.itemIndex,
    recordOpening,
    seal,
    sealTag: sealTagOfV1(seal),
    previousWord: hex256(previousWord),
    newWord: hex256(newWord),
    itemHash,
  };
}

// ----------------------------------------------------------------- batches

export interface CommittedSlotItemV1 extends BuiltSlotRecordV1 {
  itemOpening: string;
  publishedLeaf: string;
  merkleProof: string[];
}

export interface SlotBatchCommitV1 {
  batchId: number;
  itemCount: number;
  merkleRoot: string;
  previousHead: string;
  ledgerHead: string;
  calldata: string;
  items: CommittedSlotItemV1[];
}

const writeIface = new ethers.Interface([`function ${WRITE_RECORD_BATCH_SIGNATURE_V1} returns (uint256)`]);
export const WRITE_RECORD_BATCH_SELECTOR_V1 = writeIface.getFunction('writeRecordBatchAndCommit')!.selector;

export function encodeWriteRecordBatchCalldataV1(
  records: Array<Pick<BuiltSlotRecordV1, 'recordKey' | 'previousWord' | 'newWord'>>,
  merkleRoot: string,
): string {
  return writeIface.encodeFunctionData('writeRecordBatchAndCommit', [
    records.map((r) => r.recordKey),
    records.map((r) => BigInt(r.previousWord)),
    records.map((r) => BigInt(r.newWord)),
    SLOT_ENCODING_VERSION_V1,
    normalizeProofHash(merkleRoot, 'merkleRoot'),
    records.length,
  ]);
}

export interface DecodedWriteRecordBatchCalldataV1 {
  selector: string;
  functionSignature: string;
  recordKeys: string[];
  expectedWords: string[];
  newWords: string[];
  encodingVersion: number;
  merkleRoot: string;
  itemCount: number;
}

export function decodeWriteRecordBatchCalldataV1(calldata: string): DecodedWriteRecordBatchCalldataV1 {
  const data = ethers.hexlify(ethers.getBytes(calldata));
  if (!data.startsWith(WRITE_RECORD_BATCH_SELECTOR_V1)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'calldata selector is not writeRecordBatchAndCommit');
  }
  const decoded = writeIface.decodeFunctionData('writeRecordBatchAndCommit', data);
  return {
    selector: WRITE_RECORD_BATCH_SELECTOR_V1,
    functionSignature: WRITE_RECORD_BATCH_SIGNATURE_V1,
    recordKeys: Array.from(decoded[0] as string[], (k) => k.toLowerCase()),
    expectedWords: Array.from(decoded[1] as bigint[], (w) => hex256(w)),
    newWords: Array.from(decoded[2] as bigint[], (w) => hex256(w)),
    encodingVersion: Number(decoded[3]),
    merkleRoot: String(decoded[4]).toLowerCase(),
    itemCount: Number(decoded[5]),
  };
}

/**
 * Commit a batch of built records (CAS order = array order): hiding
 * commitments over the item hashes, pair-sorted root, ledger head, calldata.
 */
export function commitSlotBatchV1(
  records: BuiltSlotRecordV1[],
  batchSeed: string,
  batchId: number,
  previousHead: string,
): SlotBatchCommitV1 {
  if (records.length === 0) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a batch needs at least one record');
  for (let i = 0; i < records.length; i += 1) {
    if (records[i].itemIndex !== i) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `record ${i} was built for item index ${records[i].itemIndex}`);
    }
  }
  const commitments = buildHidingCommitmentsV1(batchSeed, records.map((r) => r.itemHash));
  const merkleRoot = commitments.publishedRoot;
  const ledgerHead = nextLedgerHeadV1(previousHead, merkleRoot, batchId);
  const items: CommittedSlotItemV1[] = records.map((r, i) => ({
    ...r,
    itemIndex: i,
    itemOpening: commitments.itemOpenings[i],
    publishedLeaf: commitments.publishedLeaves[i],
    merkleProof: buildMerkleProofV2(commitments.publishedLeaves, i),
  }));
  return {
    batchId,
    itemCount: records.length,
    merkleRoot,
    previousHead: normalizeProofHash(previousHead, 'previousHead'),
    ledgerHead,
    calldata: encodeWriteRecordBatchCalldataV1(records, merkleRoot),
    items,
  };
}

export interface SlotBatchCommitmentsV1 {
  itemCount: number;
  merkleRoot: string;
  calldata: string;
  items: CommittedSlotItemV1[];
}

/**
 * Commit a batch whose records were built under per-record seeds (one
 * intake anchor, one sealed seed; several anchors in one transaction). The
 * openings are derived record by record from that record's own seed, the
 * published leaves are position-bound exactly as in `commitSlotBatchV1`,
 * and the root is the same pair-sorted construction, so a receipt verifies
 * identically: the verifier receives openings, never seeds. With one seed
 * repeated for every record the output equals `commitSlotBatchV1` minus the
 * ledger fields, which the writer takes from the `LedgerHeadAdvanced` event
 * of the transaction that actually landed.
 */
export function commitSlotBatchWithSeedsV1(records: BuiltSlotRecordV1[], seeds: string[]): SlotBatchCommitmentsV1 {
  if (records.length === 0) throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'a batch needs at least one record');
  if (seeds.length !== records.length) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', `expected ${records.length} seeds, got ${seeds.length}`);
  }
  for (let i = 0; i < records.length; i += 1) {
    if (records[i].itemIndex !== i) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `record ${i} was built for item index ${records[i].itemIndex}`);
    }
  }
  const itemOpenings = records.map((r, i) => deriveItemOpeningV1(seeds[i], i, r.itemHash));
  const publishedLeaves = records.map((r, i) => computePublishedLeafV1(i, r.itemHash, itemOpenings[i]));
  const merkleRoot = computeMerkleItemsRootV2(publishedLeaves);
  const items: CommittedSlotItemV1[] = records.map((r, i) => ({
    ...r,
    itemIndex: i,
    itemOpening: itemOpenings[i],
    publishedLeaf: publishedLeaves[i],
    merkleProof: buildMerkleProofV2(publishedLeaves, i),
  }));
  return {
    itemCount: records.length,
    merkleRoot,
    calldata: encodeWriteRecordBatchCalldataV1(records, merkleRoot),
    items,
  };
}

// ----------------------------------------------------------------- rules

export interface TransitionRuleCheckV1 {
  ok: boolean;
  from: string | null;
  to: string;
  flags: string[];
  reason: string;
}

/**
 * Recompute the transition rule for a record from its previous and new words
 * under the layout table. A receipt that claims `transition_not_applied` for
 * a permitted move, or an applied move the table forbids, fails here.
 */
export function checkTransitionRuleV1(
  doc: LayoutDocumentV1,
  input: { previousWord: string | bigint; newWord: string | bigint; recordContent?: Record<string, unknown> },
): TransitionRuleCheckV1 {
  const lifecycleField = doc.lifecycle.field;
  const next = decodeStateV1(doc, splitWordV1(input.newWord).state96);
  const to = next[lifecycleField] as string;
  const flags = (next.flags as string[]) ?? [];
  const prevWord = BigInt(input.previousWord);
  if (prevWord === 0n) {
    if (!doc.lifecycle.genesis.includes(to)) {
      return { ok: false, from: null, to, flags, reason: `${to} is not a genesis state` };
    }
    if (flags.includes(FLAG_TRANSITION_NOT_APPLIED) || flags.includes(FLAG_DELIVERY_FAILED)) {
      return { ok: false, from: null, to, flags, reason: 'a genesis record cannot carry attempt or failure flags' };
    }
    return { ok: true, from: null, to, flags, reason: 'genesis state is in the layout genesis list' };
  }
  const prev = decodeStateV1(doc, splitWordV1(prevWord).state96);
  const from = prev[lifecycleField] as string;
  if (flags.includes(FLAG_TRANSITION_NOT_APPLIED)) {
    if (!doc.recordAttempts) return { ok: false, from, to, flags, reason: `${doc.name} does not record attempts` };
    if (to !== from) return { ok: false, from, to, flags, reason: 'an attempt record must keep the lifecycle unchanged' };
    const attempted = input.recordContent?.attemptedTarget;
    if (typeof attempted !== 'string') {
      return { ok: false, from, to, flags, reason: 'an attempt record must carry attemptedTarget in the sealed record' };
    }
    if (isTransitionAllowedV1(doc, from, attempted)) {
      return { ok: false, from, to, flags, reason: `${from} -> ${attempted} is permitted by the table; it cannot be recorded as not applied` };
    }
    return { ok: true, from, to, flags, reason: `${from} -> ${attempted} is forbidden by the table and was recorded as not applied` };
  }
  if (flags.includes(FLAG_DELIVERY_FAILED)) {
    if (to !== from) return { ok: false, from, to, flags, reason: 'a failure record must keep the lifecycle unchanged' };
    return { ok: true, from, to, flags, reason: 'failure record keeps the lifecycle' };
  }
  if (!isTransitionAllowedV1(doc, from, to)) {
    return { ok: false, from, to, flags, reason: `${from} -> ${to} is forbidden by the table but the record claims it was applied` };
  }
  return { ok: true, from, to, flags, reason: `${from} -> ${to} is permitted by the table` };
}

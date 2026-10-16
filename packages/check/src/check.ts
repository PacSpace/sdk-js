import {
  computeBundleDigestV1,
  computeBundleDigestV2,
  computeBundleDigestV3,
  computeSealHistoryDigestV1,
  createMirrorNodeRecordChainReader,
  createRpcRecordChainReader,
  decodeStateV1,
  disclosureFormOfV1,
  getPublishedLayoutRegistry,
  matchHeldFile,
  MIRROR_NODE_BY_CHAIN,
  readChainRootsV1,
  readLedgerMaterial,
  readRecordCopyV1,
  readRecordLinkCopyV1,
  recomputeLedgerHeadsV1,
  recordContentOfReceipt,
  recordKeyFromBytesV1,
  RECORD_COPY_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V2,
  RECORD_HISTORY_BUNDLE_SCHEMA_V1,
  RECORD_HISTORY_BUNDLE_SCHEMA_V2,
  RECORD_HISTORY_BUNDLE_SCHEMA_V3,
  RECORD_LINK_COPY_SCHEMA_V1,
  RECORD_SEAL_HISTORY_SCHEMA_V1,
  splitWordV1,
  verifyBundleWithPublicLayer,
  verifyRecordDisclosureV1,
  verifyRecordHistoryBundle,
  verifyRecordHistoryBundleV3,
  verifyRecordSealHistoryV1,
  type BundleVerificationV1,
  type EncryptedReadRefusalV1,
  type HeldFile,
  type LayoutRegistry,
  type RecordChainReader,
  type RecordDisclosure,
  type RecordHistoryBundleV1,
  type RecordHistoryBundleV2,
  type RecordHistoryBundleV3,
  type RecordKeyV1,
  type RecordSealHistoryV1,
  type SealHistoryVerificationV1,
  type SlotVerificationLevel,
} from '@pacspace/shared';
import {
  buildReport,
  buildSealsReport,
  sameHex,
  type CheckReport,
  type DailyStatementOutcome,
  type DisclosureOutcome,
  type HeldFileOutcome,
  type SourceOutcome,
} from './report';

declare const __PACSPACE_CHECK_VERSION__: string | undefined;

export const CHECKER_NAME = '@pacspace-io/check';
export const CHECKER_VERSION: string =
  typeof __PACSPACE_CHECK_VERSION__ === 'string' ? __PACSPACE_CHECK_VERSION__ : '0.0.0-dev';

/** The eight forms a history file names. */
export const HISTORY_SCHEMAS = [
  RECORD_HISTORY_BUNDLE_SCHEMA_V1,
  RECORD_HISTORY_BUNDLE_SCHEMA_V2,
  RECORD_HISTORY_BUNDLE_SCHEMA_V3,
  RECORD_COPY_SCHEMA_V1,
  RECORD_SEAL_HISTORY_SCHEMA_V1,
  RECORD_LINK_COPY_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V2,
] as const;
export type HistorySchema = (typeof HISTORY_SCHEMAS)[number];

/** W-L2g-27, W-C10-B-21 */
export const NOT_A_HISTORY_SENTENCE =
  'This file is not a record history. A history file names its form as record-history-bundle/v1, record-history-bundle/v2, record-history-bundle/v3, pacspace-record-copy/v1, record-seal-history/v1, record-link-copy/v1, record-disclosure/v1 or record-disclosure/v2.';
/** W-C10-B-5: an encrypted record from before format 2 (card 10). */
export const EARLIER_ENCRYPTED_FORMAT_SENTENCE = 'This record uses an earlier encrypted format that this checker no longer accepts.';
/** W-L2g-1 */
export const ENCRYPTED_NEEDS_KEY_SENTENCE =
  'This record is encrypted. Pass the file holding its record key with --key, or check a copy made with keepCopy.';
/** W-L2g-2 */
export const NOT_A_RECORD_KEY_SENTENCE = 'This is not a record key this version reads.';
/** W-L2g-3 */
export const KEY_ONLY_FOR_ENCRYPTED_SENTENCE = "--key is used only with an encrypted record's history.";
/** W-L2g-5 */
export const NOT_A_COPY_FILE_SENTENCE = 'This is not a copy file this version can read.';
/** W-L2g-4 */
export function entryUnopenedSentence(n: number): string {
  return `Entry ${n} didn't open with this record key. The key or the history is not the one expected.`;
}
export const NOTHING_REVEALED_SENTENCE =
  'This history reveals no file fingerprint. A file can be checked only against a history or copy that carries the entry that names it.';
export const DISCLOSURE_NEEDS_HISTORY_SENTENCE =
  "A disclosure is checked against the record's seals. Pass the history it came with, or a kept copy, with --history.";
export const DISCLOSURE_OFFLINE_SENTENCE =
  'The revealed fields are checked against the proof layer, so they were not checked offline. Run this again without --offline.';

export interface CheckOptions {
  /**
   * Where the proof layer is read from. `'mirror'` (the default) is the
   * mirror known for the record's network; a URL is a mirror base
   * URL; `{ rpc }` is a JSON-RPC endpoint; `'offline'` skips the source and
   * checks the file alone.
   */
  source?: 'mirror' | 'offline' | string | { rpc: string };
  /** The fingerprint printed on a statement, to compare with this file's. */
  statementFingerprint?: string | null;
  /**
   * Also read every daily statement the proof layer carries, so the
   * daily statement in the file can be compared even when later statements
   * exist, and the record's batches are checked to sit in that sequence.
   */
  full?: boolean;
  /** Network timeout per read, milliseconds. */
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  /** The seal history or kept copy a `record-disclosure/v1` file is checked against. */
  history?: HistoryFile;
  /**
   * A file the reader holds, as digests of its bytes: never its path, its
   * text, or a blinding value. `hmac` only when its blinding file was given.
   */
  heldFile?: HeldFile;
  /** A `record-history-bundle/v3`'s record key, its 32 bytes. Never kept. */
  recordKey?: Uint8Array;
  /** Called with a disclosure's revealed fields once they verified; never for fields that failed. */
  onRevealed?: (entries: RevealedEntry[]) => void;
}

/** One disclosed entry's fields as the reader sees them: entries count from 1. */
export interface RevealedEntry {
  entry: number;
  fields: Array<{ pointer: string; value: unknown }>;
  withheld: number;
}

export class HistoryFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HistoryFileError';
  }
}

/**
 * A parsed history file, as `parseHistoryFile` produces it. Callers hold it
 * and hand it back; its fields are the file's own.
 */
export interface HistoryFile {
  readonly schema: HistorySchema;
  readonly [field: string]: unknown;
}

function asBundle(file: HistoryFile): RecordHistoryBundleV1 {
  return file as unknown as RecordHistoryBundleV1;
}

/** Parse a history file's text. Refuses anything that is not one of the five forms. */
export function parseHistoryFile(text: string): HistoryFile {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HistoryFileError('This file is not a record history. It could not be read as JSON.');
  }
  const schema = parsed && typeof parsed === 'object' ? (parsed as { schema?: unknown }).schema : undefined;
  if (!(HISTORY_SCHEMAS as readonly unknown[]).includes(schema)) throw new HistoryFileError(NOT_A_HISTORY_SENTENCE);
  return parsed as HistoryFile;
}

/** Every daily statement the source carries, in order: the starting point and each batch after it. */
export interface StatementSequence {
  genesisHead: string;
  batches: Array<{ batchId: number | string | bigint; merkleRoot: string }>;
}

/**
 * Whether the daily statement in the file is the one the sequence produces
 * at its batch. The file alone can prove it only when the statement is the
 * current one (its fingerprint equals the file's current head); otherwise
 * the sequence read from the source decides, and without it the answer is
 * "not compared", never "does not match".
 */
export function dailyStatementOf(
  file: HistoryFile,
  verified: boolean,
  sequence?: StatementSequence | null,
): DailyStatementOutcome | null {
  const bundle = asBundle(file);
  const statement = bundle.ledgerStatement;
  if (!statement) return null;
  const outcome: DailyStatementOutcome = { date: statement.statementDate, fingerprint: statement.ledgerHead, matches: null };
  if (verified && bundle.ledger?.head && sameHex(statement.ledgerHead, bundle.ledger.head)) {
    return { ...outcome, matches: true };
  }
  if (sequence) {
    const asOf = BigInt(statement.asOfBatchId);
    const upTo = sequence.batches.filter((batch) => BigInt(batch.batchId) <= asOf);
    const heads = recomputeLedgerHeadsV1(sequence.genesisHead, upTo);
    return { ...outcome, matches: sameHex(heads[heads.length - 1], statement.ledgerHead) };
  }
  return outcome;
}

/** A reader whose sequence reads are made once, so the verifier and the statement comparison share one scan. */
function memoizeSequenceReads(reader: RecordChainReader): RecordChainReader {
  let head: Promise<string> | null = null;
  const advances = new Map<string, ReturnType<RecordChainReader['getLedgerAdvances']>>();
  return {
    ...reader,
    getLedgerHead: () => {
      if (!head) head = reader.getLedgerHead();
      return head;
    },
    getLedgerAdvances: (fromBlock, toBlock) => {
      const key = `${fromBlock ?? 0}:${toBlock ?? 'latest'}`;
      let pending = advances.get(key);
      if (!pending) {
        pending = reader.getLedgerAdvances(fromBlock, toBlock);
        advances.set(key, pending);
      }
      return pending;
    },
  };
}

function readerFor(
  chain: { chainId?: number; contractAddress?: string } | undefined,
  options: CheckOptions,
): { reader: RecordChainReader; readsFrom: string } {
  const chainId = chain?.chainId;
  const contractAddress = chain?.contractAddress;
  if (!contractAddress) {
    throw new HistoryFileError('This file does not say where its record was committed, so the proof layer cannot be read.');
  }
  const source = options.source ?? 'mirror';
  if (typeof source === 'object') {
    return {
      reader: createRpcRecordChainReader({ rpcUrl: source.rpc, contractAddress, chainId, timeoutMs: options.timeoutMs }),
      readsFrom: source.rpc,
    };
  }
  const mirrorBaseUrl = source === 'mirror' ? (typeof chainId === 'number' ? MIRROR_NODE_BY_CHAIN[chainId] : undefined) : source;
  if (!mirrorBaseUrl) {
    throw new HistoryFileError(
      `This file names a network the checker has no address for (${chainId ?? 'none'}). Pass one with --source <url>.`,
    );
  }
  return {
    reader: createMirrorNodeRecordChainReader({
      mirrorBaseUrl,
      chainId,
      contractAddress,
      timeoutMs: options.timeoutMs,
      fetchImpl: options.fetchImpl,
    }),
    readsFrom: mirrorBaseUrl,
  };
}

const PAYLOAD_POINTER = /^\/payloads\/(0|[1-9][0-9]*)$/;

/** Whether a disclosure carries anything that can name a file: a revealed `/payloads/<i>`, or a v1 entry's whole content. */
function disclosureNamesAFile(disclosure: unknown): boolean {
  const entries = (disclosure as { entries?: unknown } | null)?.entries;
  if (!Array.isArray(entries)) return false;
  return entries.some((entry) => {
    if (!entry || typeof entry !== 'object') return false;
    const revealed = (entry as { revealed?: unknown }).revealed;
    if (Array.isArray(revealed)) return revealed.some((leaf) => PAYLOAD_POINTER.test(String((leaf as { pointer?: unknown })?.pointer)));
    const content = (entry as { recordContent?: unknown }).recordContent;
    return !!content && typeof content === 'object' && Array.isArray((content as { payloads?: unknown }).payloads);
  });
}

/** The disclosure a file carries or is: a kept copy's, a bare disclosure, or none. */
function disclosureOf(file: HistoryFile): unknown {
  if (file.schema === RECORD_LINK_COPY_SCHEMA_V1) return (file as { disclosure?: unknown }).disclosure ?? null;
  if (file.schema === RECORD_DISCLOSURE_SCHEMA_V1 || file.schema === RECORD_DISCLOSURE_SCHEMA_V2) return file;
  return null;
}

/**
 * Whether `--held-file` can be checked against this file at all: a words
 * history carries every entry's content; a seal history carries none; a
 * kept copy or a disclosure only what it reveals. Read before the held file
 * is opened and before any request.
 */
export function revealsFileFingerprint(file: HistoryFile): boolean {
  if (file.schema === RECORD_HISTORY_BUNDLE_SCHEMA_V1 || file.schema === RECORD_HISTORY_BUNDLE_SCHEMA_V2) return true;
  if (file.schema === RECORD_HISTORY_BUNDLE_SCHEMA_V3 || file.schema === RECORD_COPY_SCHEMA_V1) return true;
  return disclosureNamesAFile(disclosureOf(file));
}

/** Whether checking this file needs batch roots read from the ledger, which `--offline` cannot do. */
export function needsLedgerRoots(file: HistoryFile): boolean {
  return disclosureOf(file) !== null;
}

/**
 * Check one history file. The file is checked on its own first (its
 * fingerprint, its layout against the published documents, every entry or
 * seal, completeness, the daily statement it carries); then, unless offline,
 * the record's current state, its batches and any disclosure's batch roots
 * are read from the proof layer and the file is checked against them.
 * Nothing is sent to PacSpace.
 */
export async function checkHistory(file: HistoryFile, options: CheckOptions = {}): Promise<CheckReport> {
  if (options.source === 'offline' && needsLedgerRoots(file)) throw new HistoryFileError(DISCLOSURE_OFFLINE_SENTENCE);
  if (options.heldFile && !revealsFileFingerprint(file)) throw new HistoryFileError(NOTHING_REVEALED_SENTENCE);
  if (options.recordKey && file.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3) throw new HistoryFileError(KEY_ONLY_FOR_ENCRYPTED_SENTENCE);
  switch (file.schema) {
    case RECORD_HISTORY_BUNDLE_SCHEMA_V1:
    case RECORD_HISTORY_BUNDLE_SCHEMA_V2:
      return checkBundle(file, options);
    case RECORD_HISTORY_BUNDLE_SCHEMA_V3: {
      if (!options.recordKey) throw new HistoryFileError(ENCRYPTED_NEEDS_KEY_SENTENCE);
      if (options.recordKey.length !== 32) throw new HistoryFileError(NOT_A_RECORD_KEY_SENTENCE);
      const recordKey = await recordKeyFromBytesV1(options.recordKey);
      return checkEncrypted(file, file as unknown as RecordHistoryBundleV3, recordKey, options);
    }
    case RECORD_COPY_SCHEMA_V1: {
      const read = await readRecordCopyV1(file);
      if (!read.ok) throw new HistoryFileError(NOT_A_COPY_FILE_SENTENCE);
      return checkEncrypted(file, read.history, read.recordKey, options);
    }
    case RECORD_SEAL_HISTORY_SCHEMA_V1:
      return checkSeals(file.schema, file as unknown as RecordSealHistoryV1, null, options);
    case RECORD_LINK_COPY_SCHEMA_V1: {
      const read = readRecordLinkCopyV1(file);
      if (!read.ok) throw new HistoryFileError('This is not a kept copy this version can read.');
      return checkSeals(file.schema, read.copy.sealHistory, read.copy.disclosure, options);
    }
    case RECORD_DISCLOSURE_SCHEMA_V1:
    case RECORD_DISCLOSURE_SCHEMA_V2: {
      const against = options.history;
      if (!against) throw new HistoryFileError(DISCLOSURE_NEEDS_HISTORY_SENTENCE);
      if (against.schema === RECORD_SEAL_HISTORY_SCHEMA_V1) {
        return checkSeals(file.schema, against as unknown as RecordSealHistoryV1, file as unknown as RecordDisclosure, options);
      }
      if (against.schema === RECORD_LINK_COPY_SCHEMA_V1) {
        const read = readRecordLinkCopyV1(against);
        if (!read.ok) throw new HistoryFileError('This is not a kept copy this version can read.');
        return checkSeals(file.schema, read.copy.sealHistory, file as unknown as RecordDisclosure, options);
      }
      throw new HistoryFileError(NOT_A_HISTORY_SENTENCE);
    }
    default:
      throw new HistoryFileError(NOT_A_HISTORY_SENTENCE);
  }
}

function payloadsOfContent(content: unknown): unknown[] {
  const payloads = (content as { payloads?: unknown } | null)?.payloads;
  return Array.isArray(payloads) ? payloads : [];
}

/** The held-file rule over each entry's payload references, entry by entry; `entries` are seqs. */
function heldFileOutcome(held: HeldFile, bySeq: Array<{ seq: number; items: unknown[] }>, offline: boolean): HeldFileOutcome {
  const matchedEntries: number[] = [];
  let blinded = false;
  let blindingNeededAt: number | null = null;
  for (const { seq, items } of [...bySeq].sort((a, b) => a.seq - b.seq)) {
    const match = matchHeldFile(items, held);
    if (match.matched) {
      matchedEntries.push(seq + 1);
      if (match.blinded) blinded = true;
    } else if (match.blindingNeeded && blindingNeededAt === null) {
      blindingNeededAt = seq + 1;
    }
  }
  return {
    matched: matchedEntries.length > 0,
    entries: matchedEntries,
    blinded: blinded || (matchedEntries.length === 0 && blindingNeededAt !== null),
    blindingNeededAt: matchedEntries.length === 0 ? blindingNeededAt : null,
    offline,
  };
}

/** Payload references of the receipts the verifier passed, never of one whose seal failed. */
function verifiedPayloads(file: HistoryFile, verification: BundleVerificationV1): Array<{ seq: number; items: unknown[] }> {
  const verified = new Set((verification.history?.perReceipt ?? []).filter((row) => row.result.verified).map((row) => row.seq));
  const out: Array<{ seq: number; items: unknown[] }> = [];
  for (const receipt of (file as { receipts?: unknown[] }).receipts ?? []) {
    const seq = (receipt as { seq?: unknown })?.seq;
    if (typeof seq !== 'number' || !verified.has(seq)) continue;
    const content =
      recordContentOfReceipt(receipt) ?? (receipt as { recordContent?: unknown }).recordContent ?? null;
    out.push({ seq, items: payloadsOfContent(content) });
  }
  return out;
}

/**
 * The live reads `verifyBundleWithPublicLayer` makes, for a v2 history:
 * the word, the layout and each batch root from the source (and, with
 * `full`, the ledger), then the verifier of either form.
 */
async function verifyBundleV2WithSource(
  reader: RecordChainReader,
  bundle: RecordHistoryBundleV2,
  level: SlotVerificationLevel,
  layouts: LayoutRegistry,
) {
  const contractMatchesBundle =
    !!bundle.chain?.contractAddress && bundle.chain.contractAddress.toLowerCase() === reader.contractAddress.toLowerCase();
  const chainWord = await reader.getRecord(bundle.recordKey);
  const onChainLayout = await reader.getLayout(bundle.layout.layoutId);
  const batchRoots: Record<string, string> = {};
  for (const id of [...new Set(bundle.receipts.map((r) => String(r.batchId)))]) batchRoots[id] = await reader.getBatchRoot(id);
  const ledger = level === 'ledger' ? await readLedgerMaterial(reader, [], {}) : undefined;
  const bundleCheck = await verifyRecordHistoryBundle(bundle, {
    layouts,
    chainWord,
    batchRoots,
    ledger: ledger ? { genesisHead: ledger.genesisHead, batches: ledger.batches, expectedHead: ledger.expectedHead } : undefined,
  });
  const layoutMatches = onChainLayout.registered && bundleCheck.layoutDigest === onChainLayout.layoutDigest;
  return {
    verified: contractMatchesBundle && layoutMatches && bundleCheck.verified,
    contractMatchesBundle,
    layoutOnChain: { matchesBundle: layoutMatches },
    bundleCheck,
  };
}

async function checkBundle(file: HistoryFile, options: CheckOptions): Promise<CheckReport> {
  const bundle = asBundle(file);
  const v2 = file.schema === RECORD_HISTORY_BUNDLE_SCHEMA_V2;
  const layouts = getPublishedLayoutRegistry();
  const offline = await verifyRecordHistoryBundle(bundle, { layouts });
  const computedFingerprint = (() => {
    try {
      return v2 ? computeBundleDigestV2(file as unknown as RecordHistoryBundleV2) : computeBundleDigestV1(bundle);
    } catch {
      return '';
    }
  })();
  const base = {
    checker: { name: CHECKER_NAME, version: CHECKER_VERSION },
    form: file.schema,
    reference: String(bundle.recordKey ?? ''),
    fingerprint: typeof bundle.bundleDigest === 'string' ? bundle.bundleDigest : null,
    computedFingerprint,
    exportedAt: typeof bundle.exportedAt === 'string' ? bundle.exportedAt : null,
    statementFingerprint: options.statementFingerprint?.trim() || null,
  };
  const heldOf = (verification: BundleVerificationV1, offlineRun: boolean) =>
    options.heldFile ? heldFileOutcome(options.heldFile, verifiedPayloads(file, verification), offlineRun) : null;

  if (options.source === 'offline' || !offline.schemaOk || !offline.digestOk) {
    // A file that is not a history, or was changed, is not taken to the source.
    return buildReport({
      ...base,
      verification: offline,
      source: { compared: false, reason: 'offline' },
      dailyStatement: dailyStatementOf(file, offline.verified),
      heldFile: heldOf(offline, options.source === 'offline'),
    });
  }

  let source: SourceOutcome;
  let verification = offline;
  let sequence: StatementSequence | null = null;
  try {
    const found = readerFor(bundle.chain, options);
    const reader = options.full ? memoizeSequenceReads(found.reader) : found.reader;
    const level: SlotVerificationLevel = options.full ? 'ledger' : 'semantic';
    const live = v2
      ? await verifyBundleV2WithSource(reader, file as unknown as RecordHistoryBundleV2, level, layouts)
      : await verifyBundleWithPublicLayer({ reader, bundle, level, layouts });
    if (options.full) {
      const material = await readLedgerMaterial(reader, [], {});
      sequence = { genesisHead: material.genesisHead, batches: material.batches };
    }
    verification = live.bundleCheck;
    const detail = live.verified
      ? null
      : !live.contractMatchesBundle
        ? 'The record was committed somewhere other than where this file says.'
        : !live.layoutOnChain?.matchesBundle
          ? 'The published form of this record does not match the one this file carries.'
          : live.bundleCheck.reason;
    source = {
      compared: true,
      matches: live.verified,
      chainId: bundle.chain.chainId,
      readsFrom: found.readsFrom,
      contractAddress: reader.contractAddress.toLowerCase(),
      detail,
    };
  } catch (error) {
    if (error instanceof HistoryFileError) throw error;
    source = { compared: false, reason: 'unreachable', detail: (error as Error).message };
  }

  return buildReport({
    ...base,
    verification,
    source,
    dailyStatement: dailyStatementOf(file, verification.verified, sequence),
    heldFile: heldOf(verification, false),
  });
}

/** An encrypted history's refusal as a report sentence (W-L2d-27 to W-L2d-29, W-L2g-4); null when the file is not one this version reads. */
function encryptedRefusalSentence(refusal: EncryptedReadRefusalV1): string | null {
  const entry = typeof refusal.seq === 'number' ? refusal.seq + 1 : null;
  switch (refusal.code) {
    case 'RECORD_HISTORY_WRONG_RECORD':
      return 'The history served is for another record. Nothing was opened.';
    case 'RECORD_ENTRY_HASH_MISMATCH':
      return entry === null ? null : `Entry ${entry} opened, but its content doesn't match its sealed record hash.`;
    case 'RECORD_ENTRY_REFS_MISMATCH':
      return entry === null ? null : `Entry ${entry} opened, but the entries it amends or references don't match the ones stored with it.`;
    case 'RECORD_HISTORY_RECEIPT_FORM':
    case 'RECORD_COPY_MALFORMED':
      return null;
    default:
      return entry === null ? null : entryUnopenedSentence(entry);
  }
}

/**
 * An encrypted history (`record-history-bundle/v3`, alone with its key or
 * inside a copy file): every envelope opened and its record hash recomputed
 * before the seal checks, then, unless offline, the same reads from the
 * proof layer as a v2 history. The key stays in this function.
 */
async function checkEncrypted(file: HistoryFile, bundle: RecordHistoryBundleV3, recordKey: RecordKeyV1, options: CheckOptions): Promise<CheckReport> {
  const receipts: unknown[] = Array.isArray(bundle?.receipts) ? bundle.receipts : [];
  const format2 = receipts.every((r) => ['semantic-receipt/v5', 'semantic-receipt/v6'].includes((r as { schema?: unknown })?.schema as string));
  if (!format2) throw new HistoryFileError(EARLIER_ENCRYPTED_FORMAT_SENTENCE);
  const layouts = getPublishedLayoutRegistry();
  const notThisForm = file.schema === RECORD_COPY_SCHEMA_V1 ? NOT_A_COPY_FILE_SENTENCE : NOT_A_HISTORY_SENTENCE;
  const asFile = bundle as unknown as HistoryFile;
  const base = {
    checker: { name: CHECKER_NAME, version: CHECKER_VERSION },
    form: file.schema,
    reference: String(bundle?.recordKey ?? ''),
    fingerprint: typeof bundle?.bundleDigest === 'string' ? bundle.bundleDigest : null,
    computedFingerprint: (() => {
      try {
        return computeBundleDigestV3(bundle);
      } catch {
        return '';
      }
    })(),
    exportedAt: typeof bundle?.exportedAt === 'string' ? bundle.exportedAt : null,
    statementFingerprint: options.statementFingerprint?.trim() || null,
  };
  const refused = (refusal: EncryptedReadRefusalV1): CheckReport => {
    if (refusal.code === 'RECORD_HISTORY_DIGEST') {
      return buildReport({
        ...base,
        verification: { verified: false, digestOk: false, reason: '', history: null },
        source: { compared: false, reason: 'offline' },
        dailyStatement: null,
      });
    }
    const sentence = encryptedRefusalSentence(refusal);
    if (sentence === null) throw new HistoryFileError(notThisForm);
    return buildReport({
      ...base,
      verification: { verified: false, digestOk: true, reason: sentence, history: null },
      source: { compared: false, reason: 'offline' },
      dailyStatement: dailyStatementOf(asFile, false),
    });
  };
  const heldOf = (verification: BundleVerificationV1, opened: Array<{ seq: number; content?: unknown }>, offlineRun: boolean) => {
    if (!options.heldFile) return null;
    const verified = new Set((verification.history?.perReceipt ?? []).filter((row) => row.result.verified).map((row) => row.seq));
    const payloads = opened.filter((o) => 'content' in o && verified.has(o.seq)).map((o) => ({ seq: o.seq, items: payloadsOfContent(o.content) }));
    return heldFileOutcome(options.heldFile, payloads, offlineRun);
  };

  const offline = await verifyRecordHistoryBundleV3(bundle, { layouts, recordKey });
  if (!offline.ok) return refused(offline);
  const encrypted = { refusedUnopened: offline.refused.filter((r) => !r.opened).length };
  if (options.source === 'offline' || !offline.verification.schemaOk || !offline.verification.digestOk) {
    return buildReport({
      ...base,
      verification: offline.verification,
      source: { compared: false, reason: 'offline' },
      dailyStatement: dailyStatementOf(asFile, offline.verification.verified),
      heldFile: heldOf(offline.verification, offline.opened, options.source === 'offline'),
      encrypted,
    });
  }

  let source: SourceOutcome;
  let result = offline;
  let sequence: StatementSequence | null = null;
  try {
    const found = readerFor(bundle.chain, options);
    const reader = options.full ? memoizeSequenceReads(found.reader) : found.reader;
    const contractMatches =
      !!bundle.chain?.contractAddress && bundle.chain.contractAddress.toLowerCase() === reader.contractAddress.toLowerCase();
    const chainWord = await reader.getRecord(bundle.recordKey);
    const onChainLayout = await reader.getLayout(bundle.layout.layoutId);
    const batchRoots: Record<string, string> = {};
    for (const id of [...new Set(bundle.receipts.map((r) => String(r.batchId)))]) batchRoots[id] = await reader.getBatchRoot(id);
    const ledger = options.full ? await readLedgerMaterial(reader, [], {}) : undefined;
    if (ledger) sequence = { genesisHead: ledger.genesisHead, batches: ledger.batches };
    const live = await verifyRecordHistoryBundleV3(bundle, {
      layouts,
      recordKey,
      chainWord,
      batchRoots,
      ledger: ledger ? { genesisHead: ledger.genesisHead, batches: ledger.batches, expectedHead: ledger.expectedHead } : undefined,
    });
    if (!live.ok) return refused(live);
    result = live;
    const layoutMatches = onChainLayout.registered && live.verification.layoutDigest === onChainLayout.layoutDigest;
    const matches = contractMatches && layoutMatches && live.verification.verified;
    source = {
      compared: true,
      matches,
      chainId: bundle.chain.chainId,
      readsFrom: found.readsFrom,
      contractAddress: reader.contractAddress.toLowerCase(),
      detail: matches
        ? null
        : !contractMatches
          ? 'The record was committed somewhere other than where this file says.'
          : !layoutMatches
            ? 'The published form of this record does not match the one this file carries.'
            : live.verification.reason,
    };
  } catch (error) {
    if (error instanceof HistoryFileError) throw error;
    source = { compared: false, reason: 'unreachable', detail: (error as Error).message };
  }

  return buildReport({
    ...base,
    verification: result.verification,
    source,
    dailyStatement: dailyStatementOf(asFile, result.verification.verified, sequence),
    heldFile: heldOf(result.verification, result.opened, false),
    encrypted,
  });
}

/** The record's entry count from its current word, as the page's hero reads it; null when it cannot be read. */
function entryCountOf(form: RecordSealHistoryV1, layouts: LayoutRegistry): number | null {
  if (!form || typeof form.currentWord !== 'string') return null;
  const layout = layouts.get(form.layout?.layoutId);
  if (!layout) return null;
  try {
    const seq = Number(String(decodeStateV1(layout.doc, splitWordV1(form.currentWord).state96).seq));
    return Number.isSafeInteger(seq) ? seq + 1 : null;
  } catch {
    return null;
  }
}

/** Whether the form's ledger material sits in the sequence the source carries. */
function ledgerAgrees(form: RecordSealHistoryV1, material: { genesisHead: string; expectedHead: string; batches: Array<{ batchId: number | string | bigint; merkleRoot: string }> }): boolean {
  if (!form.ledger) return true;
  const heads = recomputeLedgerHeadsV1(material.genesisHead, material.batches);
  if (!sameHex(heads[heads.length - 1], material.expectedHead)) return false;
  if (!heads.some((head) => sameHex(head, form.ledger!.head))) return false;
  const roots = new Map(material.batches.map((b) => [String(b.batchId), b.merkleRoot.toLowerCase()] as const));
  return form.ledger.batches.every((b) => roots.get(String(b.batchId)) === b.merkleRoot.toLowerCase());
}

/** A reader that records which batch ids the source answered at all, so a refused root is told from an unread one. */
function answeringReader(reader: RecordChainReader): { reader: RecordChainReader; answered: Set<string> } {
  const answered = new Set<string>();
  return {
    answered,
    reader: {
      ...reader,
      getBatchRoot: async (batchId) => {
        const root = await reader.getBatchRoot(batchId);
        answered.add(String(batchId));
        return root;
      },
    },
  };
}

/** A JSON Pointer token for an object member's name. */
const pointerToken = (name: string) => name.replace(/~/g, '~0').replace(/\//g, '~1');

async function checkDisclosure(
  form: RecordSealHistoryV1,
  disclosure: RecordDisclosure,
  reader: RecordChainReader | null,
  onRevealed?: CheckOptions['onRevealed'],
): Promise<DisclosureOutcome> {
  const sub = disclosureFormOfV1(form, disclosure);
  if (!sub) return { kind: 'refused', code: null, reason: null };
  if (!reader) return { kind: 'root-not-read' };
  const recorded = answeringReader(reader);
  const batchIds = [...new Set(sub.entries.map((e) => String(e.batchId)))];
  const { chainRoots, leftOut } = await readChainRootsV1(recorded.reader, batchIds);
  if (leftOut.some((id) => !recorded.answered.has(id))) return { kind: 'root-not-read' };
  const result = await verifyRecordDisclosureV1({ form: sub, chainRoots, disclosure });
  if (!result.ok) return { kind: 'refused', code: result.code, reason: result.reason };
  onRevealed?.(
    result.entries
      .filter((e) => e.fields.length > 0 || e.content !== null)
      .map((e) => ({
        entry: e.seq + 1,
        fields: e.fields.length
          ? e.fields.map((f) => ({ pointer: f.pointer, value: f.value }))
          : Object.entries(e.content ?? {}).map(([name, value]) => ({ pointer: `/${pointerToken(name)}`, value })),
        withheld: e.withheld,
      })),
  );
  return {
    kind: 'verified',
    revealed: result.entries.filter((e) => e.fields.length > 0 || e.content !== null).map((e) => e.seq),
    withheld: result.entries.reduce((sum, e) => sum + e.withheld, 0),
    payloads: result.entries.map((e) => ({
      seq: e.seq,
      items:
        e.content && !e.fields.length
          ? payloadsOfContent(e.content)
          : e.fields
              .map((field) => ({ field, match: PAYLOAD_POINTER.exec(field.pointer) }))
              .filter((f) => f.match)
              .sort((a, b) => Number(a.match![1]) - Number(b.match![1]))
              .map((f) => f.field.value),
    })),
  };
}

async function checkSeals(
  formName: HistorySchema,
  form: RecordSealHistoryV1,
  disclosure: RecordDisclosure | null,
  options: CheckOptions,
): Promise<CheckReport> {
  const layouts = getPublishedLayoutRegistry();
  let verification: SealHistoryVerificationV1 = verifyRecordSealHistoryV1(form, { layouts });
  const computedFingerprint = (() => {
    try {
      return computeSealHistoryDigestV1(form);
    } catch {
      return '';
    }
  })();
  const base = {
    checker: { name: CHECKER_NAME, version: CHECKER_VERSION },
    form: formName,
    reference: String(form?.recordKey ?? ''),
    fingerprint: typeof form?.digest === 'string' ? form.digest : null,
    computedFingerprint,
    statementFingerprint: options.statementFingerprint?.trim() || null,
    queued: (Array.isArray(form?.pending) ? form.pending : [])
      .filter((p) => p?.status === 'queued' && typeof p.seq === 'number')
      .map((p) => p.seq as number)
      .sort((a, b) => a - b),
  };
  const entries = entryCountOf(form, layouts);

  if (options.source === 'offline' || !verification.schemaOk || !verification.digestOk) {
    return buildSealsReport({
      ...base,
      entries,
      verification,
      source: { compared: false, reason: 'offline' },
      disclosure: disclosure ? { kind: 'not-checked' } : null,
      heldFile: options.heldFile ? heldFileOutcome(options.heldFile, [], options.source === 'offline') : null,
    });
  }

  let source: SourceOutcome;
  let reader: RecordChainReader | null = null;
  try {
    const found = readerFor(form.chain, options);
    reader = options.full ? memoizeSequenceReads(found.reader) : found.reader;
    const chainWord = await reader.getRecord(form.recordKey);
    verification = verifyRecordSealHistoryV1(form, { layouts, chainWord });
    const contractMatches = reader.contractAddress.toLowerCase() === String(form.chain.contractAddress).toLowerCase();
    const wordMatches =
      form.currentWord === null ? BigInt(chainWord) === 0n : verification.chainWordMatches === true;
    const ledgerMatches = options.full && form.ledger ? ledgerAgrees(form, await readLedgerMaterial(reader, [], {})) : true;
    const matches = contractMatches && wordMatches && ledgerMatches;
    source = {
      compared: true,
      matches,
      chainId: form.chain.chainId,
      readsFrom: found.readsFrom,
      contractAddress: reader.contractAddress.toLowerCase(),
      detail: contractMatches ? null : 'The record was committed somewhere other than where this file says.',
    };
  } catch (error) {
    if (error instanceof HistoryFileError) throw error;
    source = { compared: false, reason: 'unreachable', detail: (error as Error).message };
    reader = null;
  }

  let disclosureOutcome: DisclosureOutcome | null = null;
  if (disclosure) {
    disclosureOutcome = verification.verified ? await checkDisclosure(form, disclosure, reader, options.onRevealed) : { kind: 'not-checked' };
  }
  const held = options.heldFile
    ? heldFileOutcome(options.heldFile, disclosureOutcome?.kind === 'verified' ? disclosureOutcome.payloads : [], false)
    : null;

  return buildSealsReport({
    ...base,
    entries,
    verification,
    source,
    disclosure: disclosureOutcome,
    heldFile: held,
  });
}

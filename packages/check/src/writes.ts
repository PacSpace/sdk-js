import type { RecordChainReader, RecordWrite } from '@pacspace/shared';
import type { EntryWrite, WritesOutcome } from './report';

/**
 * Where each entry was committed, read from the proof layer after the check
 * has its verdict. Information only: nothing here can change what the check
 * found, and every failure ends as "not read".
 */

/** At most this many requests for one lookup, one at a time, one attempt each. */
export const WRITES_LOOKUP_MAX_REQUESTS = 40;
/** The lookup's whole budget when `--timeout` is not given, milliseconds. */
export const WRITES_LOOKUP_DEFAULT_BUDGET_MS = 10_000;

const HEX64 = /^0x[0-9a-f]{64}$/;
const HEX40 = /^0x[0-9a-f]{40}$/;
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/**
 * Where an explorer of the proof layer shows a write, by network. Kept here, not read from the
 * platform's chain settings, so the package carries nothing else of them; a test holds the two equal.
 */
export const WRITE_EXPLORERS: Readonly<Record<number, string>> = Object.freeze({
  295: 'https://hashscan.io/mainnet/transaction/',
  296: 'https://hashscan.io/testnet/transaction/',
});

/**
 * The explorer address of a write, or null. The checker links a write only when it read the mirror it
 * knows for one of the two networks it knows: with `--source`, `--rpc` or any other network, the
 * explorer may not be showing what was read, so none is named.
 */
export function writeLinkFor(source: 'mirror' | 'offline' | string | { rpc: string } | undefined, chainId: unknown): (transactionHash: string) => string | null {
  const base = (source ?? 'mirror') === 'mirror' && typeof chainId === 'number' && Object.prototype.hasOwnProperty.call(WRITE_EXPLORERS, chainId) ? WRITE_EXPLORERS[chainId] : null;
  return (transactionHash) => (base === null || !HEX64.test(transactionHash) ? null : `${base}${transactionHash}`);
}

/** One committed entry of the file: its number (from 1) and the two words its write carries. */
export interface WantedEntry {
  entry: number;
  previousWord: string;
  newWord: string;
}

export interface WritesLookupInput {
  reader: RecordChainReader;
  recordKey: string;
  /** The contract the file names; a write counts only when its log names the same one. */
  contractAddress: string;
  wanted: WantedEntry[];
  /** The file's export time, a hint for where the search starts. */
  startAt: string | null;
  /** True when this run already read the record's whole history (`--full` on a mirror), so nothing more is asked. */
  whole: boolean;
  budgetMs: number;
  /** The explorer address for a write, or null when the checker has none for this source. */
  linkFor: (transactionHash: string) => string | null;
  /** Test seams. */
  windowSeconds?: number;
  now?: () => number;
}

/** The committed entries of a history's receipts that passed the check, with the words their writes carry. */
export function wantedEntriesOf(receipts: unknown, verifiedSeqs: ReadonlySet<number>): WantedEntry[] {
  const out: WantedEntry[] = [];
  for (const receipt of Array.isArray(receipts) ? receipts : []) {
    const { seq, previousWord, newWord } = (receipt ?? {}) as { seq?: unknown; previousWord?: unknown; newWord?: unknown };
    if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0 || !verifiedSeqs.has(seq)) continue;
    if (typeof previousWord !== 'string' || typeof newWord !== 'string') continue;
    const previous = previousWord.toLowerCase();
    const next = newWord.toLowerCase();
    if (!HEX64.test(previous) || !HEX64.test(next)) continue;
    out.push({ entry: seq + 1, previousWord: previous, newWord: next });
  }
  return out.sort((a, b) => a.entry - b.entry);
}

/** A write the report may print: on the file's contract, with a hash and a time that fit their patterns. */
function printable(write: RecordWrite, contractAddress: string): boolean {
  return (
    !!write &&
    typeof write === 'object' &&
    typeof write.contractAddress === 'string' &&
    write.contractAddress.toLowerCase() === contractAddress &&
    typeof write.transactionHash === 'string' &&
    HEX64.test(write.transactionHash.toLowerCase()) &&
    typeof write.committedAt === 'string' &&
    ISO_INSTANT.test(write.committedAt) &&
    Number.isFinite(Date.parse(write.committedAt)) &&
    typeof write.previousWord === 'string' &&
    typeof write.newWord === 'string' &&
    HEX64.test(write.previousWord.toLowerCase()) &&
    HEX64.test(write.newWord.toLowerCase())
  );
}

/** The distinct logs that carry exactly this entry's two words. */
function hitsFor(entry: WantedEntry, writes: RecordWrite[], contractAddress: string): RecordWrite[] {
  const seen = new Map<string, RecordWrite>();
  for (const write of Array.isArray(writes) ? writes : []) {
    if (!printable(write, contractAddress)) continue;
    if (write.previousWord.toLowerCase() !== entry.previousWord || write.newWord.toLowerCase() !== entry.newWord) continue;
    seen.set(`${write.transactionHash!.toLowerCase()}:${write.logIndex ?? ''}`, write);
  }
  return [...seen.values()];
}

/** `p`, or `'cut'` when the budget ends first. */
async function within<T>(p: Promise<T>, ms: number): Promise<T | 'cut'> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const cut = new Promise<'cut'>((resolve) => {
    timer = setTimeout(() => resolve('cut'), Math.max(0, ms));
  });
  p.catch(() => undefined);
  try {
    return await Promise.race([p, cut]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Look up where each wanted entry was committed. One log per entry or the
 * entry is listed as not found; a refused or failed read, or one that the
 * budget cut off before anything was found, is "not read". Never throws.
 */
export async function lookUpWrites(input: WritesLookupInput): Promise<WritesOutcome> {
  try {
    const contractAddress = String(input.contractAddress ?? '').toLowerCase();
    if (!HEX40.test(contractAddress)) return { read: false, reason: 'unreachable' };
    if (input.wanted.length === 0) return { read: true, entries: [], notFound: [] };
    const done = (writes: RecordWrite[]) => input.wanted.every((entry) => hitsFor(entry, writes, contractAddress).length > 0);

    let writes: RecordWrite[];
    let cutOff = false;
    if (input.whole) {
      const all = await within(input.reader.getRecordWrites(input.recordKey), input.budgetMs);
      if (all === 'cut') return { read: false, reason: 'timeout' };
      writes = all;
    } else {
      if (!input.reader.findRecordWrites) return { read: false, reason: 'unreachable' };
      // A reader that never answers must not hold the report: the same budget bounds the call from outside.
      const result = await within(
        input.reader.findRecordWrites(input.recordKey, {
          startAt: input.startAt,
          done,
          budgetMs: input.budgetMs,
          maxRequests: WRITES_LOOKUP_MAX_REQUESTS,
          windowSeconds: input.windowSeconds,
          now: input.now,
        }),
        input.budgetMs + 250,
      );
      if (result === 'cut') return { read: false, reason: 'timeout' };
      writes = result.writes;
      cutOff = result.ended === 'timeout';
    }

    const byTransaction = new Map<string, EntryWrite>();
    const notFound: number[] = [];
    for (const entry of input.wanted) {
      const hits = hitsFor(entry, writes, contractAddress);
      if (hits.length !== 1) {
        notFound.push(entry.entry);
        continue;
      }
      const transactionHash = hits[0].transactionHash!.toLowerCase();
      const group = byTransaction.get(transactionHash);
      if (group) {
        group.entries.push(entry.entry);
        continue;
      }
      const link = input.linkFor(transactionHash);
      byTransaction.set(transactionHash, {
        entries: [entry.entry],
        committedAt: hits[0].committedAt!,
        transactionHash,
        blockNumber: Number.isSafeInteger(hits[0].blockNumber) ? (hits[0].blockNumber as number) : null,
        link: typeof link === 'string' ? link : null,
      });
    }
    const entries = [...byTransaction.values()].sort((a, b) => a.entries[0] - b.entries[0]);
    if (cutOff && entries.length === 0) return { read: false, reason: 'timeout' };
    return { read: true, entries, notFound };
  } catch {
    return { read: false, reason: 'unreachable' };
  }
}

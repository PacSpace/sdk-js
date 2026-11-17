/**
 * One reading of the public mirror's answer to "where was this record
 * written": the request, the page link and the log. The Shared Record page's
 * finder (in the reader's browser) and the checker's lookup both use it, so
 * a change in the mirror's shape is met in one place.
 *
 * Pure and dependency-free: it runs in a browser and in the bundled checker.
 * Nothing here reads the network.
 */

/** The mirror refuses a topic search whose timestamp range is seven days or wider. */
export const LEDGER_WRITE_SEARCH_WINDOW_LIMIT_SECONDS = 7 * 24 * 60 * 60;

const HEX64 = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x[0-9a-f]*$/;
const TIMESTAMP = /^\d+(\.\d+)?$/;
const NEXT_PATH = /^\/api\/v1\/contracts\//;

export interface LedgerWriteSearchInput {
  /** `0x` + 40 hex, lower case. */
  contractAddress: string;
  /** The RecordWritten event's topic, `0x` + 64 hex, lower case. */
  topic0: string;
  /** `0x` + 64 hex, lower case. */
  recordKey: string;
  /** Seconds since the epoch; the window is `[lower, upper)`. */
  lower: number;
  upper: number;
}

/** The mirror path that lists one record's writes in a window, newest first. */
export function ledgerWriteSearchPath(input: LedgerWriteSearchInput): string {
  const query = `topic0=${input.topic0}&topic1=${input.recordKey}&timestamp=gte:${input.lower}&timestamp=lt:${input.upper}&order=desc&limit=100`;
  return `/api/v1/contracts/${input.contractAddress}/results/logs?${query}`;
}

/** A page's `links.next`, only when it is a path under the mirror's own contracts API; anything else ends the paging. */
export function nextLedgerWritePath(next: unknown): string | null {
  return typeof next === 'string' && NEXT_PATH.test(next) ? next : null;
}

/** One RecordWritten log, as the mirror reports it, with every value held to its pattern. */
export interface LedgerWriteLog {
  /** `0x` + 64 hex. */
  transactionHash: string;
  /** The mirror's consensus timestamp as sent: seconds, or seconds and a fraction. */
  timestamp: string;
  /** The same time, ISO 8601, to the millisecond. */
  committedAt: string;
  /** The write's whole words, `0x` + 64 hex. */
  previousWord: string;
  newWord: string;
  /** `0x` + 40 hex. */
  operator: string;
  encodingVersion: number;
  /** The contract the log names, lower case; null when the log does not say. */
  address: string | null;
  blockNumber: number | null;
  logIndex: number | null;
}

/**
 * A mirror log read as one write of `recordKey`, or null when it is another
 * event, another record, or carries a value outside its pattern. The filter
 * the mirror applied is checked again here.
 */
export function parseLedgerWriteLog(log: unknown, expected: { topic0: string; recordKey: string }): LedgerWriteLog | null {
  if (!log || typeof log !== 'object') return null;
  const raw = log as { topics?: unknown; data?: unknown; transaction_hash?: unknown; timestamp?: unknown; address?: unknown; block_number?: unknown; index?: unknown };
  const topics = Array.isArray(raw.topics) ? raw.topics.map((topic) => String(topic).toLowerCase()) : [];
  if (topics[0] !== expected.topic0 || topics[1] !== expected.recordKey) return null;
  const data = typeof raw.data === 'string' ? raw.data.toLowerCase() : '';
  const transactionHash = typeof raw.transaction_hash === 'string' ? raw.transaction_hash.toLowerCase() : '';
  const timestamp = typeof raw.timestamp === 'string' ? raw.timestamp : '';
  if (!HEX_DATA.test(data) || data.length < 2 + 64 * 3) return null;
  if (!HEX64.test(transactionHash) || !TIMESTAMP.test(timestamp)) return null;
  // RecordWritten(recordKey indexed, operator indexed, encodingVersion, previousWord, newWord): the data words in order.
  const encodingVersion = Number.parseInt(data.slice(2, 2 + 64).slice(-8), 16);
  const previousWord = data.slice(2 + 64, 2 + 64 * 2);
  const newWord = data.slice(2 + 64 * 2, 2 + 64 * 3);
  const [seconds, fraction = ''] = timestamp.split('.');
  const ms = Number(seconds) * 1000 + Number(fraction.slice(0, 3).padEnd(3, '0'));
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return null;
  const address = typeof raw.address === 'string' ? raw.address.toLowerCase() : null;
  return {
    transactionHash,
    timestamp,
    committedAt: new Date(ms).toISOString(),
    previousWord: `0x${previousWord}`,
    newWord: `0x${newWord}`,
    operator: HEX64.test(topics[2] ?? '') ? `0x${topics[2].slice(26)}` : '',
    encodingVersion,
    address,
    blockNumber: Number.isSafeInteger(raw.block_number) ? (raw.block_number as number) : null,
    logIndex: Number.isSafeInteger(raw.index) ? (raw.index as number) : null,
  };
}

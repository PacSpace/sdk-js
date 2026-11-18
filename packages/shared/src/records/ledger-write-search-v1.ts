/**
 * One reading of the public mirror's answers: the request for "where was
 * this record written", the page link, the log, and the limits every mirror
 * answer is held to (its size, its redirects, its next page). The Shared
 * Record page's finder (in the reader's browser), the checker's lookup and
 * the mirror reader's scan all use it, so a change in the mirror's shape is
 * met in one place and a source is held to one rule.
 *
 * Dependency-free: it runs in a browser and in the bundled checker. Nothing
 * here makes a request; `readMirrorJson` reads the body of an answer the
 * caller already has.
 */

/** The mirror refuses a topic search whose timestamp range is seven days or wider. */
export const LEDGER_WRITE_SEARCH_WINDOW_LIMIT_SECONDS = 7 * 24 * 60 * 60;

/** The page size a write search asks for; the mirror's own maximum. */
export const LEDGER_WRITE_SEARCH_PAGE_LIMIT = 100;

/**
 * The most bytes of one mirror answer that are read, counted after any
 * decompression. A full page of 100 logs is about 133,000 bytes on both
 * public mirrors (read 18 November 2026), so this is about eight of them.
 */
export const MIRROR_ANSWER_MAX_BYTES = 1_048_576;

const HEX40 = /^0x[0-9a-f]{40}$/;
const HEX64 = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x[0-9a-f]*$/;
const TIMESTAMP = /^\d+(\.\d+)?$/;

/** Why a mirror answer was not read. */
export type MirrorRefusalCode = 'redirect' | 'too-large' | 'too-many-logs' | 'next-page';

const REFUSAL_CODES: readonly string[] = ['redirect', 'too-large', 'too-many-logs', 'next-page'];

/** A mirror answered, and its answer was not read: a redirect, an answer over the size limit, a page longer than asked for, or a next page somewhere else. */
export class MirrorAnswerRefused extends Error {
  readonly code: MirrorRefusalCode;

  constructor(code: MirrorRefusalCode, message: string) {
    super(message);
    this.name = 'MirrorAnswerRefused';
    this.code = code;
  }
}

/** The refusal's code, or null for any other error. Read by name and code, so it holds across two bundled copies of this module. */
export function mirrorRefusalOf(error: unknown): MirrorRefusalCode | null {
  if (!error || typeof error !== 'object') return null;
  const { name, code } = error as { name?: unknown; code?: unknown };
  return name === 'MirrorAnswerRefused' && typeof code === 'string' && REFUSAL_CODES.includes(code) ? (code as MirrorRefusalCode) : null;
}

/** A request path as a message names it: without its query. */
function pathLabel(path: string | undefined): string {
  return path ? ` (${path.split('?')[0]})` : '';
}

export const mirrorRefusal = {
  redirect: (path?: string) => new MirrorAnswerRefused('redirect', `mirror node answered with a redirect, which is not followed${pathLabel(path)}`),
  tooLarge: (maxBytes: number, path?: string) => new MirrorAnswerRefused('too-large', `mirror node answer is larger than ${maxBytes} bytes${pathLabel(path)}`),
  tooManyLogs: (asked: number, path?: string) => new MirrorAnswerRefused('too-many-logs', `mirror node returned more logs than the ${asked} asked for${pathLabel(path)}`),
  nextPage: () => new MirrorAnswerRefused('next-page', "mirror node gave a next page that is not this contract's log"),
} as const;

/**
 * Whether an answer is a redirect, in each form a runtime gives one: a 3xx
 * status (Node, asked with `redirect: 'manual'`), an opaque redirect (a
 * browser, asked the same way), or an answer that was reached by following one.
 */
export function isMirrorRedirect(response: Pick<Response, 'status'> & Partial<Pick<Response, 'type' | 'redirected'>>): boolean {
  return response.redirected === true || response.type === 'opaqueredirect' || (response.status >= 300 && response.status < 400);
}

/**
 * The text of a mirror answer, read no further than `maxBytes`. The bytes
 * are counted as they are read, after the runtime has decompressed them, so
 * neither a missing content-length nor a small compressed one lets a larger
 * answer in; a content-length over the limit refuses before anything is
 * read. An answer with no stream (a caller's own `fetch`) is read with
 * `text()` and held to the same count.
 */
export async function readMirrorText(response: Response, maxBytes: number = MIRROR_ANSWER_MAX_BYTES, path?: string): Promise<string> {
  const declared = Number(response.headers?.get?.('content-length') ?? Number.NaN);
  const body = response.body;
  if (Number.isFinite(declared) && declared > maxBytes) {
    await body?.cancel?.().catch(() => undefined);
    throw mirrorRefusal.tooLarge(maxBytes, path);
  }
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let text = '';
    let read = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      read += value.byteLength;
      if (read > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw mirrorRefusal.tooLarge(maxBytes, path);
      }
      text += decoder.decode(value, { stream: true });
    }
    return text + decoder.decode();
  }
  // No stream to count (not the case in Node 20 or a browser): the text is read whole, then held to the same limit.
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > maxBytes) throw mirrorRefusal.tooLarge(maxBytes, path);
  return text;
}

/** A mirror answer as JSON, read no further than `maxBytes` (see `readMirrorText`). */
export async function readMirrorJson(response: Response, maxBytes: number = MIRROR_ANSWER_MAX_BYTES, path?: string): Promise<unknown> {
  return JSON.parse(await readMirrorText(response, maxBytes, path)) as unknown;
}

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

/** The mirror path of one contract's log. */
export function contractLogPath(contractAddress: string): string {
  return `/api/v1/contracts/${contractAddress}/results/logs`;
}

/** The mirror path that lists one record's writes in a window, newest first. */
export function ledgerWriteSearchPath(input: LedgerWriteSearchInput): string {
  const query = `topic0=${input.topic0}&topic1=${input.recordKey}&timestamp=gte:${input.lower}&timestamp=lt:${input.upper}&order=desc&limit=${LEDGER_WRITE_SEARCH_PAGE_LIMIT}`;
  return `${contractLogPath(input.contractAddress)}?${query}`;
}

/**
 * A page's `links.next` as the path to ask the same source for, or null.
 * The link is taken only when it stays on the source (`base`, the mirror's
 * address with any path prefix of its own) and on this contract's log:
 * a path, or the source's own address followed by that path, with or without
 * the source's prefix. Another origin, scheme or port, a protocol-relative
 * link, user info, a backslash, a traversal, a fragment, another contract or
 * another path gives null. What comes back is always
 * `/api/v1/contracts/<contract>/results/logs?<query>`, for the caller to put
 * after its own base, so nothing in the link chooses where the request goes.
 */
export function nextLogPath(next: unknown, source: { base: string; contract: string }): string | null {
  if (typeof next !== 'string' || next === '') return null;
  const contract = source.contract.toLowerCase();
  if (!HEX40.test(contract)) return null;
  // Only printable ASCII with no space or backslash: a parser would trim or rewrite the rest.
  if (!/^[\x21-\x5b\x5d-\x7e]+$/.test(next)) return null;
  if (next.startsWith('//')) return null;
  let base: URL;
  let url: URL;
  try {
    base = new URL(source.base);
    url = new URL(next, `${base.origin}/`);
  } catch {
    return null;
  }
  if (base.protocol !== 'https:' && base.protocol !== 'http:') return null;
  if (url.origin !== base.origin || url.username !== '' || url.password !== '' || url.hash !== '' || next.includes('#')) return null;
  // The path as written, before a parser folds dots away.
  const written = (next.startsWith('/') ? next : next.slice(next.indexOf('/', next.indexOf('//') + 2))).split('?')[0];
  if (/(^|\/)\.{1,2}(\/|$)/.test(written) || /%2e/i.test(written) || written !== url.pathname) return null;
  if (url.search.length < 2) return null;
  const logs = contractLogPath(contract);
  const prefix = base.pathname.replace(/\/+$/, '');
  const path = url.pathname.toLowerCase();
  if (path !== logs && !(prefix !== '' && url.pathname.startsWith(`${prefix}/`) && url.pathname.slice(prefix.length).toLowerCase() === logs)) return null;
  return `${logs}${url.search}`;
}

/** The same page of a contract's log, asked for `limit` logs: the link's own `limit` replaced, the rest left as written. */
export function withLogPageLimit(path: string, limit: number): string {
  const at = path.indexOf('?');
  const before = at === -1 ? path : path.slice(0, at);
  const parts = at === -1 ? [] : path.slice(at + 1).split('&').filter((part) => part !== '');
  let placed = false;
  const out: string[] = [];
  for (const part of parts) {
    if (!part.startsWith('limit=')) out.push(part);
    else if (!placed) {
      out.push(`limit=${limit}`);
      placed = true;
    }
  }
  if (!placed) out.push(`limit=${limit}`);
  return `${before}?${out.join('&')}`;
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
  /** The contract the log names, lower case: always the contract asked for. */
  address: string;
  blockNumber: number | null;
  logIndex: number | null;
}

/**
 * A mirror log read as one write of `recordKey` on `contractAddress`, or
 * null when it is another event, another record, another contract's log or
 * one that names no contract, or carries a value outside its pattern. The
 * filter the mirror applied is checked again here.
 */
export function parseLedgerWriteLog(log: unknown, expected: { topic0: string; recordKey: string; contractAddress: string }): LedgerWriteLog | null {
  if (!log || typeof log !== 'object') return null;
  const raw = log as { topics?: unknown; data?: unknown; transaction_hash?: unknown; timestamp?: unknown; address?: unknown; block_number?: unknown; index?: unknown };
  const address = typeof raw.address === 'string' ? raw.address.toLowerCase() : '';
  if (!HEX40.test(address) || address !== String(expected.contractAddress).toLowerCase()) return null;
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

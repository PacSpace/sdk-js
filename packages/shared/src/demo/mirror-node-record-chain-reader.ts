import { ethers } from 'ethers';
import { normalizeProofHash } from '../proof/merkle-v2';
import { hex256 } from '../proof/slot-encoding-v1';
import { MIRROR_NODE_BY_CHAIN } from '../records/inspect-record-calldata-v1';
import {
  contractLogPath,
  isMirrorRedirect,
  KEPT_LOG_DATA_MAX_CHARS,
  KEPT_LOG_MAX_TOPICS,
  LEDGER_WRITE_SEARCH_PAGE_LIMIT,
  ledgerWriteSearchPath,
  LOG_SCAN_BUDGET_TIMEOUTS,
  LOG_SCAN_MAX_KEPT_LOGS,
  LOG_SCAN_MAX_REQUESTS,
  MIRROR_ANSWER_MAX_BYTES,
  mirrorRefusal,
  mirrorRefusalOf,
  nextLogPath,
  parseLedgerWriteLog,
  readMirrorJson,
  readMirrorText,
  withLogPageLimit,
} from '../records/ledger-write-search-v1';
import {
  LEDGER_HEAD_ADVANCED_TOPIC,
  RECORD_LANE_ABI_V38,
  RECORD_WRITTEN_TOPIC,
  type LedgerAdvance,
  type OnChainLayout,
  type RecordChainReader,
  type RecordWrite,
  type RecordWriteSearchResult,
} from './independent-verify-records';

/**
 * A `RecordChainReader` over the Hedera mirror node REST API (plan step 5,
 * "chain reader (JSON-RPC + Hedera mirror node)"). Reads go through
 * `POST /api/v1/contracts/call` (an `eth_call` equivalent) and the event
 * history through `GET /api/v1/contracts/{address}/results/logs`, filtered
 * by topic and paged with the mirror's `links.next`, because the JSON-RPC
 * relay caps `eth_getLogs` block ranges too narrowly for a full history
 * scan and rate-limits the shared endpoint. The mirror node is a public
 * source PacSpace does not operate; a relying party can point the reader at
 * any mirror it trusts.
 *
 * The source is held to its own address, size and contract: every request
 * goes to the base it was given, a redirect is not followed, no answer is
 * read past `MIRROR_ANSWER_MAX_BYTES`, a page with more logs than were
 * asked for is not read, and a next page is read only from the same source
 * and this contract's log. Each of these ends the read with a
 * `MirrorAnswerRefused`, without a retry.
 *
 * A whole scan of the contract's log is bounded as well. It is given sixty
 * request timeouts in all and each request no more than what is left; it
 * asks at most 10,000 times, counting a page asked again smaller; it keeps
 * at most a million logs; and every log must come after the last one read,
 * by consensus timestamp and index, so a source cannot repeat a page or go
 * back. A scan that stops is refused whole, never read as a shorter log.
 */
export interface MirrorNodeReaderOptions {
  /** Mirror base URL; defaults from `chainId` through MIRROR_NODE_BY_CHAIN. */
  mirrorBaseUrl?: string;
  chainId?: number;
  contractAddress: string;
  timeoutMs?: number;
  /** Page size for log reads (mirror maximum is 100). */
  pageSize?: number;
  fetchImpl?: typeof fetch;
  /** Retries on 429 and 5xx (each with a short linear backoff). */
  attempts?: number;
  /**
   * Keep the contract's log pages once read, for this reader's life, so a second question of the same
   * history asks nothing more. Only for a reader made for one run.
   */
  keepLogPages?: boolean;
  /** Test seams for a whole scan's stops: its clock, the most requests it makes and the most logs it keeps. */
  scan?: { now?: () => number; maxRequests?: number; maxKeptLogs?: number };
}

/** Six days: a day inside the mirror's rule that a topic search span less than seven. */
export const RECORD_WRITE_SEARCH_WINDOW_SECONDS = 6 * 24 * 60 * 60;
const DAY_SECONDS = 24 * 60 * 60;
/** A consensus timestamp as the mirror sends it: seconds, a dot, nine digits. */
const CONSENSUS_TIMESTAMP = /^\d{1,12}\.\d{9}$/;

/** `1794856672.526106228` as an ISO instant to the millisecond, or undefined when it is not a consensus timestamp. */
function committedAtOf(timestamp: unknown): string | undefined {
  if (typeof timestamp !== 'string' || !CONSENSUS_TIMESTAMP.test(timestamp)) return undefined;
  const [seconds, fraction] = timestamp.split('.');
  return new Date(Number(seconds) * 1000 + Number(fraction.slice(0, 3))).toISOString();
}

interface MirrorLog {
  address: string;
  data: string;
  index: number;
  topics: string[];
  block_number: number;
  transaction_hash: string;
  timestamp: string;
}

/** One scan's stops: when its time ends, and how many times it has asked. */
interface ScanState {
  deadline: number;
  requests: number;
}

interface MirrorLogsPage {
  logs?: unknown;
  links?: { next?: unknown };
}

const KEPT_TOPICS: readonly string[] = [RECORD_WRITTEN_TOPIC.toLowerCase(), LEDGER_HEAD_ADVANCED_TOPIC.toLowerCase()];
const HEX_DATA = /^0x[0-9a-fA-F]*$/;

/** Where a log sits in the mirror's order: its consensus timestamp in nanoseconds, then its index. */
export interface MirrorLogPosition {
  nanos: bigint;
  index: number;
}

/** A log's position, or null when its timestamp is not a consensus timestamp or its index is not a whole number. */
export function mirrorLogPosition(raw: unknown): MirrorLogPosition | null {
  if (!raw || typeof raw !== 'object') return null;
  const { timestamp, index } = raw as { timestamp?: unknown; index?: unknown };
  if (typeof timestamp !== 'string' || !CONSENSUS_TIMESTAMP.test(timestamp)) return null;
  if (typeof index !== 'number' || !Number.isSafeInteger(index) || index < 0) return null;
  const [seconds, fraction] = timestamp.split('.');
  return { nanos: BigInt(seconds) * 1_000_000_000n + BigInt(fraction), index };
}

/** Whether `next` comes after `last` in the mirror's ascending order. */
export function mirrorLogFollows(last: MirrorLogPosition | null, next: MirrorLogPosition): boolean {
  return last === null || next.nanos > last.nanos || (next.nanos === last.nanos && next.index > last.index);
}

/**
 * A log of the scan as the reader keeps it: only the two events it reads
 * (RecordWritten, LedgerHeadAdvanced), only the seven values it uses, and
 * only at those events' fixed size (three topics, three data words), so
 * what a history's scan holds in memory does not grow with what else the
 * contract's log carries or with what a source pads a log with. With
 * `contract`, the log must also be that contract's and sit at a well formed
 * position. Any other log is null.
 */
export function keptMirrorLog(raw: unknown, contract?: string): MirrorLog | null {
  if (!raw || typeof raw !== 'object') return null;
  const log = raw as Partial<Record<keyof MirrorLog, unknown>>;
  if (!Array.isArray(log.topics) || typeof log.data !== 'string') return null;
  if (log.topics.length > KEPT_LOG_MAX_TOPICS || log.data.length > KEPT_LOG_DATA_MAX_CHARS || !HEX_DATA.test(log.data)) return null;
  const topics = log.topics.map((topic) => String(topic));
  if (!KEPT_TOPICS.includes((topics[0] ?? '').toLowerCase())) return null;
  if (topics.some((topic) => topic.length > 66)) return null;
  if (contract !== undefined) {
    if (typeof log.address !== 'string' || log.address.toLowerCase() !== contract) return null;
    if (!mirrorLogPosition(raw)) return null;
    if (typeof log.block_number !== 'number' || !Number.isSafeInteger(log.block_number)) return null;
    if (typeof log.transaction_hash !== 'string' || log.transaction_hash.length > 98) return null;
  }
  return {
    address: log.address as string,
    data: log.data,
    index: log.index as number,
    topics,
    block_number: log.block_number as number,
    transaction_hash: log.transaction_hash as string,
    timestamp: log.timestamp as string,
  };
}

export function createMirrorNodeRecordChainReader(options: MirrorNodeReaderOptions): RecordChainReader {
  const chainId = options.chainId ?? 296;
  const base = (options.mirrorBaseUrl ?? MIRROR_NODE_BY_CHAIN[chainId] ?? '').replace(/\/+$/, '');
  if (!base) throw new Error(`No mirror node known for chain ${chainId}; pass mirrorBaseUrl.`);
  const contractAddress = ethers.getAddress(options.contractAddress).toLowerCase();
  const timeoutMs = Number(options.timeoutMs || 10000);
  const pageSize = Math.min(100, Math.max(1, Number(options.pageSize || 100)));
  const attempts = Math.max(1, options.attempts ?? 3);
  const fetchImpl = options.fetchImpl ?? fetch;
  const iface = new ethers.Interface(RECORD_LANE_ABI_V38 as unknown as string[]);
  const now = options.scan?.now ?? Date.now;
  const maxScanRequests = options.scan?.maxRequests ?? LOG_SCAN_MAX_REQUESTS;
  const maxKeptLogs = options.scan?.maxKeptLogs ?? LOG_SCAN_MAX_KEPT_LOGS;
  const scanBudgetMs = LOG_SCAN_BUDGET_TIMEOUTS * timeoutMs;

  /**
   * One answer from the source: always the base and a path, never an address an answer gave. With `deadline`
   * (a scan's), each attempt gets no more than what is left of it, and running out is the scan's refusal.
   */
  async function request(path: string, init?: RequestInit, deadline?: number): Promise<unknown> {
    const url = `${base}${path}`;
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const left = deadline === undefined ? timeoutMs : deadline - now();
      if (left <= 0) throw mirrorRefusal.scanTooSlow(scanBudgetMs);
      const allowed = Math.min(timeoutMs, left);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), allowed);
      try {
        const response = await fetchImpl(url, { ...init, redirect: 'manual', signal: controller.signal });
        if (isMirrorRedirect(response)) {
          await response.body?.cancel?.().catch(() => undefined);
          throw mirrorRefusal.redirect(path);
        }
        if (response.status === 429 || response.status >= 500) {
          await response.body?.cancel?.().catch(() => undefined);
          lastError = new Error(`mirror node ${response.status} for ${path}`);
        } else if (!response.ok) {
          const body = await readMirrorText(response, MIRROR_ANSWER_MAX_BYTES, path).catch(() => '');
          throw new Error(`mirror node ${response.status} for ${path}${body ? `: ${body.slice(0, 200)}` : ''}`);
        } else {
          return await readMirrorJson(response, MIRROR_ANSWER_MAX_BYTES, path);
        }
      } catch (error) {
        // A refused answer is the source's own doing: asking again would not change it.
        if (mirrorRefusalOf(error)) throw error;
        if ((error as Error).name === 'AbortError') {
          // Cut off by what was left of the scan's time, not by a request's own timeout: the scan is over.
          if (deadline !== undefined && allowed < timeoutMs) throw mirrorRefusal.scanTooSlow(scanBudgetMs);
          lastError = new Error(`mirror node request timed out after ${timeoutMs}ms (${path})`);
        }
        else if (/^mirror node \d{3} for/.test((error as Error).message) && !/^mirror node (429|5\d\d)/.test((error as Error).message)) throw error;
        else lastError = error as Error;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
    }
    if (deadline !== undefined && now() >= deadline) throw mirrorRefusal.scanTooSlow(scanBudgetMs);
    throw lastError ?? new Error(`mirror node request failed (${path})`);
  }

  async function call(fn: string, args: unknown[] = []): Promise<ethers.Result> {
    const data = iface.encodeFunctionData(fn, args);
    const json = (await request('/api/v1/contracts/call', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ to: contractAddress, data, estimate: false }),
    })) as { result?: string; _status?: { messages?: Array<{ message?: string; detail?: string }> } };
    if (typeof json?.result !== 'string') {
      const detail = json?._status?.messages?.map((m) => m.message).filter(Boolean).join(', ');
      throw new Error(`mirror node call ${fn} returned no result${detail ? ` (${detail})` : ''}`);
    }
    return iface.decodeFunctionResult(fn, json.result);
  }

  function matchesTopics(log: MirrorLog, topics: Array<string | null>): boolean {
    return topics.every((topic, index) => !topic || (log.topics[index] ?? '').toLowerCase() === topic.toLowerCase());
  }

  let keptLogs: Promise<MirrorLog[]> | null = null;

  /** Every log of the contract, unfiltered, in the mirror's ascending order. */
  function readAllLogs(): Promise<MirrorLog[]> {
    if (!options.keepLogPages) return readAllLogPages();
    if (!keptLogs) {
      keptLogs = readAllLogPages();
      keptLogs.catch(() => {
        keptLogs = null;
      });
    }
    return keptLogs;
  }

  async function readAllLogPages(): Promise<MirrorLog[]> {
    const params = new URLSearchParams();
    params.set('order', 'asc');
    params.set('limit', String(pageSize));
    // The mirror refuses a topic filter without a timestamp range of at most
    // seven days ("Cannot search topics without a valid timestamp range"), and
    // a full history spans months. The scan therefore reads the contract's
    // logs unfiltered and applies the topics here; the contract's other
    // events are read past and not kept. The mirror filters by consensus
    // timestamp, not block; block bounds are applied client-side as well.
    let next: string | null = `${contractLogPath(contractAddress)}?${params.toString()}`;
    const out: MirrorLog[] = [];
    const scan: ScanState = { deadline: now() + scanBudgetMs, requests: 0 };
    let last: MirrorLogPosition | null = null;
    let size = pageSize;
    while (next) {
      const { page, asked } = await readLogPage(next, size, scan);
      size = Math.min(pageSize, asked * 2);
      // An answer that is no page at all (JSON null) throws here, as it always has: read as an empty page it would end a history early.
      // The same holds for `logs` that is neither a list nor absent: it throws rather than read as an empty page.
      const logs: unknown[] = Array.isArray(page.logs) ? page.logs : [...((page.logs ?? []) as Iterable<unknown>)];
      if (logs.length > asked) throw mirrorRefusal.tooManyLogs(asked, next);
      for (const raw of logs) {
        // Forward only: a log with a position must come after the last one read, so a page repeated or
        // one that goes back ends the scan. A log without a well formed position is read past, never kept.
        const position = mirrorLogPosition(raw);
        if (!position) continue;
        if (!mirrorLogFollows(last, position)) throw mirrorRefusal.notForward();
        last = position;
        const log = keptMirrorLog(raw, contractAddress);
        if (!log) continue;
        if (out.length >= maxKeptLogs) throw mirrorRefusal.scanTooManyLogs(maxKeptLogs);
        out.push(log);
      }
      const link = page.links?.next;
      if (link === null || link === undefined || link === '') {
        next = null;
      } else {
        // A link that leaves the source or this contract's log ends the run: stopping quietly would cut a history short.
        const path = nextLogPath(link, { base, contract: contractAddress });
        if (!path) throw mirrorRefusal.nextPage();
        next = withLogPageLimit(path, size);
      }
    }
    return out;
  }

  /**
   * One page of the scan. A page over the size limit is asked for again with
   * half as many logs, down to one, so a page that carries a few large logs
   * is still read; only a single log over the limit is refused. The scan
   * asks for the page after it at twice the size that was read, up to the
   * full size, so a run of large logs is not asked for from the top each page.
   * Every ask counts toward the scan's request stop and runs inside its time.
   */
  async function readLogPage(path: string, start: number, scan: ScanState): Promise<{ page: MirrorLogsPage; asked: number }> {
    let asked = start;
    for (;;) {
      if (scan.requests >= maxScanRequests) throw mirrorRefusal.scanTooManyRequests(maxScanRequests);
      scan.requests += 1;
      try {
        return { page: (await request(withLogPageLimit(path, asked), undefined, scan.deadline)) as MirrorLogsPage, asked };
      } catch (error) {
        if (mirrorRefusalOf(error) !== 'too-large' || asked <= 1) throw error;
        asked = Math.max(1, Math.floor(asked / 2));
      }
    }
  }

  async function scanLogs(topics: Array<string | null>, fromBlock: number, toBlock: number | 'latest'): Promise<MirrorLog[]> {
    const out: MirrorLog[] = [];
    for (const log of await readAllLogs()) {
      if (!matchesTopics(log, topics)) continue;
      if (log.block_number < fromBlock) continue;
      if (toBlock !== 'latest' && log.block_number > toBlock) continue;
      out.push(log);
    }
    out.sort((a, b) => a.block_number - b.block_number || a.index - b.index);
    return out;
  }

  /** One page of a write search: one attempt, no redirect followed, held to the size and count limits, cut off after `ms`. */
  async function searchPage(path: string, ms: number): Promise<MirrorLogsPage | 'timeout'> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    try {
      const response = await fetchImpl(`${base}${path}`, { headers: { accept: 'application/json' }, redirect: 'error', signal: controller.signal });
      if (isMirrorRedirect(response)) throw mirrorRefusal.redirect(path);
      if (!response.ok) throw new Error(`mirror node ${response.status} for a record's writes`);
      const page = (await readMirrorJson(response, MIRROR_ANSWER_MAX_BYTES, path)) as MirrorLogsPage;
      // An answer that is no page at all (JSON null) throws here, as it always has, and the lookup says it was not read.
      if (Array.isArray(page.logs) && page.logs.length > LEDGER_WRITE_SEARCH_PAGE_LIMIT) throw mirrorRefusal.tooManyLogs(LEDGER_WRITE_SEARCH_PAGE_LIMIT, path);
      return page;
    } catch (error) {
      if (controller.signal.aborted) return 'timeout';
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    contractAddress,
    async getRecord(recordKey) {
      const key = normalizeProofHash(recordKey, 'recordKey');
      const result = await call('getRecord', [key]);
      return hex256(BigInt(result[0] as bigint));
    },
    async getLayout(layoutId) {
      const l = await call('getLayout', [layoutId]);
      const layout: OnChainLayout = {
        layoutDigest: String(l[0]).toLowerCase(),
        stateBits: Number(l[1]),
        sealBits: Number(l[2]),
        registered: Boolean(l[3]),
      };
      return layout;
    },
    async getBatchRoot(batchId) {
      const result = await call('getBatchRoot', [BigInt(batchId)]);
      return normalizeProofHash(String(result[0]), 'observedProofRoot');
    },
    async getLedgerHead() {
      const result = await call('getLedgerHead', []);
      return normalizeProofHash(String(result[0]), 'ledgerHead');
    },
    async getLedgerAdvances(fromBlock = 0, toBlock = 'latest') {
      const logs = await scanLogs([LEDGER_HEAD_ADVANCED_TOPIC], fromBlock, toBlock);
      const out: LedgerAdvance[] = [];
      for (const log of logs) {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (!parsed) continue;
        out.push({
          batchId: parsed.args.batchId.toString(),
          merkleRoot: String(parsed.args.merkleRoot).toLowerCase(),
          previousHead: String(parsed.args.previousHead).toLowerCase(),
          newHead: String(parsed.args.newHead).toLowerCase(),
          blockNumber: log.block_number,
          transactionHash: log.transaction_hash,
        });
      }
      out.sort((a, b) => Number(BigInt(a.batchId) - BigInt(b.batchId)));
      return out;
    },
    async getRecordWrites(recordKey, fromBlock = 0, toBlock = 'latest') {
      const key = normalizeProofHash(recordKey, 'recordKey');
      const logs = await scanLogs([RECORD_WRITTEN_TOPIC, key], fromBlock, toBlock);
      const out: RecordWrite[] = [];
      for (const log of logs) {
        const parsed = iface.parseLog({ topics: [...log.topics], data: log.data });
        if (!parsed) continue;
        out.push({
          previousWord: hex256(BigInt(parsed.args.previousWord)),
          newWord: hex256(BigInt(parsed.args.newWord)),
          operator: String(parsed.args.operator).toLowerCase(),
          encodingVersion: Number(parsed.args.encodingVersion),
          blockNumber: log.block_number,
          transactionHash: log.transaction_hash,
          logIndex: log.index,
          committedAt: committedAtOf(log.timestamp),
          contractAddress: typeof log.address === 'string' ? log.address.toLowerCase() : undefined,
        });
      }
      return out;
    },
    async findRecordWrites(recordKey, search) {
      const key = normalizeProofHash(recordKey, 'recordKey').toLowerCase();
      const topic0 = RECORD_WRITTEN_TOPIC.toLowerCase();
      const now = search.now ?? Date.now;
      const deadline = now() + search.budgetMs;
      const windowSeconds = Math.max(1, Math.floor(search.windowSeconds ?? RECORD_WRITE_SEARCH_WINDOW_SECONDS));
      const nowSeconds = Math.floor(now() / 1000);
      const hint = search.startAt ? Date.parse(search.startAt) : Number.NaN;
      let upper = Math.min(Number.isFinite(hint) ? Math.floor(hint / 1000) : nowSeconds, nowSeconds) + DAY_SECONDS;
      const writes: RecordWrite[] = [];
      let requests = 0;
      const end = (ended: RecordWriteSearchResult['ended']): RecordWriteSearchResult => ({ writes, ended, requests });
      while (!search.done(writes)) {
        if (upper <= 0) return end('limit');
        const lower = Math.max(0, upper - windowSeconds);
        let path: string | null = ledgerWriteSearchPath({ contractAddress, topic0, recordKey: key, lower, upper });
        while (path) {
          const left = deadline - now();
          if (requests >= search.maxRequests || left <= 0) return end('limit');
          requests += 1;
          const page = await searchPage(path, left);
          if (page === 'timeout') return end('timeout');
          for (const log of Array.isArray(page?.logs) ? page.logs : []) {
            // The shared parse holds the log to this record and this contract, as the page's finder does.
            const write = parseLedgerWriteLog(log, { topic0, recordKey: key, contractAddress });
            // The stricter time pattern: a value this reader prints is the mirror's consensus timestamp or nothing.
            if (!write || !CONSENSUS_TIMESTAMP.test(write.timestamp)) continue;
            writes.push({
              previousWord: write.previousWord,
              newWord: write.newWord,
              operator: write.operator,
              encodingVersion: write.encodingVersion,
              blockNumber: write.blockNumber ?? undefined,
              transactionHash: write.transactionHash,
              logIndex: write.logIndex ?? undefined,
              committedAt: write.committedAt,
              contractAddress: write.address,
            });
          }
          if (search.done(writes)) return end('done');
          const link = page?.links?.next;
          path = nextLogPath(link, { base, contract: contractAddress });
          // As in the scan: a link that leaves the source or this contract's log ends the lookup as not read, not as a shorter page.
          if (!path && link !== null && link !== undefined && link !== '') throw mirrorRefusal.nextPage();
        }
        upper = lower;
      }
      return end('done');
    },
  };
}

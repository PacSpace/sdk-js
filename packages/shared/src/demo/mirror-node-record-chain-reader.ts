import { ethers } from 'ethers';
import { normalizeProofHash } from '../proof/merkle-v2';
import { hex256 } from '../proof/slot-encoding-v1';
import { MIRROR_NODE_BY_CHAIN } from '../records/inspect-record-calldata-v1';
import {
  contractLogPath,
  isMirrorRedirect,
  LEDGER_WRITE_SEARCH_PAGE_LIMIT,
  ledgerWriteSearchPath,
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

interface MirrorLogsPage {
  logs?: unknown;
  links?: { next?: unknown };
}

const KEPT_TOPICS: readonly string[] = [RECORD_WRITTEN_TOPIC.toLowerCase(), LEDGER_HEAD_ADVANCED_TOPIC.toLowerCase()];

/**
 * A log of the scan as the reader keeps it: only the two events it reads
 * (RecordWritten, LedgerHeadAdvanced) and only the seven values it uses, so
 * what a history's scan holds in memory does not grow with what else the
 * contract's log carries. Any other log is null.
 */
export function keptMirrorLog(raw: unknown): MirrorLog | null {
  if (!raw || typeof raw !== 'object') return null;
  const log = raw as Partial<Record<keyof MirrorLog, unknown>>;
  if (!Array.isArray(log.topics) || typeof log.data !== 'string') return null;
  const topics = log.topics.map((topic) => String(topic));
  if (!KEPT_TOPICS.includes((topics[0] ?? '').toLowerCase())) return null;
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

  /** One answer from the source: always the base and a path, never an address an answer gave. */
  async function request(path: string, init?: RequestInit): Promise<unknown> {
    const url = `${base}${path}`;
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
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
        if ((error as Error).name === 'AbortError') lastError = new Error(`mirror node request timed out after ${timeoutMs}ms (${path})`);
        else if (/^mirror node \d{3} for/.test((error as Error).message) && !/^mirror node (429|5\d\d)/.test((error as Error).message)) throw error;
        else lastError = error as Error;
      } finally {
        clearTimeout(timer);
      }
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, 250 * attempt));
    }
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
    let pages = 0;
    let size = pageSize;
    while (next) {
      const { page, asked } = await readLogPage(next, size);
      size = Math.min(pageSize, asked * 2);
      // An answer that is no page at all (JSON null) throws here, as it always has: read as an empty page it would end a history early.
      // The same holds for `logs` that is neither a list nor absent: it throws rather than read as an empty page.
      const logs: unknown[] = Array.isArray(page.logs) ? page.logs : [...((page.logs ?? []) as Iterable<unknown>)];
      if (logs.length > asked) throw mirrorRefusal.tooManyLogs(asked, next);
      for (const raw of logs) {
        const log = keptMirrorLog(raw);
        if (log) out.push(log);
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
      pages += 1;
      if (pages > 10_000) throw new Error('mirror node log scan exceeded 10,000 pages');
    }
    return out;
  }

  /**
   * One page of the scan. A page over the size limit is asked for again with
   * half as many logs, down to one, so a page that carries a few large logs
   * is still read; only a single log over the limit is refused. The scan
   * asks for the page after it at twice the size that was read, up to the
   * full size, so a run of large logs is not asked for from the top each page.
   */
  async function readLogPage(path: string, start: number): Promise<{ page: MirrorLogsPage; asked: number }> {
    let asked = start;
    for (;;) {
      try {
        return { page: (await request(withLogPageLimit(path, asked))) as MirrorLogsPage, asked };
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

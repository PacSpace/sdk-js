import { ethers } from 'ethers';
import { normalizeProofHash } from '../proof/merkle-v2';
import { hex256 } from '../proof/slot-encoding-v1';
import { MIRROR_NODE_BY_CHAIN } from '../records/inspect-record-calldata-v1';
import { ledgerWriteSearchPath, nextLedgerWritePath, parseLedgerWriteLog } from '../records/ledger-write-search-v1';
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
  logs: MirrorLog[];
  links?: { next?: string | null };
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

  async function request(path: string, init?: RequestInit): Promise<unknown> {
    const url = path.startsWith('http') ? path : `${base}${path.startsWith('/') ? '' : '/'}${path}`;
    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const response = await fetchImpl(url, { ...init, signal: controller.signal });
        if (response.status === 429 || response.status >= 500) {
          lastError = new Error(`mirror node ${response.status} for ${path}`);
        } else if (!response.ok) {
          const body = await response.text().catch(() => '');
          throw new Error(`mirror node ${response.status} for ${path}${body ? `: ${body.slice(0, 200)}` : ''}`);
        } else {
          return (await response.json()) as unknown;
        }
      } catch (error) {
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
    // logs unfiltered and applies the topics here; the contract emits only
    // RecordWritten and LedgerHeadAdvanced, so the extra pages are bounded by
    // the lane's own history. The mirror filters by consensus timestamp, not
    // block; block bounds are applied client-side as well.
    let next: string | null = `/api/v1/contracts/${contractAddress}/results/logs?${params.toString()}`;
    const out: MirrorLog[] = [];
    let pages = 0;
    while (next) {
      const page = (await request(next)) as MirrorLogsPage;
      out.push(...(page.logs ?? []));
      next = page.links?.next ?? null;
      pages += 1;
      if (pages > 10_000) throw new Error('mirror node log scan exceeded 10,000 pages');
    }
    return out;
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

  /** One page of a write search: one attempt, no redirect followed, cut off after `ms`. */
  async function searchPage(path: string, ms: number): Promise<MirrorLogsPage | 'timeout'> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), ms);
    try {
      const response = await fetchImpl(`${base}${path}`, { headers: { accept: 'application/json' }, redirect: 'error', signal: controller.signal });
      if (!response.ok) throw new Error(`mirror node ${response.status} for a record's writes`);
      return (await response.json()) as MirrorLogsPage;
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
          for (const log of Array.isArray(page.logs) ? page.logs : []) {
            const write = parseLedgerWriteLog(log, { topic0, recordKey: key });
            // The stricter time pattern: a value this reader prints is the mirror's consensus timestamp or nothing.
            if (!write || write.address !== contractAddress || !CONSENSUS_TIMESTAMP.test(write.timestamp)) continue;
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
          path = nextLedgerWritePath(page.links?.next);
        }
        upper = lower;
      }
      return end('done');
    },
  };
}

import { checkHistory, HistoryFileError, parseHistoryFile, type CheckOptions } from './check';

export const RELEASES_SCHEMA = 'pacspace-releases/v1';
export const RELEASE_MANIFEST_FORMAT = 'pacspace-release-manifest/v2';
export const RELEASES_PATH = '/.well-known/pacspace-releases.json';
/** The history is read from this path on the host only; the releases file's `historyUrl` is not followed. */
export const HISTORY_PATH = '/.well-known/pacspace-releases-history.json';
export const MANIFEST_PATH = '/manifest.json';
export const DEFAULT_RELEASE_ORIGIN = 'https://records.pacspace.io';

/** A release record on the ledger: the checker reads only the record it pins, never one a host names. */
export interface ReleaseAnchor {
  recordKey: string;
  contractAddress: string;
  chainId: number;
}

/** The production release record (card 10, F8): the record `key-pages` in PacSpace's release workspace. */
export const PRODUCTION_RELEASE_ANCHORS: readonly ReleaseAnchor[] = Object.freeze([
  Object.freeze({
    recordKey: '0x04a6bd0ad122d086eaa2de181816b9a3d8894ec91d18588add27aca6675bd867',
    contractAddress: '0xb3ba5f3eb4fc5d4a495500a746d23da49e0a0a86',
    chainId: 295,
  }),
]);

/** Each file is asked for three ways; only no encoding or gzip may come back. */
export const PROBE_ENCODINGS = Object.freeze(['identity', 'gzip', 'gzip, deflate, br, zstd']);

/** The words `check release` prints (W-L2h-10 to W-L2h-17, W-C10-30 to 35). */
export const releaseWords = {
  matches: (commit: string, origin: string, n: number, seq: number) =>
    `Release ${commit} on ${origin}: ${n} files match the release record on the ledger (entry ${seq}).`,
  differs: (path: string) => `${path} differs from the release record.`,
  notServed: (path: string) => `${path} is in the release record but the host doesn't serve it.`,
  extraScript: (page: string, script: string) => `${page} loads ${script}, which isn't in the release record.`,
  policyDiffers: (page: string) => `The policy on ${page} differs from the release record.`,
  policyReportOnly: (page: string) => `The policy on ${page} is only reported, not enforced.`,
  compressedDiffers: (path: string) => `The compressed copy of ${path} differs from the release record.`,
  headerDiffers: (header: string, path: string) => `${header} on ${path} differs from the release record.`,
  stagingOnly: (record: string) => `This run checks ${record}, not the production release record. It is for staging only.`,
  notProductionRecord: 'The ledger record here is not the production release record.',
  inProgress: (served: string, latest: string) =>
    `The host serves ${served}; the release record's latest entry is ${latest}. A release may be in progress; run it again in a few minutes.`,
  unreachable: (origin: string) => `Couldn't reach ${origin} or the ledger. Nothing was checked.`,
  total: (n: number) => (n === 1 ? '1 difference from the release record.' : `${n} differences from the release record.`),
} as const;

export interface ReleaseManifestFile {
  path: string;
  sha256: string;
  bytes?: number;
  gzip?: { sha256: string; bytes?: number };
  /**
   * The header set the key server sends with this file (manifest v2). The check
   * requires each of these headers with its value; a header outside the set, such
   * as one a host adds in front of the server, is not a difference.
   */
  headers: Record<string, string>;
}

export interface ReleaseManifestPage {
  path: string;
  file?: string;
  policy: string;
  reportOnlyPolicy?: string;
}

export interface ReleaseManifest {
  format: typeof RELEASE_MANIFEST_FORMAT;
  commit: string;
  files: ReleaseManifestFile[];
  pages: ReleaseManifestPage[];
}

export interface ReleaseEntryRef {
  commit: string;
  manifestSha256: string;
  record?: { seq?: number };
}

export interface ReleasesFile {
  schema: typeof RELEASES_SCHEMA;
  latest: ReleaseEntryRef;
  previous?: ReleaseEntryRef | null;
  historyUrl: string;
}

export type ReleaseDifference =
  | { kind: 'differs'; path: string }
  | { kind: 'not-served'; path: string }
  | { kind: 'extra-script'; page: string; script: string }
  | { kind: 'policy'; page: string }
  | { kind: 'policy-report-only'; page: string }
  | { kind: 'compressed'; path: string }
  | { kind: 'header'; header: string; path: string }
  | { kind: 'anchor' };

export interface ReleaseReport {
  origin: string;
  /** `matches`: every file matches the latest entry; `in-progress`: the host serves the entry before it. */
  outcome: 'matches' | 'differs' | 'in-progress' | 'unreachable';
  commit: string | null;
  /** The entry the served manifest matches, 1-based, when it matches one the ledger verified. */
  entry: number | null;
  latestEntry: number | null;
  files: number;
  differences: ReleaseDifference[];
  sentences: string[];
  /** The release record a staging run checked, when it named one. */
  stagingRecord?: string;
  /** 0 everything matches; 1 any difference, or any staging run; 2 the host or the ledger could not be reached. */
  exitCode: 0 | 1 | 2;
}

/** One answer as the host sent it: no decoding, every header. */
export interface RawAnswer {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

export type RawGet = (url: string, acceptEncoding: string, timeoutMs: number) => Promise<RawAnswer>;

export interface ReleaseOptions {
  origin?: string;
  source?: CheckOptions['source'];
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  /** Reads files as the host sent them, undecoded; the CLI passes Node's https client. Required. */
  rawGet?: RawGet;
  /** The pinned release records; the production record unless a caller pins others. */
  anchors?: readonly ReleaseAnchor[];
  /** Staging only: check this record instead. Refused with the production origin, and never exits 0. */
  releaseRecord?: ReleaseAnchor;
}

export class ReleaseUsageError extends Error {}

const sameAnchor = (a: ReleaseAnchor, b: { recordKey?: unknown; chainId?: unknown; contractAddress?: unknown }) =>
  String(b.recordKey ?? '').toLowerCase() === a.recordKey.toLowerCase() &&
  Number(b.chainId) === a.chainId &&
  String(b.contractAddress ?? '').toLowerCase() === a.contractAddress.toLowerCase();

class Unreachable extends Error {}

const HASH_RE = /^[0-9a-f]{64}$/;

/** A gzip body's bytes, or null when it isn't gzip. */
async function gunzip(bytes: Uint8Array): Promise<Uint8Array | null> {
  try {
    const stream = new Blob([bytes as BlobPart]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sentenceOf(difference: ReleaseDifference): string {
  switch (difference.kind) {
    case 'differs':
      return releaseWords.differs(difference.path);
    case 'not-served':
      return releaseWords.notServed(difference.path);
    case 'extra-script':
      return releaseWords.extraScript(difference.page, difference.script);
    case 'policy':
      return releaseWords.policyDiffers(difference.page);
    case 'policy-report-only':
      return releaseWords.policyReportOnly(difference.page);
    case 'compressed':
      return releaseWords.compressedDiffers(difference.path);
    case 'header':
      return releaseWords.headerDiffers(difference.header, difference.path);
    case 'anchor':
      return releaseWords.notProductionRecord;
  }
}

function parseReleases(text: string): ReleasesFile {
  const parsed = JSON.parse(text) as Partial<ReleasesFile>;
  if (
    parsed?.schema !== RELEASES_SCHEMA ||
    typeof parsed.historyUrl !== 'string' ||
    typeof parsed.latest?.commit !== 'string' ||
    typeof parsed.latest?.manifestSha256 !== 'string'
  ) {
    throw new Error('not a releases file');
  }
  return parsed as ReleasesFile;
}

function parseManifest(text: string): ReleaseManifest {
  const parsed = JSON.parse(text) as Partial<ReleaseManifest>;
  if (parsed?.format !== RELEASE_MANIFEST_FORMAT || !Array.isArray(parsed.files) || !Array.isArray(parsed.pages)) {
    throw new Error('not a release manifest');
  }
  for (const file of parsed.files) {
    if (typeof file?.path !== 'string' || !file.path.startsWith('/') || !HASH_RE.test(String(file.sha256))) {
      throw new Error('not a release manifest');
    }
    if (!file.headers || typeof file.headers !== 'object' || Object.values(file.headers).some((v) => typeof v !== 'string')) {
      throw new Error('not a release manifest');
    }
    if (file.gzip !== undefined && !HASH_RE.test(String(file.gzip?.sha256))) throw new Error('not a release manifest');
  }
  return parsed as ReleaseManifest;
}

/** The script sources a page loads, as paths on `origin` or as absolute URLs elsewhere. */
export function scriptSourcesOf(html: string, origin: string): string[] {
  const out = new Set<string>();
  const re = /<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  for (let match = re.exec(html); match; match = re.exec(html)) {
    const raw = (match[1] ?? match[2] ?? match[3] ?? '').replace(/&amp;/g, '&');
    if (!raw) continue;
    let url: URL;
    try {
      url = new URL(raw, `${origin}/`);
    } catch {
      out.add(raw);
      continue;
    }
    out.add(url.origin === origin ? url.pathname : url.href);
  }
  return [...out];
}

/**
 * Check that a key host serves exactly what its release record on the
 * ledger names: the history at the fixed path must be the pinned record, and
 * is checked against the ledger; the served manifest must be one of its
 * verified entries; every file is read three ways, as sent, and compared
 * with that manifest byte for byte, compressed copy and header set; and each
 * page's policies and loaded scripts are compared too. This proves what the
 * host served to this checker, not what it serves anyone else. Nothing is
 * sent to PacSpace beyond reading the host's own public files.
 */
export async function checkRelease(options: ReleaseOptions = {}): Promise<ReleaseReport> {
  const origin = new URL(options.origin ?? DEFAULT_RELEASE_ORIGIN).origin;
  if (options.releaseRecord && origin === DEFAULT_RELEASE_ORIGIN) throw new ReleaseUsageError('a staging release record with the production origin');
  const anchors = options.releaseRecord ? [options.releaseRecord] : (options.anchors ?? PRODUCTION_RELEASE_ANCHORS);
  const fetchImpl = options.fetchImpl ?? fetch;
  if (!options.rawGet) throw new ReleaseUsageError('checkRelease reads files as sent, so it needs rawGet');
  const rawGet = options.rawGet;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const report = await checkPinned(origin, anchors, fetchImpl, rawGet, timeoutMs, options.source);
  if (!options.releaseRecord) return report;
  const record = options.releaseRecord.recordKey;
  return {
    ...report,
    stagingRecord: record,
    sentences: [...report.sentences, releaseWords.stagingOnly(record)],
    exitCode: report.exitCode === 0 ? 1 : report.exitCode,
  };
}

async function checkPinned(
  origin: string,
  anchors: readonly ReleaseAnchor[],
  fetchImpl: typeof fetch,
  rawGet: RawGet,
  timeoutMs: number,
  source: CheckOptions['source'],
): Promise<ReleaseReport> {
  const raw = async (url: string, encoding: string): Promise<RawAnswer> => {
    let answer: RawAnswer;
    try {
      answer = await rawGet(url, encoding, timeoutMs);
    } catch {
      throw new Unreachable();
    }
    if (answer.status >= 500) throw new Unreachable();
    return answer;
  };

  const get = async (url: string): Promise<{ status: number; bytes: Uint8Array; headers: Headers }> => {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        redirect: 'manual',
        cache: 'no-store',
        headers: { 'accept-encoding': 'identity' },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      throw new Unreachable();
    }
    if (response.status >= 500) throw new Unreachable();
    return { status: response.status, bytes: new Uint8Array(await response.arrayBuffer()), headers: response.headers };
  };
  const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

  const base: Omit<ReleaseReport, 'outcome' | 'sentences' | 'exitCode'> = {
    origin,
    commit: null,
    entry: null,
    latestEntry: null,
    files: 0,
    differences: [],
  };
  const unreachable = (): ReleaseReport => ({
    ...base,
    outcome: 'unreachable',
    sentences: [releaseWords.unreachable(origin)],
    exitCode: 2,
  });
  const differs = (differences: ReleaseDifference[], extra: Partial<ReleaseReport> = {}): ReleaseReport => ({
    ...base,
    ...extra,
    outcome: 'differs',
    differences,
    sentences: [...differences.map(sentenceOf), releaseWords.total(differences.length)],
    exitCode: 1,
  });

  try {
    const releasesRead = await get(`${origin}${RELEASES_PATH}`);
    if (releasesRead.status !== 200) return differs([{ kind: 'not-served', path: RELEASES_PATH }]);
    let releases: ReleasesFile;
    try {
      releases = parseReleases(text(releasesRead.bytes));
    } catch {
      return differs([{ kind: 'differs', path: RELEASES_PATH }]);
    }

    const historyPath = HISTORY_PATH;
    const historyRead = await get(`${origin}${HISTORY_PATH}`);
    if (historyRead.status !== 200) return differs([{ kind: 'not-served', path: historyPath }]);
    let history;
    try {
      history = parseHistoryFile(text(historyRead.bytes));
    } catch {
      return differs([{ kind: 'differs', path: historyPath }]);
    }
    const named = history as { recordKey?: unknown; chain?: { chainId?: unknown; contractAddress?: unknown } };
    const pinned = { recordKey: named.recordKey, chainId: named.chain?.chainId, contractAddress: named.chain?.contractAddress };
    if (!anchors.some((anchor) => sameAnchor(anchor, pinned))) return differs([{ kind: 'anchor' }]);

    const manifestRead = await get(`${origin}${MANIFEST_PATH}`);
    if (manifestRead.status !== 200) return differs([{ kind: 'not-served', path: MANIFEST_PATH }]);
    let manifest: ReleaseManifest;
    try {
      manifest = parseManifest(text(manifestRead.bytes));
    } catch {
      return differs([{ kind: 'differs', path: MANIFEST_PATH }]);
    }
    base.commit = manifest.commit;

    let report;
    try {
      report = await checkHistory(history, {
        source: source ?? 'mirror',
        timeoutMs,
        fetchImpl,
        heldFile: { sha256: await sha256Hex(manifestRead.bytes), byteLength: String(manifestRead.bytes.length) },
      });
    } catch (error) {
      if (error instanceof HistoryFileError) return differs([{ kind: 'differs', path: historyPath }]);
      throw error;
    }
    if (report.exitCode === 3 || (report.source.compared === false && report.source.reason === 'unreachable')) {
      return unreachable();
    }
    if (!report.passed) return differs([{ kind: 'differs', path: historyPath }]);
    const latest = report.record.entries;
    base.latestEntry = latest;
    const matched = report.heldFile?.entries ?? [];
    if (latest === null || !matched.includes(latest)) {
      if (latest !== null && matched.includes(latest - 1)) {
        return {
          ...base,
          entry: latest - 1,
          outcome: 'in-progress',
          sentences: [releaseWords.inProgress(manifest.commit, releases.latest.commit)],
          exitCode: 1,
        };
      }
      return differs([{ kind: 'differs', path: MANIFEST_PATH }]);
    }
    base.entry = latest;

    const differences: ReleaseDifference[] = [];
    const known = new Set(manifest.files.map((file) => file.path));
    const pageFiles = new Set(manifest.pages.map((page) => page.file ?? page.path));
    for (const file of manifest.files) {
      let bytesDiffer = false;
      let compressedDiffers = false;
      let notServed = false;
      const headers = new Set<string>();
      for (const encoding of PROBE_ENCODINGS) {
        const read = await raw(`${origin}${file.path}`, encoding);
        if (read.status !== 200) {
          notServed = true;
          break;
        }
        const coding = (read.headers['content-encoding'] ?? '').trim().toLowerCase();
        if (coding === '' || coding === 'identity') {
          if ((await sha256Hex(read.body)) !== file.sha256) bytesDiffer = true;
        } else if (coding === 'gzip' && encoding !== 'identity' && file.gzip) {
          const unzipped = await gunzip(read.body);
          if ((await sha256Hex(read.body)) !== file.gzip.sha256 || !unzipped || (await sha256Hex(unzipped)) !== file.sha256) compressedDiffers = true;
        } else {
          compressedDiffers = true;
        }
        // A page's two policies are the page check's below.
        for (const [name, value] of Object.entries(file.headers)) {
          if (pageFiles.has(file.path) && name.startsWith('content-security-policy')) continue;
          if (read.headers[name] !== value) headers.add(name);
        }
      }
      if (notServed) differences.push({ kind: 'not-served', path: file.path });
      if (bytesDiffer) differences.push({ kind: 'differs', path: file.path });
      if (compressedDiffers) differences.push({ kind: 'compressed', path: file.path });
      for (const header of [...headers].sort()) differences.push({ kind: 'header', header, path: file.path });
    }
    for (const page of manifest.pages) {
      const read = await get(`${origin}${page.path}`);
      if (read.status !== 200) {
        if (!differences.some((d) => d.kind === 'not-served' && d.path === page.path)) {
          differences.push({ kind: 'not-served', path: page.path });
        }
        continue;
      }
      const served = read.headers.get('content-security-policy');
      const reported = read.headers.get('content-security-policy-report-only');
      if (served === null && reported !== null) differences.push({ kind: 'policy-report-only', page: page.path });
      else if (served !== page.policy) differences.push({ kind: 'policy', page: page.path });
      else if ((page.reportOnlyPolicy ?? null) !== reported) {
        differences.push({ kind: 'header', header: 'content-security-policy-report-only', path: page.path });
      }
      for (const script of scriptSourcesOf(text(read.bytes), origin)) {
        if (!known.has(script)) differences.push({ kind: 'extra-script', page: page.path, script });
      }
    }
    base.files = manifest.files.length;
    if (differences.length) return differs(differences);
    return {
      ...base,
      outcome: 'matches',
      sentences: [releaseWords.matches(manifest.commit, origin, manifest.files.length, latest)],
      exitCode: 0,
    };
  } catch (error) {
    if (error instanceof Unreachable) return unreachable();
    throw error;
  }
}

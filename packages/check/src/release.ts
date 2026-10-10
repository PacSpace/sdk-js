import { checkHistory, HistoryFileError, parseHistoryFile, type CheckOptions } from './check';

export const RELEASES_SCHEMA = 'pacspace-releases/v1';
export const RELEASE_MANIFEST_FORMAT = 'pacspace-release-manifest/v1';
export const RELEASES_PATH = '/.well-known/pacspace-releases.json';
export const MANIFEST_PATH = '/manifest.json';
export const DEFAULT_RELEASE_ORIGIN = 'https://records.pacspace.io';

/** The words `check release` prints (W-L2h-10 to W-L2h-17). */
export const releaseWords = {
  matches: (commit: string, origin: string, n: number, seq: number) =>
    `Release ${commit} on ${origin}: ${n} files match the release record on the ledger (entry ${seq}).`,
  differs: (path: string) => `${path} differs from the release record.`,
  notServed: (path: string) => `${path} is in the release record but the host doesn't serve it.`,
  extraScript: (page: string, script: string) => `${page} loads ${script}, which isn't in the release record.`,
  policyDiffers: (page: string) => `The policy on ${page} differs from the release record.`,
  inProgress: (served: string, latest: string) =>
    `The host serves ${served}; the release record's latest entry is ${latest}. A release may be in progress; run it again in a few minutes.`,
  unreachable: (origin: string) => `Couldn't reach ${origin} or the ledger. Nothing was checked.`,
  total: (n: number) => (n === 1 ? '1 difference from the release record.' : `${n} differences from the release record.`),
} as const;

export interface ReleaseManifestFile {
  path: string;
  sha256: string;
  bytes?: number;
}

export interface ReleaseManifestPage {
  path: string;
  file?: string;
  policy: string;
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
  | { kind: 'policy'; page: string };

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
  /** 0 everything matches; 1 any difference; 2 the host or the ledger could not be reached. */
  exitCode: 0 | 1 | 2;
}

export interface ReleaseOptions {
  origin?: string;
  source?: CheckOptions['source'];
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

class Unreachable extends Error {}

const HASH_RE = /^[0-9a-f]{64}$/;

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
 * ledger names: the history the host points to is checked against the
 * ledger, the served manifest must be one of its verified entries, and
 * every file, page policy and loaded script is compared with that manifest.
 * Nothing is sent to PacSpace beyond reading the host's own public files.
 */
export async function checkRelease(options: ReleaseOptions = {}): Promise<ReleaseReport> {
  const origin = new URL(options.origin ?? DEFAULT_RELEASE_ORIGIN).origin;
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;

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

    const historyUrl = new URL(releases.historyUrl, `${origin}/`);
    const historyPath = historyUrl.origin === origin ? historyUrl.pathname : historyUrl.href;
    const historyRead = await get(historyUrl.href);
    if (historyRead.status !== 200) return differs([{ kind: 'not-served', path: historyPath }]);
    let history;
    try {
      history = parseHistoryFile(text(historyRead.bytes));
    } catch {
      return differs([{ kind: 'differs', path: historyPath }]);
    }

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
        source: options.source ?? 'mirror',
        timeoutMs,
        fetchImpl: options.fetchImpl,
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
    for (const file of manifest.files) {
      const read = await get(`${origin}${file.path}`);
      if (read.status !== 200) differences.push({ kind: 'not-served', path: file.path });
      else if ((await sha256Hex(read.bytes)) !== file.sha256) differences.push({ kind: 'differs', path: file.path });
    }
    for (const page of manifest.pages) {
      const read = await get(`${origin}${page.path}`);
      if (read.status !== 200) {
        if (!differences.some((d) => d.kind === 'not-served' && d.path === page.path)) {
          differences.push({ kind: 'not-served', path: page.path });
        }
        continue;
      }
      const served = read.headers.get('content-security-policy') ?? read.headers.get('content-security-policy-report-only');
      if (served !== page.policy) differences.push({ kind: 'policy', page: page.path });
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

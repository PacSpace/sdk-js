import { createHash, createHmac } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import {
  BLINDING_FILE_MAX_BYTES,
  parseBlindingFile,
  RECORD_DISCLOSURE_MAX_BYTES_V1,
  RECORD_DISCLOSURE_SCHEMA_V1,
  RECORD_DISCLOSURE_SCHEMA_V2,
  RECORD_HISTORY_BUNDLE_SCHEMA_V3,
  RECORD_LINK_COPY_MAX_BYTES_V1,
  RECORD_LINK_COPY_SCHEMA_V1,
  RECORD_SEAL_HISTORY_SCHEMA_V1,
  type HeldFile,
} from '@pacspace/shared';
import {
  CHECKER_NAME,
  CHECKER_VERSION,
  checkHistory,
  DISCLOSURE_NEEDS_HISTORY_SENTENCE,
  DISCLOSURE_OFFLINE_SENTENCE,
  ENCRYPTED_NEEDS_KEY_SENTENCE,
  HistoryFileError,
  KEY_ONLY_FOR_ENCRYPTED_SENTENCE,
  needsLedgerRoots,
  NOT_A_HISTORY_SENTENCE,
  NOT_A_RECORD_KEY_SENTENCE,
  NOTHING_REVEALED_SENTENCE,
  parseHistoryFile,
  revealsFileFingerprint,
  type CheckOptions,
  type HistoryFile,
} from './check';
import { runOpen } from './open';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { checkRelease, DEFAULT_RELEASE_ORIGIN, releaseWords, type RawAnswer, type RawGet, type ReleaseAnchor } from './release';
import { renderReport, TOO_LARGE_SENTENCE } from './report';

export interface CliArgs {
  file: string | null;
  source: CheckOptions['source'];
  statementFingerprint: string | null;
  full: boolean;
  json: boolean;
  help: boolean;
  version: boolean;
  timeoutMs: number | undefined;
  heldFile: string | null;
  blinding: string | null;
  history: string | null;
  /** A path, or `-` for stdin; never the key itself. */
  key: string | null;
}

export const USAGE = `Usage: pacspace-check <history.json> [options]
       pacspace-check <history.json> --key <path>
       pacspace-check open [--link-file <path>] [--access-code-file <path>] [--copy <path>] [--html <path>] [--source <url> | --rpc <url>] [--timeout <ms>] [--json]
       pacspace-check release [--origin <url>] [--source <url> | --rpc <url>] [--timeout <ms>] [--json]
       pacspace-check release --origin <url> --release-record <record key>,<network id>,<contract>

Checks a PacSpace record history file: every entry against what was
committed, the file against its own fingerprint, and the record against
the proof layer. open reads the record from the link's host, and release reads the key pages from the host it checks. Checking a file sends nothing to PacSpace.

Options:
  --fingerprint <0x...>  the fingerprint printed on a statement; the checker
                         says whether it names this file
  --held-file <path>     check whether a verified entry names a file you hold
  --blinding <path>      the blinding file for the file you hold, when its entry is blinded
  --history <path>       the seal history or kept copy a disclosure is checked against
  --key <path>           the record key for an encrypted history, read from this file (- for stdin)
  --link-file <path>     open: read the link from this file instead of asking
  --access-code-file <path>  open: read the access code from this file instead of asking
  --copy <path>          open: save a kept copy of what the link shows to a new file
  --html <path>          open: save the report as a page that opens without a network connection
  --offline              check the file alone; do not read the proof layer
  --source <url>         read the proof layer from this mirror instead of
                         the one known for the record's network
  --rpc <url>            read the proof layer over JSON-RPC at this URL
  --full                 also read every daily statement
  --timeout <ms>         network timeout per read (default 10000)
  --json                 print the report as JSON
  --version              print the checker's version
  --help                 print this text

Exit codes: 0 the check passed as asked; 1 it did not, or the file you hold is not in it; 2 the history file, the link, a key, the file you hold, its blinding file or the arguments could not be used; 3 the proof layer or the link's host could not be reached. When more than one applies, 2 comes before 3, and 3 before 1.
`;

export const BLINDING_FILE_INVALID_SENTENCE = 'This is not a valid blinding file.';
export const BLINDING_NEEDS_HELD_FILE_SENTENCE = '--blinding needs --held-file.';
export const HISTORY_ONLY_FOR_DISCLOSURE_SENTENCE = '--history is used only with a disclosure file.';

export function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    file: null,
    source: 'mirror',
    statementFingerprint: null,
    full: false,
    json: false,
    help: false,
    version: false,
    timeoutMs: undefined,
    heldFile: null,
    blinding: null,
    history: null,
    key: null,
  };
  const takeValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`${flag} needs a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case '--help':
      case '-h':
        args.help = true;
        break;
      case '--version':
        args.version = true;
        break;
      case '--json':
        args.json = true;
        break;
      case '--offline':
        args.source = 'offline';
        break;
      case '--full':
        args.full = true;
        break;
      case '--fingerprint':
        args.statementFingerprint = takeValue(arg, index);
        index += 1;
        break;
      case '--held-file':
        args.heldFile = takeValue(arg, index);
        index += 1;
        break;
      case '--blinding':
        args.blinding = takeValue(arg, index);
        index += 1;
        break;
      case '--history':
        args.history = takeValue(arg, index);
        index += 1;
        break;
      case '--key':
        args.key = takeValue(arg, index);
        index += 1;
        break;
      case '--source':
        args.source = takeValue(arg, index);
        index += 1;
        break;
      case '--rpc':
        args.source = { rpc: takeValue(arg, index) };
        index += 1;
        break;
      case '--timeout': {
        const raw = takeValue(arg, index);
        const parsed = Number(raw);
        if (!Number.isFinite(parsed) || parsed <= 0) throw new UsageError('--timeout needs a number of milliseconds.');
        args.timeoutMs = parsed;
        index += 1;
        break;
      }
      default:
        if (arg.startsWith('--')) throw new UsageError(`Unknown option ${arg}.`);
        if (args.file) throw new UsageError('Pass one history file.');
        args.file = arg;
    }
  }
  if (args.blinding && !args.heldFile) throw new UsageError(BLINDING_NEEDS_HELD_FILE_SENTENCE);
  return args;
}

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  /** The file's bytes, at most `max` of them; one more than a bound tells a file over it. */
  readBytes: (path: string, max: number) => Promise<Uint8Array>;
  /** The file's bytes in chunks, read once. */
  openBytes: (path: string) => AsyncIterable<Uint8Array>;
  /**
   * One line from stdin, null at its end. On a terminal `prompt` is shown
   * first and `hidden` keeps the typing off the screen.
   */
  readLine?: (options: { prompt?: string; hidden?: boolean }) => Promise<string | null>;
  /** Writes a new file with `mode`; an existing path is refused (EEXIST). */
  writeNewFile?: (path: string, bytes: Uint8Array, mode: number) => Promise<void>;
  now?: () => Date;
  fetchImpl?: typeof fetch;
  /** `release` reads files as the host sent them; Node's https client unless given. */
  rawGet?: RawGet;
}

/** Node's https (or http, for a local host) with no decoding, so a compressed body is read as sent. */
/** No key-page file comes near this; a larger answer is not read to the end. */
export const RAW_BODY_LIMIT = 32 * 1024 * 1024;

export const nodeRawGet: RawGet = (url, acceptEncoding, timeoutMs) => {
  const target = new URL(url);
  const request = target.protocol === 'http:' ? httpRequest : httpsRequest;
  return new Promise<RawAnswer>((resolve, reject) => {
    const sent = request(
      target,
      { method: 'GET', headers: { 'accept-encoding': acceptEncoding, 'cache-control': 'no-cache' }, timeout: timeoutMs },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > RAW_BODY_LIMIT) {
            sent.destroy(new Error('too large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          clearTimeout(deadline);
          const headers: Record<string, string> = {};
          for (const [name, value] of Object.entries(response.headers)) {
            if (value !== undefined) headers[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
          }
          resolve({ status: response.statusCode ?? 0, headers, body: new Uint8Array(Buffer.concat(chunks)) });
        });
        response.on('error', reject);
      },
    );
    const deadline = setTimeout(() => sent.destroy(new Error('timeout')), timeoutMs);
    sent.on('timeout', () => sent.destroy(new Error('timeout')));
    sent.on('error', (error) => {
      clearTimeout(deadline);
      reject(error);
    });
    sent.end();
  });
};

export class ExitTwo extends Error {}

const RECORD_KEY_TEXT = /^[A-Za-z0-9_-]{43}$/;

/** The record key's 32 bytes from `--key`'s file or stdin: base64url text, surrounding whitespace ignored. */
async function readRecordKey(io: CliIo, from: string): Promise<Uint8Array> {
  let text: string | null;
  if (from === '-') {
    text = io.readLine ? await io.readLine({}) : null;
  } else {
    try {
      text = new TextDecoder().decode(await io.readBytes(resolve(from), 1024));
    } catch (error) {
      throw new ExitTwo(`The file could not be read: ${(error as Error).message}`);
    }
  }
  const trimmed = (text ?? '').trim();
  if (!RECORD_KEY_TEXT.test(trimmed)) throw new ExitTwo(NOT_A_RECORD_KEY_SENTENCE);
  const bytes = new Uint8Array(Buffer.from(trimmed, 'base64url'));
  if (bytes.length !== 32 || Buffer.from(bytes).toString('base64url') !== trimmed) throw new ExitTwo(NOT_A_RECORD_KEY_SENTENCE);
  return bytes;
}

/** A history file's bytes, refused above its bound before it is parsed. */
async function readHistoryFile(io: CliIo, path: string): Promise<{ file: HistoryFile; byteLength: number }> {
  let bytes: Uint8Array;
  try {
    bytes = await io.readBytes(resolve(path), RECORD_LINK_COPY_MAX_BYTES_V1 + 1);
  } catch (error) {
    throw new ExitTwo(`The file could not be read: ${(error as Error).message}`);
  }
  if (bytes.length > RECORD_LINK_COPY_MAX_BYTES_V1) throw new ExitTwo(TOO_LARGE_SENTENCE);
  const file = parseHistoryFile(new TextDecoder().decode(bytes));
  if ((file.schema === RECORD_DISCLOSURE_SCHEMA_V1 || file.schema === RECORD_DISCLOSURE_SCHEMA_V2) && bytes.length > RECORD_DISCLOSURE_MAX_BYTES_V1) {
    throw new ExitTwo(TOO_LARGE_SENTENCE);
  }
  return { file, byteLength: bytes.length };
}

/**
 * The held file's SHA-256, its length and, with a blinding file, its HMAC
 * under the blinding's value, from one pass over its bytes. Only digests
 * leave here; the value is zeroed once the pass ends.
 */
async function heldFileDigests(io: CliIo, heldPath: string, blindingPath: string | null): Promise<HeldFile> {
  let blinding: { value: Uint8Array; digest: string; byteLength: string } | null = null;
  if (blindingPath) {
    let raw: Uint8Array;
    try {
      raw = await io.readBytes(resolve(blindingPath), BLINDING_FILE_MAX_BYTES + 1);
    } catch (error) {
      throw new ExitTwo(`The file could not be read: ${(error as Error).message}`);
    }
    const parsed = parseBlindingFile(raw);
    raw.fill(0);
    if (!parsed.ok) throw new ExitTwo(BLINDING_FILE_INVALID_SENTENCE);
    blinding = parsed.blinding;
  }
  try {
    const sha = createHash('sha256');
    const mac = blinding ? createHmac('sha256', blinding.value) : null;
    let length = 0n;
    try {
      for await (const chunk of io.openBytes(resolve(heldPath))) {
        sha.update(chunk);
        mac?.update(chunk);
        length += BigInt(chunk.length);
      }
    } catch (error) {
      throw new ExitTwo(`The file could not be read: ${(error as Error).message}`);
    }
    const held: HeldFile = { sha256: sha.digest('hex'), byteLength: length.toString() };
    if (mac && blinding) {
      held.hmac = { digest: mac.digest('hex'), blindingDigest: blinding.digest, blindingByteLength: blinding.byteLength };
    }
    return held;
  } finally {
    blinding?.value.fill(0);
  }
}

export interface ReleaseArgs {
  origin: string | undefined;
  source: CheckOptions['source'];
  timeoutMs: number | undefined;
  json: boolean;
  releaseRecord: ReleaseAnchor | undefined;
}

/** `<record key>,<chain id>,<contract>`, or null. */
export function releaseRecordOf(value: string): ReleaseAnchor | null {
  const [recordKey, chainId, contractAddress, ...rest] = value.split(',').map((part) => part.trim());
  if (rest.length || !/^0x[0-9a-fA-F]{64}$/.test(recordKey ?? '') || !/^[1-9][0-9]*$/.test(chainId ?? '') || !/^0x[0-9a-fA-F]{40}$/.test(contractAddress ?? '')) {
    return null;
  }
  return { recordKey: recordKey.toLowerCase(), chainId: Number(chainId), contractAddress: contractAddress.toLowerCase() };
}

export function parseReleaseArgs(argv: string[]): ReleaseArgs {
  const args: ReleaseArgs = { origin: undefined, source: 'mirror', timeoutMs: undefined, json: false, releaseRecord: undefined };
  const takeValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`${flag} needs a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case '--origin':
        args.origin = takeValue(arg, index);
        index += 1;
        break;
      case '--source':
        args.source = takeValue(arg, index);
        index += 1;
        break;
      case '--rpc':
        args.source = { rpc: takeValue(arg, index) };
        index += 1;
        break;
      case '--timeout': {
        const parsed = Number(takeValue(arg, index));
        if (!Number.isFinite(parsed) || parsed <= 0) throw new UsageError('--timeout needs a number of milliseconds.');
        args.timeoutMs = parsed;
        index += 1;
        break;
      }
      case '--json':
        args.json = true;
        break;
      case '--release-record': {
        const record = releaseRecordOf(takeValue(arg, index));
        if (!record) throw new UsageError('--release-record needs a value.');
        args.releaseRecord = record;
        index += 1;
        break;
      }
      default:
        throw new UsageError(`Unknown option ${arg}.`);
    }
  }
  if (args.origin !== undefined) {
    try {
      new URL(args.origin);
    } catch {
      throw new UsageError('--origin needs a value.');
    }
  }
  return args;
}

async function runRelease(argv: string[], io: CliIo): Promise<number> {
  let args: ReleaseArgs;
  try {
    args = parseReleaseArgs(argv);
  } catch (error) {
    io.stderr(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (args.releaseRecord && new URL(args.origin ?? DEFAULT_RELEASE_ORIGIN).origin === DEFAULT_RELEASE_ORIGIN) {
    io.stderr(`${releaseWords.stagingOnly(args.releaseRecord.recordKey)}\n`);
    return 2;
  }
  const report = await checkRelease({
    origin: args.origin,
    source: args.source,
    timeoutMs: args.timeoutMs,
    fetchImpl: io.fetchImpl,
    rawGet: io.rawGet ?? nodeRawGet,
    releaseRecord: args.releaseRecord,
  });
  io.stdout(args.json ? `${JSON.stringify(report, null, 2)}\n` : `${report.sentences.join('\n')}\n`);
  return report.exitCode;
}

/** Run the checker; returns the exit code. Reads and writes only through `io`. */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  if (argv[0] === 'release') return runRelease(argv.slice(1), io);
  if (argv[0] === 'open') return runOpen(argv.slice(1), io);
  let args: CliArgs;
  try {
    args = parseArgs(argv);
  } catch (error) {
    io.stderr(`${(error as Error).message}\n\n${USAGE}`);
    return 2;
  }
  if (args.help) {
    io.stdout(USAGE);
    return 0;
  }
  if (args.version) {
    io.stdout(`${CHECKER_NAME} ${CHECKER_VERSION}\n`);
    return 0;
  }
  if (!args.file) {
    io.stderr(USAGE);
    return 2;
  }

  try {
    const { file } = await readHistoryFile(io, args.file);
    let history: HistoryFile | undefined;
    if (args.history) {
      if (file.schema !== RECORD_DISCLOSURE_SCHEMA_V1 && file.schema !== RECORD_DISCLOSURE_SCHEMA_V2) throw new ExitTwo(`${HISTORY_ONLY_FOR_DISCLOSURE_SENTENCE}\n\n${USAGE}`.trimEnd());
      history = (await readHistoryFile(io, args.history)).file;
      if (history.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1 && history.schema !== RECORD_LINK_COPY_SCHEMA_V1) {
        throw new ExitTwo(NOT_A_HISTORY_SENTENCE);
      }
    }
    if (args.source === 'offline' && needsLedgerRoots(file)) throw new ExitTwo(DISCLOSURE_OFFLINE_SENTENCE);
    if ((file.schema === RECORD_DISCLOSURE_SCHEMA_V1 || file.schema === RECORD_DISCLOSURE_SCHEMA_V2) && !history) throw new ExitTwo(DISCLOSURE_NEEDS_HISTORY_SENTENCE);
    if (args.key && file.schema !== RECORD_HISTORY_BUNDLE_SCHEMA_V3) throw new ExitTwo(KEY_ONLY_FOR_ENCRYPTED_SENTENCE);
    if (!args.key && file.schema === RECORD_HISTORY_BUNDLE_SCHEMA_V3) throw new ExitTwo(ENCRYPTED_NEEDS_KEY_SENTENCE);
    const recordKey = args.key ? await readRecordKey(io, args.key) : undefined;
    try {
      let heldFile: HeldFile | undefined;
      if (args.heldFile) {
        if (!revealsFileFingerprint(file)) throw new ExitTwo(NOTHING_REVEALED_SENTENCE);
        heldFile = await heldFileDigests(io, args.heldFile, args.blinding);
      }
      const report = await checkHistory(file, {
        source: args.source,
        statementFingerprint: args.statementFingerprint,
        full: args.full,
        timeoutMs: args.timeoutMs,
        fetchImpl: io.fetchImpl,
        history,
        heldFile,
        recordKey,
      });
      io.stdout(args.json ? `${JSON.stringify(report, null, 2)}\n` : renderReport(report));
      return report.exitCode;
    } finally {
      recordKey?.fill(0);
    }
  } catch (error) {
    if (error instanceof ExitTwo || error instanceof HistoryFileError) {
      io.stderr(`${error.message}\n`);
      return 2;
    }
    io.stderr(`The check could not run: ${(error as Error).message}\n`);
    return 2;
  }
}

/** At most `max` bytes of a file. */
async function readBounded(path: string, max: number): Promise<Uint8Array> {
  const handle = await open(path, 'r');
  try {
    const buffer = Buffer.alloc(max);
    let total = 0;
    while (total < max) {
      const { bytesRead } = await handle.read(buffer, total, max - total, null);
      if (bytesRead === 0) break;
      total += bytesRead;
    }
    return new Uint8Array(buffer.buffer, buffer.byteOffset, total);
  } finally {
    await handle.close();
  }
}

/* c8 ignore start */
/** One line typed on the terminal, echoed unless hidden; Ctrl-C ends the run, Ctrl-D ends the input. */
function readTerminalLine(hidden: boolean): Promise<string | null> {
  const stdin = process.stdin;
  return new Promise((resolveLine) => {
    let line = '';
    const finish = (value: string | null) => {
      stdin.off('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write('\n');
      resolveLine(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish(line);
        if (ch === '\u0003') {
          stdin.setRawMode(false);
          process.stderr.write('\n');
          process.exit(130);
        }
        if (ch === '\u0004') return finish(line.length > 0 ? line : null);
        if (ch === '\u007f' || ch === '\b') {
          if (line.length > 0) {
            line = line.slice(0, -1);
            if (!hidden) process.stderr.write('\b \b');
          }
          continue;
        }
        if (ch < ' ') continue;
        line += ch;
        if (!hidden) process.stderr.write(ch);
      }
    };
    stdin.setEncoding('utf8');
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

let pipedLines: AsyncIterator<string> | null = null;

async function readStdinLine(options: { prompt?: string; hidden?: boolean }): Promise<string | null> {
  if (process.stdin.isTTY) {
    if (options.prompt) process.stderr.write(`${options.prompt} `);
    return readTerminalLine(!!options.hidden);
  }
  pipedLines ??= createInterface({ input: process.stdin, terminal: false })[Symbol.asyncIterator]();
  const next = await pipedLines.next();
  return next.done ? null : next.value;
}

if (require.main === module) {
  runCli(process.argv.slice(2), {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
    readBytes: readBounded,
    openBytes: (path) => createReadStream(path),
    readLine: readStdinLine,
    writeNewFile: (path, bytes, mode) => writeFile(path, bytes, { flag: 'wx', mode }),
    now: () => new Date(),
  }).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`The check could not run: ${(error as Error).message}\n`);
      process.exitCode = 2;
    },
  );
}
/* c8 ignore stop */

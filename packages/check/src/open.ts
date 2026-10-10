import { resolve } from 'node:path';
import {
  buildRecordLinkCopyV1,
  decryptDisclosureV1,
  readDisclosureFragmentV1,
  RECORD_SEAL_HISTORY_SCHEMA_V1,
  type RecordDisclosureV1,
  type RecordSealHistoryV1,
} from '@pacspace/shared';
import { CHECKER_NAME, CHECKER_VERSION, checkHistory, HistoryFileError, parseHistoryFile, type CheckOptions, type RevealedEntry } from './check';
import type { CliIo } from './cli';
import { dayOfUtc, renderReport, type CheckReport } from './report';

/**
 * `pacspace-check open` (ADR 0015 section 8, layer 2; L2g design D2): reads
 * a Shared Record link the way the Shared Record does, opens its revealed
 * fields with the key after #, and checks the result as a kept copy. Every
 * request goes to the link's own origin, built from origin and path, so the
 * part after # never leaves this machine; no redirect is followed. The
 * access code goes only to the verify route; it, the key and the session
 * cookie are never printed or written.
 */

/** W-L2g-11 */
export const LINK_PROMPT = 'Paste the link, then press Enter:';
/** W-L2g-12 */
export const LINK_IN_ARGV_SENTENCE =
  'The link was given on the command line, where your shell history and other programs on this machine can see it. Next time, run open and paste the link when it asks.';
/** W-L2g-13 */
export const NOT_A_LINK_SENTENCE = 'This is not a PacSpace record link. A record link looks like https://<host>/c/<handle>/.';
/** W-L2g-14 */
export const ACCESS_CODE_PROMPT = 'This link asks for an access code. Type it, then press Enter:';
/** W-L2g-15 */
export const hostUnreachableSentence = (host: string) => `The link could not be read from ${host}. Check the connection and run it again.`;
/** W-L2g-16 */
export const NO_KEY_SENTENCE = 'This link reveals fields, but it has no key after #. Ask the sender for the whole link.';
/** W-L2g-17 */
export const KEY_DOES_NOT_OPEN_SENTENCE = "The revealed fields didn't open with this link's key. Ask the sender for the whole link.";
/** W-L2g-18 */
export const REVEALED_HEADER = 'Revealed fields';
/** W-L2g-20 */
export const savedCopySentence = (path: string) => `Saved a kept copy to ${path}. Check it again at any time with: npx @pacspace-io/check ${path}`;
/** W-L2g-21 */
export const pathExistsSentence = (path: string) => `${path} already exists. Choose another path.`;
/** W-L2g-22 */
export const savedReportSentence = (path: string) => `Saved the report to ${path}. It opens in a browser without a network connection.`;
/** The Shared Record's approved count line. */
const notShown = (k: number) => `${k} ${k === 1 ? 'field' : 'fields'} not shown.`;

const STEP_UP_REQUIRED = 'CUSTOMER_LINK_STEP_UP_REQUIRED';
const LINK_NOT_FOUND = 'CUSTOMER_LINK_NOT_FOUND';
const LINE_MAX_BYTES = 8192;

export interface OpenArgs {
  link: string | null;
  linkFile: string | null;
  accessCodeFile: string | null;
  copy: string | null;
  html: string | null;
  source: CheckOptions['source'];
  timeoutMs: number | undefined;
  json: boolean;
}

class OpenUsageError extends Error {}

/** Ends the run with this exit code, its sentence on stderr. */
class OpenStop extends Error {
  constructor(
    message: string,
    readonly exitCode: 2 | 3,
  ) {
    super(message);
  }
}

export function parseOpenArgs(argv: string[]): OpenArgs {
  const args: OpenArgs = { link: null, linkFile: null, accessCodeFile: null, copy: null, html: null, source: 'mirror', timeoutMs: undefined, json: false };
  const takeValue = (flag: string, index: number): string => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new OpenUsageError(`${flag} needs a value.`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    switch (arg) {
      case '--link-file':
        args.linkFile = takeValue(arg, index);
        index += 1;
        break;
      case '--access-code-file':
        args.accessCodeFile = takeValue(arg, index);
        index += 1;
        break;
      case '--copy':
        args.copy = takeValue(arg, index);
        index += 1;
        break;
      case '--html':
        args.html = takeValue(arg, index);
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
        if (!Number.isFinite(parsed) || parsed <= 0) throw new OpenUsageError('--timeout needs a number of milliseconds.');
        args.timeoutMs = parsed;
        index += 1;
        break;
      }
      case '--json':
        args.json = true;
        break;
      default:
        if (arg.startsWith('--')) throw new OpenUsageError(`Unknown option ${arg}.`);
        if (args.link !== null) throw new OpenUsageError('Pass one link.');
        args.link = arg;
    }
  }
  return args;
}

/** The first line of a small file. */
async function firstLineOf(io: CliIo, path: string): Promise<string> {
  let bytes: Uint8Array;
  try {
    bytes = await io.readBytes(resolve(path), LINE_MAX_BYTES);
  } catch (error) {
    throw new OpenStop(`The file could not be read: ${(error as Error).message}`, 2);
  }
  return new TextDecoder().decode(bytes).split(/\r?\n/)[0] ?? '';
}

/** The link's origin, its handle as the disclosure is bound to it, and the key after #. */
function readLink(text: string | null): { origin: string; host: string; handle: string; key: Uint8Array | null } {
  let url: URL;
  try {
    url = new URL((text ?? '').trim());
  } catch {
    throw new OpenStop(NOT_A_LINK_SENTENCE, 2);
  }
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (!(url.protocol === 'https:' || (url.protocol === 'http:' && local)) || url.username || url.password) {
    throw new OpenStop(NOT_A_LINK_SENTENCE, 2);
  }
  const match = /^\/c\/([^/]+)(?:\/.*)?$/.exec(url.pathname);
  if (!match) throw new OpenStop(NOT_A_LINK_SENTENCE, 2);
  let handle = match[1];
  try {
    handle = decodeURIComponent(handle);
  } catch {
    // the handle as written
  }
  handle = handle.trim().toLowerCase();
  if (!handle) throw new OpenStop(NOT_A_LINK_SENTENCE, 2);
  return { origin: url.origin, host: url.host, handle, key: readDisclosureFragmentV1(url.hash) };
}

const withoutControls = (text: string) =>
  Array.from(text)
    .filter((ch) => ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) !== 0x7f)
    .join('');

/** A refusal's own sentence and code, as the link host serves it; control characters dropped. */
async function refusalOf(response: Response): Promise<{ code: string | null; message: string | null }> {
  try {
    const body = (await response.json()) as { code?: unknown; message?: unknown; error?: { code?: unknown; message?: unknown } } | null;
    const code = body?.error?.code ?? body?.code;
    const message = body?.error?.message ?? body?.message;
    return {
      code: typeof code === 'string' ? code : null,
      message: typeof message === 'string' ? withoutControls(message).trim() || null : null,
    };
  } catch {
    return { code: null, message: null };
  }
}

/** The revealed fields as the terminal shows them: each value as JSON, so no control character reaches the screen. */
export function renderRevealed(entries: RevealedEntry[]): string {
  const lines = [REVEALED_HEADER];
  for (const entry of entries) {
    lines.push(`Entry ${entry.entry}`);
    for (const field of entry.fields) lines.push(`  ${field.pointer}: ${JSON.stringify(field.value)}`);
    if (entry.withheld > 0) lines.push(`  ${notShown(entry.withheld)}`);
  }
  return `${lines.join('\n')}\n`;
}

const escapeHtml = (text: string) =>
  text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

/** The report as one page with no script and no network (W-L2g-23): the facts, the sentences and the revealed fields. */
export function renderOpenHtml(input: { report: CheckReport; revealed: RevealedEntry[]; version: string; now: Date }): string {
  const { report, revealed } = input;
  const facts: Array<[string, string]> = [
    ['Reference', report.record.reference],
    ['Fingerprint of this history', report.file.fingerprint ?? 'none'],
  ];
  if (report.source.compared) facts.push(['Public source', report.source.readsFrom]);
  const body: string[] = [
    '<h1>PacSpace record check</h1>',
    '<table>',
    ...facts.map(([label, value]) => `<tr><th>${escapeHtml(label)}</th><td>${escapeHtml(value)}</td></tr>`),
    '</table>',
    ...report.sentences.map((sentence) => `<p>${escapeHtml(sentence)}</p>`),
  ];
  if (revealed.length > 0) {
    body.push(`<h2>${REVEALED_HEADER}</h2>`);
    for (const entry of revealed) {
      body.push(`<h3>Entry ${entry.entry}</h3>`, '<table>');
      for (const field of entry.fields) {
        body.push(`<tr><th>${escapeHtml(field.pointer)}</th><td>${escapeHtml(JSON.stringify(field.value))}</td></tr>`);
      }
      body.push('</table>');
      if (entry.withheld > 0) body.push(`<p>${escapeHtml(notShown(entry.withheld))}</p>`);
    }
  }
  body.push(`<footer>Made by ${CHECKER_NAME} ${escapeHtml(input.version)} on ${dayOfUtc(input.now.toISOString())} (UTC).</footer>`);
  return [
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`,
    '<meta name="referrer" content="no-referrer">',
    '<title>PacSpace record check</title>',
    '<style>body{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}th{text-align:left;padding-right:1rem;vertical-align:top;font-weight:600}td{word-break:break-all}footer{margin-top:2rem;color:#555}</style>',
    '</head>',
    '<body>',
    ...body,
    '</body>',
    '</html>',
    '',
  ].join('\n');
}

async function writeNew(io: CliIo, path: string, bytes: Uint8Array): Promise<void> {
  if (!io.writeNewFile) throw new OpenStop(`The file could not be written: ${path}`, 2);
  try {
    await io.writeNewFile(resolve(path), bytes, 0o600);
  } catch (error) {
    if ((error as { code?: unknown }).code === 'EEXIST') throw new OpenStop(pathExistsSentence(path), 2);
    throw new OpenStop(`The file could not be written: ${(error as Error).message}`, 2);
  }
}

export async function runOpen(argv: string[], io: CliIo): Promise<number> {
  let args: OpenArgs;
  try {
    args = parseOpenArgs(argv);
  } catch (error) {
    io.stderr(`${(error as Error).message}\n`);
    return 2;
  }
  let cookie: string | null = null;
  try {
    let linkText: string | null;
    if (args.link !== null) {
      io.stderr(`${LINK_IN_ARGV_SENTENCE}\n`);
      linkText = args.link;
    } else if (args.linkFile) {
      linkText = await firstLineOf(io, args.linkFile);
    } else {
      linkText = io.readLine ? await io.readLine({ prompt: LINK_PROMPT }) : null;
    }
    const link = readLink(linkText);
    const fetchImpl = io.fetchImpl ?? fetch;
    const timeoutMs = args.timeoutMs ?? 10_000;
    const base = `${link.origin}/api/v1/c/${encodeURIComponent(link.handle)}`;
    const request = async (tail: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
      const headers: Record<string, string> = { Accept: 'application/json', ...(init.headers ?? {}) };
      if (cookie) headers.Cookie = cookie;
      try {
        return await fetchImpl(`${base}${tail}`, { method: init.method ?? 'GET', headers, body: init.body, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
      } catch {
        throw new OpenStop(hostUnreachableSentence(link.host), 3);
      }
    };
    const stopWith = async (response: Response): Promise<never> => {
      const refusal = await refusalOf(response);
      if (refusal.message) throw new OpenStop(refusal.message, 2);
      throw new OpenStop(hostUnreachableSentence(link.host), 3);
    };

    let history = await request('/history', { headers: { 'X-Record-Entries': 'all' } });
    if (history.status === 401) {
      const refusal = await refusalOf(history.clone());
      if (refusal.code === STEP_UP_REQUIRED) {
        const code = args.accessCodeFile
          ? await firstLineOf(io, args.accessCodeFile)
          : io.readLine
            ? await io.readLine({ prompt: ACCESS_CODE_PROMPT, hidden: true })
            : null;
        if (!code || !code.trim()) throw new OpenStop(refusal.message ?? hostUnreachableSentence(link.host), 2);
        const verified = await request('/access/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ factor: 'ACCESS_HINT', value: code.trim() }),
        });
        if (!verified.ok) await stopWith(verified);
        const setCookie = verified.headers.getSetCookie?.()[0] ?? verified.headers.get('set-cookie') ?? '';
        cookie = setCookie.split(';')[0].trim() || null;
        history = await request('/history', { headers: { 'X-Record-Entries': 'all' } });
      }
    }
    if (!history.ok) await stopWith(history);
    let sealHistory: RecordSealHistoryV1;
    try {
      sealHistory = (await history.json()) as RecordSealHistoryV1;
    } catch {
      throw new OpenStop(NOT_A_LINK_SENTENCE, 2);
    }
    if (!sealHistory || sealHistory.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1) throw new OpenStop(NOT_A_LINK_SENTENCE, 2);

    let disclosure: RecordDisclosureV1 | null = null;
    const answer = await request('/disclosure');
    if (answer.ok) {
      const envelope = ((await answer.json().catch(() => null)) as { envelope?: unknown } | null)?.envelope;
      if (typeof envelope === 'string') {
        if (!link.key) throw new OpenStop(NO_KEY_SENTENCE, 2);
        const opened = await decryptDisclosureV1({ envelope, key: link.key, handle: link.handle });
        if (!opened.ok) throw new OpenStop(KEY_DOES_NOT_OPEN_SENTENCE, 2);
        disclosure = opened.disclosure as RecordDisclosureV1;
      }
    } else if (answer.status !== 404 || (await refusalOf(answer.clone())).code !== LINK_NOT_FOUND) {
      await stopWith(answer);
    }
    link.key?.fill(0);

    let copy: Awaited<ReturnType<typeof buildRecordLinkCopyV1>>;
    try {
      copy = await buildRecordLinkCopyV1({ sealHistory, disclosure });
    } catch {
      throw new OpenStop(KEY_DOES_NOT_OPEN_SENTENCE, 2);
    }
    let revealed: RevealedEntry[] = [];
    const report = await checkHistory(parseHistoryFile(new TextDecoder().decode(copy.bytes)), {
      source: args.source,
      timeoutMs: args.timeoutMs,
      fetchImpl: io.fetchImpl,
      onRevealed: (entries) => {
        revealed = entries;
      },
    });

    if (args.json) {
      io.stdout(`${JSON.stringify({ ...report, revealedFields: revealed }, null, 2)}\n`);
    } else {
      io.stdout(renderReport(report));
      if (revealed.length > 0) io.stdout(`\n${renderRevealed(revealed)}`);
    }
    if (args.copy) {
      await writeNew(io, args.copy, copy.bytes);
      io.stderr(`${savedCopySentence(args.copy)}\n`);
    }
    if (args.html) {
      const page = renderOpenHtml({ report, revealed, version: CHECKER_VERSION, now: io.now ? io.now() : new Date() });
      await writeNew(io, args.html, new TextEncoder().encode(page));
      io.stderr(`${savedReportSentence(args.html)}\n`);
    }
    return report.exitCode;
  } catch (error) {
    if (error instanceof OpenStop) {
      io.stderr(`${error.message}\n`);
      return error.exitCode;
    }
    if (error instanceof HistoryFileError) {
      io.stderr(`${error.message}\n`);
      return 2;
    }
    io.stderr(`The check could not run: ${(error as Error).message}\n`);
    return 2;
  } finally {
    cookie = null;
  }
}

import {
  SHARED_RECORD_EVIDENCE_SCHEMA_V1,
  acknowledgmentKeyIdV2,
  deviceCodeV1,
  deviceIdV1,
  isSealedFlagNoteV2,
  payloadDigestV1,
  readSharedRecordAckV2,
  sharedRecordAckDisclosureDigestV2,
  sharedRecordAckMessageV2,
  sharedRecordAckSealHistoryDigestV2,
  sharedRecordEvidenceSigningMessageV1,
  sharedRecordEvidenceV1KeyProblems,
  type EvidenceRecordV1,
  type EvidenceSystemRecordV1,
  type RecordDisclosure,
  type RecordSealHistoryV1,
  type SharedRecordAckBodyV2,
  type SharedRecordEvidenceV1,
} from '@pacspace/shared';
import { isDeepStrictEqual } from './equal';
import { loadDeviceSignature } from './device-signature';
import { CHECKER_NAME, CHECKER_VERSION, checkCommittedEntries, checkHistory, type CheckOptions, type RevealedEntry } from '../check';
import { EVIDENCE_WORDS as W } from './words';

export const EVIDENCE_REPORT_SCHEMA = 'pacspace-check-evidence-report/v1' as const;

/** One check of the file: `passed` is null for a line that reports what was not checked, never a failure. */
export interface EvidenceLine {
  check: string;
  passed: boolean | null;
  sentence: string;
}

export interface EvidenceReport {
  schema: typeof EVIDENCE_REPORT_SCHEMA;
  checker: { name: string; version: string };
  ref: string | null;
  edition: string | null;
  lines: EvidenceLine[];
  /** 0 every check passed; 1 one did not; 2 the file could not be used; 3 the proof layer could not be reached (before 1, as the checker's other commands). */
  exitCode: 0 | 1 | 2 | 3;
}

export type EvidenceOptions = Pick<CheckOptions, 'source' | 'timeoutMs' | 'fetchImpl'>;

/** A file that is not an evidence record this version reads: the report says so, and nothing else runs. */
export class EvidenceFileError extends Error {}

/** base64url to bytes, or null when it is not base64url; no Node built-in, so the library form can run anywhere. */
function fromBase64Url(text: unknown): Uint8Array | null {
  if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '='));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

const groupedCode = (code: string) => code.replace(/ /g, '').match(/.{5}/g)?.join(' ') ?? code;
const hex = (v: unknown) => (typeof v === 'string' ? v.toLowerCase() : '');

/**
 * The file's parsed JSON as an evidence record: its schema, kind, version and every key in place for its edition. A
 * file for reviewers that carries what that version leaves out (a revealed field, a reply, an agent line, a decline's
 * note) is not one.
 */
export function readEvidenceFile(value: unknown): SharedRecordEvidenceV1 {
  const v = value as Partial<SharedRecordEvidenceV1> | null;
  if (!v || typeof v !== 'object' || v.schema !== SHARED_RECORD_EVIDENCE_SCHEMA_V1 || v.kind !== 'pacspace-evidence-record' || v.version !== 1) {
    throw new EvidenceFileError(W.notEvidence);
  }
  if (sharedRecordEvidenceV1KeyProblems(v).length) throw new EvidenceFileError(W.notEvidence);
  if (!Array.isArray(v.records) || v.records.some((r) => !r || typeof r.sealHistory !== 'object' || r.sealHistory === null)) throw new EvidenceFileError(W.notEvidence);
  return v as SharedRecordEvidenceV1;
}

/**
 * `pacspace-check evidence <file>` (R7; D-42, its `evidence`): the file's schema and both of the signing device's
 * signatures; every record's seals against the proof layer, through the reads the checker already makes; that the
 * records are numbered 1 to n with none missing; each record's close against its own last seal and, when the file holds
 * the index record, against what the index record committed for its join; in Full, every revealed and answered field
 * against its entry's seal; each acknowledgment the file holds signed by a confirmed device, the latest check's naming
 * exactly the file's seal histories and, in Full, its disclosures; and, when the file holds
 * the link's own record, each acknowledgment against what it committed. A For reviewers file passes every check that
 * needs no field. It makes no request to PacSpace: the proof layer only.
 */
export async function checkEvidence(file: SharedRecordEvidenceV1, options: EvidenceOptions = {}): Promise<EvidenceReport> {
  const lines: EvidenceLine[] = [];
  const add = (check: string, passed: boolean | null, sentence: string) => lines.push({ check, passed, sentence });
  let unreachable = false;
  const full = file.edition === 'full';
  add('edition', null, W.edition(file.edition));

  await signature(file, add);

  const numbers = file.records.map((r) => r.record).sort((a, b) => a - b);
  const missing: number[] = [];
  for (let n = 1; n <= (numbers[numbers.length - 1] ?? 0); n += 1) if (!numbers.includes(n)) missing.push(n);
  if (missing.length || new Set(numbers).size !== numbers.length) add('numbering', false, W.numberMissing(missing.length ? missing : [numbers[0]]));
  else add('numbering', true, W.numbered(numbers.length));

  const closeFailed: number[] = [];
  for (const record of file.records) {
    const report = await checkHistory(record.sealHistory as never, options);
    if (report.exitCode === 3) unreachable = true;
    const sealsAgree = record.seals.length === record.entries && record.sealHistory.entries.length === record.entries && record.seals.every((s, i) => hex(s) === hex(record.sealHistory.entries[i]?.seal));
    if (options.source === 'offline') add(`record ${record.record}`, report.passed && sealsAgree ? null : false, report.passed && sealsAgree ? W.recordOffline(record.record) : W.recordDiffers(record.record));
    else if (report.exitCode !== 3) add(`record ${record.record}`, report.passed && sealsAgree, report.passed && sealsAgree ? W.recordMatches(record.record, record.entries) : W.recordDiffers(record.record));
    const last = record.sealHistory.entries[record.sealHistory.entries.length - 1];
    if (!last || last.seq !== record.close.lastSeq || hex(last.seal) !== hex(record.close.lastSeal) || record.close.lastSeq + 1 !== record.entries) closeFailed.push(record.record);
  }
  if (closeFailed.length) for (const n of closeFailed) add('close', false, W.closeDiffers(n));
  else add('close', true, W.closeMatches(file.records.length));

  if (full) unreachable = (await revealedAndAnswered(file, options, add)) || unreachable;
  else answeredSeals(file, add);

  const held = await acknowledgments(file, add);

  unreachable = (await indexRecord(file, options, add)) || unreachable;
  unreachable = (await readerRecord(file, held, options, add)) || unreachable;

  if (unreachable) add('proof layer', null, W.unreachable);
  add('boundary', null, W.boundary);
  const failed = lines.some((l) => l.passed === false);
  return {
    schema: EVIDENCE_REPORT_SCHEMA,
    checker: { name: CHECKER_NAME, version: CHECKER_VERSION },
    ref: file.ref,
    edition: file.edition,
    lines,
    exitCode: unreachable ? 3 : failed ? 1 : 0,
  };
}

type Add = (check: string, passed: boolean | null, sentence: string) => void;

/** The signing device's three keys give its id and code; both signatures over the rest of the file; and that code a confirmed device's. */
async function signature(file: SharedRecordEvidenceV1, add: Add): Promise<void> {
  const s = file.signature;
  if (!s) return add('signature', false, W.notSigned);
  const xwing = fromBase64Url(s.device.xwingPublicKey);
  const mldsa = fromBase64Url(s.device.mldsaPublicKey);
  let code: string | null = null;
  try {
    if (xwing && mldsa) code = groupedCode(deviceCodeV1(await deviceIdV1({ xwingPublicKey: xwing, p256Jwk: s.device.p256Jwk, mldsaPublicKey: mldsa })));
  } catch {
    code = null;
  }
  const { verifyDeviceMessageV1 } = await loadDeviceSignature();
  const ok = !!mldsa && code !== null && (await verifyDeviceMessageV1({ p256Jwk: s.device.p256Jwk, mldsaPublicKey: mldsa, message: sharedRecordEvidenceSigningMessageV1(file), signature: s.signature, mldsaSignature: s.mldsaSignature }));
  if (!ok || code === null) return add('signature', false, W.signatureDiffers);
  const confirmed = file.devices.some((d) => d.status === 'confirmed' && groupedCode(d.code) === code);
  add('signature', confirmed, confirmed ? W.signed(code) : W.signerNotOnLink(code));
}

/** Full: each record's revealed fields and each answer's shown fields, from their disclosures, against the entries' seals. */
async function revealedAndAnswered(file: SharedRecordEvidenceV1, options: EvidenceOptions, add: Add): Promise<boolean> {
  const byNumber = new Map(file.records.map((r) => [r.record, r]));
  const unprovenRecords = new Set(file.records.filter((r) => r.disclosure === undefined && (r.revealed?.length ?? 0) > 0).map((r) => r.record));
  const unprovenAnswers = new Set(file.answers.filter((a) => a.entries.some((e) => 'fields' in e && e.fields !== undefined && e.disclosure === undefined)).map((a) => a.request));
  for (const record of unprovenRecords) add(`revealed ${record}`, false, W.revealedDiffer(record));
  for (const request of unprovenAnswers) add(`answer ${request}`, false, W.answerDiffers(request));
  const anyDisclosure = file.records.some((r) => r.disclosure !== undefined) || file.answers.some((a) => a.entries.some((e) => 'disclosure' in e && e.disclosure !== undefined));
  if (!anyDisclosure) return false;
  if (options.source === 'offline') {
    add('fields', null, W.notCheckedOffline);
    return false;
  }
  let unreachable = false;
  const open = async (record: EvidenceRecordV1, disclosure: unknown) => {
    const revealed: RevealedEntry[] = [];
    const report = await checkHistory(disclosure as never, { ...options, history: record.sealHistory as never, onRevealed: (entries) => revealed.push(...entries) });
    if (report.exitCode === 3) unreachable = true;
    return { passed: report.passed, unreachable: report.exitCode === 3, revealed };
  };
  for (const record of file.records) {
    if (record.disclosure === undefined) continue;
    const opened = await open(record, record.disclosure);
    if (opened.unreachable) continue;
    const listed = record.revealed ?? [];
    const agree = listed.every((x) => {
      const found = opened.revealed.find((e) => e.entry === x.entry);
      const seal = record.sealHistory.entries.find((e) => e.seq === x.entry - 1)?.seal;
      return !!found && sameFields(x.fields, found.fields) && hex(x.committed) === hex(seal) && (x.recomputed === null || hex(x.recomputed) === hex(seal));
    });
    add(`revealed ${record.record}`, opened.passed && agree, opened.passed && agree ? W.revealedMatch(record.record, listed.length || opened.revealed.length) : W.revealedDiffer(record.record));
  }
  for (const answer of file.answers) {
    if (unprovenAnswers.has(answer.request)) continue;
    let shown = 0;
    let ok = true;
    let notReached = false;
    for (const entry of answer.entries) {
      if (!('seal' in entry)) continue;
      shown += 1;
      const record = byNumber.get(entry.record);
      const seal = record?.sealHistory.entries.find((e) => e.seq === entry.entry - 1)?.seal;
      if (!record || hex(entry.committed) !== hex(seal) || hex(entry.seal) !== hex(seal)) {
        ok = false;
        continue;
      }
      if (entry.disclosure === undefined) {
        // With nothing to open, a field listed cannot be checked, and the entry stands on its own seals.
        if (entry.fields !== undefined || entry.matchesSeal !== true || (entry.recomputed !== null && hex(entry.recomputed) !== hex(seal))) ok = false;
        continue;
      }
      const opened = await open(record, entry.disclosure);
      if (opened.unreachable) {
        notReached = true;
        continue;
      }
      const found = opened.revealed.find((e) => e.entry === entry.entry);
      if (!opened.passed || !found || (entry.fields !== undefined && !sameFields(entry.fields, found.fields)) || entry.matchesSeal !== true) ok = false;
    }
    // An entry whose disclosure the proof layer did not answer is unchecked: the answer claims no match for it.
    if (shown && !(ok && notReached)) add(`answer ${answer.request}`, ok, ok ? W.answerMatches(answer.request, shown) : W.answerDiffers(answer.request));
  }
  return unreachable;
}

/** For reviewers: each answered entry carries the seal its record committed for it. */
function answeredSeals(file: SharedRecordEvidenceV1, add: Add): void {
  const byNumber = new Map(file.records.map((r) => [r.record, r]));
  let n = 0;
  for (const answer of file.answers) {
    for (const entry of answer.entries) {
      if (!('seal' in entry)) continue;
      n += 1;
      const seal = byNumber.get(entry.record)?.sealHistory.entries.find((e) => e.seq === entry.entry - 1)?.seal;
      if (hex(entry.seal) !== hex(seal) || hex(entry.committed) !== hex(seal)) return add('answers', false, W.answerSealsDiffer(answer.request));
    }
  }
  if (n) add('answers', true, W.answerSeals(n));
}

/** Each acknowledgment the file holds whole: its body, for this link, signed with both halves of a confirmed device's v2 pair. */
async function acknowledgments(file: SharedRecordEvidenceV1, add: Add): Promise<Map<string, unknown>> {
  const held = new Map<string, unknown>();
  const notHeld: string[] = [];
  const latest = [...file.checks].sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0)).pop()?.ref;
  for (const ack of file.acknowledgments) {
    if (!ack.signed) {
      notHeld.push(ack.ref);
      continue;
    }
    const read = readSharedRecordAckV2(ack.signed.body);
    const mldsa = fromBase64Url(ack.signed.mldsaPublicKey);
    let ok = read.ok && !!mldsa && read.body.reference === file.ref && read.body.check.ref === ack.check;
    if (ok && read.ok && mldsa) {
      const { verifyDeviceMessageV1 } = await loadDeviceSignature();
      const keyId = await acknowledgmentKeyIdV2(ack.signed.p256Jwk, mldsa);
      const code = groupedCode(deviceCodeV1(read.body.deviceId));
      ok =
        keyId === read.body.keyId &&
        file.devices.some((d) => groupedCode(d.code) === code && (d.status === 'confirmed' || d.status === 'revoked')) &&
        (await verifyDeviceMessageV1({ p256Jwk: ack.signed.p256Jwk, mldsaPublicKey: mldsa, message: sharedRecordAckMessageV2(read.body), signature: ack.signed.signature, mldsaSignature: ack.signed.mldsaSignature })) &&
        noteAgrees(ack, read.body.note) &&
        flagsAgree(ack.flags, read.body);
    }
    const namesOther = ok && read.ok && ack.check === latest && !(await namesThisFile(file, read.body));
    if (ok && read.ok && !namesOther) held.set(ack.ref, read.body);
    add(`acknowledgment ${ack.ref}`, ok && !namesOther, namesOther ? W.ackNamesOther(ack.ref) : ok ? W.ackSigned(ack.ref) : W.ackDiffers(ack.ref));
  }
  if (notHeld.length) add('acknowledgments', null, W.ackNotHeld(notHeld));
  return held;
}

/**
 * The acknowledgment of the file's latest check, the check the file was made from, names exactly what the file holds:
 * every record's seal history and, in Full, every disclosure the file opened. A file for reviewers holds no disclosure,
 * so only its histories are matched. An earlier check's acknowledgment named the histories as they were then, and is
 * held to what the link's reader record committed instead.
 */
async function namesThisFile(file: SharedRecordEvidenceV1, body: SharedRecordAckBodyV2): Promise<boolean> {
  const bare = (v: string | null) => (v === null ? null : v.toLowerCase().replace(/^0x/, ''));
  try {
    if (bare(body.sealHistoryDigest) !== bare(sharedRecordAckSealHistoryDigestV2(file.records))) return false;
    if (file.edition !== 'full') return true;
    const opened = [
      ...file.records.filter((r) => r.disclosure !== undefined).map((r) => ({ request: null, record: r.record, disclosure: r.disclosure as RecordDisclosure })),
      ...file.answers.flatMap((a) =>
        a.entries.flatMap((e) => ('disclosure' in e && e.disclosure !== undefined ? [{ request: a.request, record: e.record, disclosure: e.disclosure as RecordDisclosure }] : [])),
      ),
    ];
    return bare(body.disclosureDigest) === bare(await sharedRecordAckDisclosureDigestV2(opened));
  } catch {
    return false;
  }
}

/** A listed note against the signed one: a sealed note as `noteSealed` with the reader's words or null, a plain one word for word. */
function noteAgrees(listed: { note: string | null; noteSealed?: true }, signed: SharedRecordAckBodyV2['note']): boolean {
  if (isSealedFlagNoteV2(signed)) return listed.noteSealed === true && (listed.note === null || typeof listed.note === 'string');
  return listed.noteSealed === undefined && listed.note === signed;
}

/** The Shared Record page's words for a flagged entry's result (list C); an export copy's result has none yet (EX1). */
const FLAG_RESULT_WORDS: Readonly<Record<string, string>> = { matches: 'Matches its seal', 'does-not-match': 'Does not match its seal' };

/**
 * The file lists exactly the flags its signed body carries: each result in the page's words (an export copy's result
 * claims neither), a plain note word for word, and a sealed note as `noteSealed`, whose words the file states as the
 * reader's browser opened them (the checker holds no key to them).
 */
function flagsAgree(listed: SharedRecordEvidenceV1['acknowledgments'][number]['flags'], body: SharedRecordAckBodyV2): boolean {
  const byEntry = new Map(listed.map((f) => [`${f.record}:${f.entry}`, f]));
  if (byEntry.size !== listed.length || listed.length !== body.flags.length) return false;
  return body.flags.every((f) => {
    const l = byEntry.get(`${f.record}:${f.entry}`);
    if (!l) return false;
    const words = FLAG_RESULT_WORDS[f.result];
    if (words ? l.result !== words : Object.values(FLAG_RESULT_WORDS).includes(l.result)) return false;
    return noteAgrees(l, f.note);
  });
}

/** A PacSpace-written record's entries as the file's disclosure shows them, each checked to be committed: by entry title. */
async function systemEntries(which: 'index' | 'reader', system: EvidenceSystemRecordV1, options: EvidenceOptions, add: Add): Promise<{ unreachable: boolean; byTitle: Map<string, Record<string, unknown>> | null }> {
  const outcome = await checkCommittedEntries(system.sealHistory as RecordSealHistoryV1, system.disclosure as RecordDisclosure, options);
  if (outcome.unreachable) return { unreachable: true, byTitle: null };
  if (!outcome.formOk || outcome.rootsOk === false || (outcome.disclosure && outcome.disclosure.kind !== 'verified')) {
    add(which, false, W.systemDiffers(which));
    return { unreachable: false, byTitle: null };
  }
  const byTitle = new Map<string, Record<string, unknown>>();
  for (const entry of outcome.revealed) {
    const fields: Record<string, unknown> = {};
    for (const f of entry.fields) fields[f.pointer] = f.value;
    if (typeof fields['/title'] === 'string') byTitle.set(fields['/title'] as string, fields);
  }
  return { unreachable: false, byTitle };
}

/** When the file holds the index record: each record's join commits its close's facts, and each removal is committed. */
async function indexRecord(file: SharedRecordEvidenceV1, options: EvidenceOptions, add: Add): Promise<boolean> {
  if (!file.indexRecord) {
    add('index', null, W.indexNotHeld);
    return false;
  }
  if (options.source === 'offline') {
    add('index', null, W.systemOffline);
    return false;
  }
  const { unreachable, byTitle } = await systemEntries('index', file.indexRecord, options, add);
  if (unreachable || !byTitle) return unreachable;
  for (const record of file.records) {
    const joined = byTitle.get(`Record ${record.record} joined`);
    const expected = payloadDigestV1({
      recordKey: record.sealHistory.recordKey.toLowerCase(),
      lastSeq: record.close.lastSeq,
      lastSeal: record.close.lastSeal.toLowerCase(),
      closedBy: record.close.closedBy,
      number: record.record,
      ruleVersion: record.close.ruleVersion,
    });
    const removedOk = !record.removed || byTitle.has(`Record ${record.record} removed`);
    if (!joined || !isDeepStrictEqual(joined['/payloads/0'], expected) || !removedOk) {
      add('index', false, W.indexDiffers(record.record));
      return false;
    }
  }
  add('index', true, W.indexMatches(file.records.length));
  return false;
}

/** When the file holds the link's own record: each acknowledgment it holds whole is the one that record committed. */
async function readerRecord(file: SharedRecordEvidenceV1, held: Map<string, unknown>, options: EvidenceOptions, add: Add): Promise<boolean> {
  if (!file.readerRecord) {
    add('reader', null, W.readerNotHeld);
    return false;
  }
  if (options.source === 'offline') {
    if (!file.indexRecord) add('reader', null, W.systemOffline);
    return false;
  }
  const { unreachable, byTitle } = await systemEntries('reader', file.readerRecord, options, add);
  if (unreachable || !byTitle) return unreachable;
  for (const [ref, body] of held) {
    const entry = byTitle.get(`Acknowledgment ${ref}`);
    if (!entry || !isDeepStrictEqual(entry['/payloads/0'], payloadDigestV1(body))) {
      add('reader', false, W.readerDiffers(ref));
      return false;
    }
  }
  add('reader', true, W.readerMatches(held.size));
  return false;
}

/** A listed `{pointer: value}` map against the fields a disclosure showed, exactly. */
function sameFields(listed: Record<string, unknown>, shown: Array<{ pointer: string; value: unknown }>): boolean {
  const keys = Object.keys(listed);
  return keys.length === shown.length && shown.every((f) => Object.prototype.hasOwnProperty.call(listed, f.pointer) && isDeepStrictEqual(listed[f.pointer], f.value));
}

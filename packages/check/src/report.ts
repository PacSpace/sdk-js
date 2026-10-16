/**
 * The words the checker says. Pure: everything here is built from the
 * verifier's result and the file, and nothing here reads the network.
 *
 * The sentences follow the printed statement's (records buyer posture plan,
 * Brief section 7; Rule 5): what was checked, what matched, what did not,
 * and the one boundary the check has. No mechanism, no judgement, no word
 * from the forbidden lists. A seal history's sentences are the Shared
 * Record page's, verbatim.
 */

export const REPORT_SCHEMA = 'pacspace-check-report/v1' as const;

export type SourceOutcome =
  | { compared: false; reason: 'offline' }
  | { compared: false; reason: 'unreachable'; detail: string }
  | {
      compared: true;
      matches: boolean;
      chainId: number;
      readsFrom: string;
      /** The contract the source was read at. */
      contractAddress?: string;
      detail: string | null;
    };

export interface DailyStatementOutcome {
  /** The UTC calendar day the daily statement is for (YYYY-MM-DD). */
  date: string;
  fingerprint: string;
  /** null when the file carries no material to compare the statement with. */
  matches: boolean | null;
}

/** The file the reader holds, against the payload references the check verified. No digest of it is kept. */
export interface HeldFileOutcome {
  matched: boolean;
  /** Entry numbers (1-based) whose payloads name the file. */
  entries: number[];
  /** The match was a blinded fingerprint, or a blinded one could decide it. */
  blinded: boolean;
  /** The first entry a blinding file could decide, when nothing matched. */
  blindingNeededAt: number | null;
  /** The ledger was not read (--offline). */
  offline: boolean;
}

/** What became of a disclosure's revealed fields. */
export type DisclosureOutcome =
  | { kind: 'not-checked' }
  | { kind: 'root-not-read' }
  | { kind: 'refused'; code: string | null; reason: string | null }
  | {
      kind: 'verified';
      /** Seqs of the entries that show fields. */
      revealed: number[];
      withheld: number;
      payloads: Array<{ seq: number; items: unknown[] }>;
    };

export interface CheckReport {
  schema: typeof REPORT_SCHEMA;
  checker: { name: string; version: string };
  /** The form the file names. */
  form?: string;
  record: {
    reference: string;
    /** The record's own count, when the file or the source says it; null when neither does. */
    entries: number | null;
    matched: number;
    /** Entry numbers (1-based) the record has that this file does not carry. */
    missing: number[];
    /** Entry numbers (1-based) that do not match what was committed. */
    unmatched: number[];
  };
  /** True when every entry the record has is in the file and matches what was committed. */
  passed: boolean;
  file: {
    /** The history's fingerprint as the file carries it, or as recomputed when the file carries none. */
    fingerprint: string | null;
    /** False when the file's contents no longer produce the fingerprint it carries. */
    intact: boolean;
    exportedAt: string | null;
  };
  source: SourceOutcome;
  dailyStatement: DailyStatementOutcome | null;
  statementFingerprint: { given: string; matches: boolean } | null;
  /** A disclosure's entries that show fields, as seqs. */
  revealed?: number[];
  /** How many fields the disclosure's entries do not show. */
  withheld?: number;
  heldFile?: { matched: boolean; entries: number[]; blinded: boolean };
  reason: string;
  sentences: string[];
  /** 0 the check passed as asked; 1 it did not; 3 the proof layer could not be reached. */
  exitCode: 0 | 1 | 3;
}

/** The subset of the shared verifier's result the report reads. */
export interface VerificationFacts {
  verified: boolean;
  digestOk: boolean;
  reason: string;
  history: {
    complete: boolean;
    expectedRecords: number | null;
    verifiedRecords: number;
    missingSeq: number[];
    failedSeq: number[];
  } | null;
}

export interface ReportInput {
  checker: { name: string; version: string };
  form?: string;
  reference: string;
  fingerprint: string | null;
  computedFingerprint: string;
  exportedAt: string | null;
  verification: VerificationFacts;
  source: SourceOutcome;
  dailyStatement: DailyStatementOutcome | null;
  statementFingerprint: string | null;
  heldFile?: HeldFileOutcome | null;
  /** An encrypted history, opened with its record key: refused entries a re-key left under a key not held. */
  encrypted?: { refusedUnopened: number } | null;
}

/** W-L2g-6 */
export const ENCRYPTED_OPENED_SENTENCE = 'Each entry was opened on this machine and matches its sealed record hash.';

/** W-L2g-7 */
export function refusedUnopenedSentence(k: number): string {
  return `${k} refused ${entryWord(k)} could not be opened with this record key. Their seals are checked.`;
}

export const HONESTY_SENTENCE =
  'The check shows the record is unchanged since it was committed. It does not show that what was recorded was true.';

/** W-17: the boundary of a check of seals. */
export const SEALS_BOUNDARY_SENTENCE =
  'The check shows each seal was committed and that all of them are here, in order. It does not show what any entry says, or that what was recorded was true.';
/** W-65, its first sentence; R2's reason for the code follows it. */
export const FIELDS_FAILED_SENTENCE = 'The revealed fields failed the check, so none are shown.';
/** W-70 */
export const ROOT_NOT_READ_SENTENCE =
  'The revealed fields could not be checked against the proof layer just now, so none are shown. Check again to try once more.';
/** W-71 */
export const TOO_LARGE_SENTENCE = 'This file is too large to be a copy of this record.';
/** W-C8 */
export const FILE_NOT_IN_RECORD_SENTENCE = 'This file is not in the record.';
/** W-C9 */
export const HELD_FILE_OFFLINE_SENTENCE =
  'The ledger was not read (--offline); the file you hold was matched against the history file only.';

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
];

/** "12 September 2026" for a YYYY-MM-DD day or an ISO instant, read in UTC. */
export function dayOfUtc(value: string): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec(value);
  if (!match) return value;
  const day = Number(match[3]);
  const month = MONTHS[Number(match[2]) - 1] ?? match[2];
  return `${day} ${month} ${match[1]}`;
}

function entryWord(count: number): string {
  return count === 1 ? 'entry' : 'entries';
}

function listEntries(numbers: number[]): string {
  const sorted = [...numbers].sort((a, b) => a - b);
  if (sorted.length === 1) return `Entry ${sorted[0]}`;
  const head = sorted.slice(0, -1).join(', ');
  return `Entries ${head} and ${sorted[sorted.length - 1]}`;
}

/** The page's list: "Entry 4", "Entries 2 and 4", "Entries 2, 3, and 4". */
function entryWords(entries: number[]): string {
  if (entries.length === 1) return `Entry ${entries[0]}`;
  if (entries.length === 2) return `Entries ${entries[0]} and ${entries[1]}`;
  return `Entries ${entries.slice(0, -1).join(', ')}, and ${entries[entries.length - 1]}`;
}

const isAre = (count: number) => (count === 1 ? 'is' : 'are');

export function sameHex(a: string | null | undefined, b: string | null | undefined): boolean {
  if (!a || !b) return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * The counted sentence, in the statement's form. It says what the check
 * confirms and no more: every entry the record says it has is in the file
 * and matches what was committed. It cannot confirm that nothing which
 * should have been recorded is absent, so it does not say so (the site
 * ruling of 2026-09-20).
 */
export function countedSentence(record: CheckReport['record']): string {
  const { entries, matched, missing, unmatched } = record;
  if (entries === null) {
    return `This file carries ${matched} ${entryWord(matched)} that match what was committed. The record's own count could not be read.`;
  }
  const parts: string[] = [`This record has ${entries} ${entryWord(entries)}.`];
  if (missing.length === 0 && unmatched.length === 0 && matched >= entries) {
    parts.push(
      entries === 1
        ? 'It is here, and it matches what was committed.'
        : `All ${entries} are here, and all ${entries} match what was committed.`,
    );
    return parts.join(' ');
  }
  parts.push(`${matched} of ${entries} match what was committed.`);
  if (unmatched.length) {
    parts.push(`${listEntries(unmatched)} ${unmatched.length === 1 ? 'does' : 'do'} not.`);
  }
  if (missing.length) {
    parts.push(`${listEntries(missing)} ${missing.length === 1 ? 'is' : 'are'} not in this file.`);
  }
  return parts.join(' ');
}

/** W-11 and W-12. */
export function sealsPassedSentence(n: number): string {
  if (n === 1) return 'This record has 1 entry. Its seal is here, and it is in what was committed.';
  return `This record has ${n} entries. All ${n} seals are here, in order, and each is in what was committed.`;
}

/** W-11s and W-12s: `settling` are entry numbers, `n` counts settled and settling. */
export function sealsSettlingSentence(n: number, settling: number[]): string {
  const m = n - settling.length;
  const tail = `${entryWords(settling)} ${isAre(settling.length)} still being recorded.`;
  if (m <= 0) return `This record has ${n} ${n === 1 ? 'entry' : 'entries'}. ${tail}`;
  if (m === 1) return `This record has ${n} entries. 1 of the ${n} seals is here, and it is in what was committed. ${tail}`;
  return `This record has ${n} entries. ${m} of the ${n} seals are here, in order, and each is in what was committed. ${tail}`;
}

/** W-15: `failed` are entry numbers. */
export function sealsFailedSentence(n: number, failed: number[]): string {
  if (n === 1) return 'This record has 1 entry. Its seal is not in what was committed.';
  const k = n - failed.length;
  return `This record has ${n} entries. ${k} of the ${n} seals ${isAre(k)} in what was committed. ${entryWords(failed)} ${failed.length === 1 ? 'is not' : 'are not'}.`;
}

/** W-15b: `missing` is the entry number not in this copy. */
export function sealsMissingSentence(n: number, held: number, missing: number): string {
  return `What was committed says this record has ${n} entries. This copy has ${held} of them. Entry ${missing} is not here.`;
}

/** W-16 */
export function sealsFormFailedSentence(n: number | null): string {
  return n === null
    ? 'These seals do not match what was committed.'
    : `This record has ${n} entries. These seals do not match what was committed.`;
}

/** W-62 */
export function revealedLine(shown: number, total: number): string {
  if (total === 1) return 'The entry shows fields the sharer chose to reveal. Each shown field was checked against its seal.';
  if (shown >= total) return "Every entry shows fields the sharer chose to reveal. Each shown field was checked against its entry's seal.";
  return `${shown} of ${total} entries ${shown === 1 ? 'shows' : 'show'} fields the sharer chose to reveal. Each shown field was checked against its entry's seal.`;
}

/** The facts of a seal history check the verdict reads. */
export interface SealsFacts {
  verified: boolean;
  schemaOk: boolean;
  digestOk: boolean;
  layoutOk: boolean;
  nothingCommitted: boolean;
  settlingSeq: number[];
  missingSeq: number[];
  failedSeq: number[];
  reason: string;
}

/**
 * The verdict of a seal history, case by case, as the Shared Record page
 * gives it; `entries` is the count the current word gives, `queued` the
 * seqs still being recorded. A record with entries still settling has not
 * passed yet.
 */
export function sealsVerdict(entries: number | null, v: SealsFacts, queued: number[] = []): { sentence: string; passed: boolean } {
  if (v.nothingCommitted) {
    return {
      sentence: queued.length > 0 ? sealsSettlingSentence(queued.length, queued.map((seq) => seq + 1)) : v.reason,
      passed: false,
    };
  }
  if (!v.schemaOk || !v.digestOk || !v.layoutOk || entries === null) {
    return { sentence: sealsFormFailedSentence(entries), passed: false };
  }
  if (v.failedSeq.length > 0) return { sentence: sealsFailedSentence(entries, v.failedSeq.map((seq) => seq + 1)), passed: false };
  if (v.missingSeq.length > 0) {
    return { sentence: sealsMissingSentence(entries, entries - v.missingSeq.length, v.missingSeq[0] + 1), passed: false };
  }
  if (!v.verified) return { sentence: sealsFormFailedSentence(entries), passed: false };
  if (v.settlingSeq.length > 0) {
    return { sentence: sealsSettlingSentence(entries, v.settlingSeq.map((seq) => seq + 1)), passed: false };
  }
  return { sentence: sealsPassedSentence(entries), passed: true };
}

export function sourceSentence(source: SourceOutcome): string {
  if (!source.compared) {
    return source.reason === 'offline'
      ? 'Not compared with the proof layer. The check ran on this file alone.'
      : 'The proof layer could not be reached. The check ran on this file alone.';
  }
  return source.matches
    ? 'Compared with the proof layer for this record: it matches.'
    : `Compared with the proof layer for this record: it does not match.${source.detail ? ` ${source.detail}` : ''}`;
}

export function dailyStatementSentence(statement: DailyStatementOutcome | null): string {
  if (!statement) return 'This file carries no daily statement.';
  const day = `Daily statement of ${dayOfUtc(statement.date)} (UTC)`;
  if (statement.matches === null) {
    return `${day}: not compared from this file alone. Pass --full to compare it with the proof layer.`;
  }
  return statement.matches ? `${day}: matches.` : `${day}: does not match what the proof layer carries for that day.`;
}

export const FILE_CHANGED_SENTENCE =
  'This file has been changed since it was exported. Its contents no longer produce the fingerprint it carries.';

export function fingerprintSentence(intact: boolean, given: CheckReport['statementFingerprint']): string | null {
  if (!given) return null;
  if (!intact) return 'The fingerprint you gave cannot be matched, because this file was changed.';
  return given.matches
    ? 'The fingerprint you gave names this file.'
    : 'The fingerprint you gave does not name this file. The statement it was printed on was checked over a different export of this record.';
}

/** W-C4, W-C5 or W-C8, then W-C9 when the ledger was not read. */
export function heldFileSentences(held: HeldFileOutcome): string[] {
  const lines: string[] = [];
  if (held.matched) lines.push(`The file you hold matches entry ${held.entries[0]}.`);
  else if (held.blindingNeededAt !== null) {
    lines.push(`Entry ${held.blindingNeededAt} is blinded. Add --blinding with the file's blinding file to check it.`);
  } else lines.push(FILE_NOT_IN_RECORD_SENTENCE);
  if (held.offline) lines.push(HELD_FILE_OFFLINE_SENTENCE);
  return lines;
}

/** 3 before 1: a source that could not be read is reported as such even when something else failed. */
function exitCodeOf(unreachable: boolean, failed: boolean): CheckReport['exitCode'] {
  if (unreachable) return 3;
  return failed ? 1 : 0;
}

function statementFingerprintOf(given: string | null, intact: boolean, fingerprint: string | null) {
  return given ? { given, matches: intact && sameHex(given, fingerprint) } : null;
}

function heldFileField(held: HeldFileOutcome | null | undefined): CheckReport['heldFile'] | undefined {
  return held ? { matched: held.matched, entries: held.entries, blinded: held.blinded } : undefined;
}

export function buildReport(input: ReportInput): CheckReport {
  const history = input.verification.history;
  const matched = history?.verifiedRecords ?? 0;
  const entries = history?.expectedRecords ?? (history ? matched : null);
  const record: CheckReport['record'] = {
    reference: input.reference,
    entries,
    matched,
    missing: (history?.missingSeq ?? []).map((seq) => seq + 1),
    unmatched: (history?.failedSeq ?? []).map((seq) => seq + 1),
  };
  const intact = input.verification.digestOk;
  const file: CheckReport['file'] = {
    fingerprint: input.fingerprint ?? input.computedFingerprint,
    intact,
    exportedAt: input.exportedAt,
  };
  const statementFingerprint = statementFingerprintOf(input.statementFingerprint, intact, file.fingerprint);
  const passed = input.verification.verified && (input.source.compared ? input.source.matches : true);

  const sentences: string[] = [];
  if (!intact) {
    sentences.push(FILE_CHANGED_SENTENCE);
  } else if (history) {
    sentences.push(countedSentence(record));
    if (input.encrypted) {
      sentences.push(ENCRYPTED_OPENED_SENTENCE);
      if (input.encrypted.refusedUnopened > 0) sentences.push(refusedUnopenedSentence(input.encrypted.refusedUnopened));
    }
  } else {
    sentences.push(input.verification.reason);
  }
  sentences.push(sourceSentence(input.source));
  sentences.push(dailyStatementSentence(input.dailyStatement));
  const fingerprintLine = fingerprintSentence(intact, statementFingerprint);
  if (fingerprintLine) sentences.push(fingerprintLine);
  if (input.heldFile) sentences.push(...heldFileSentences(input.heldFile));
  sentences.push(HONESTY_SENTENCE);

  const failed =
    !passed || (statementFingerprint !== null && !statementFingerprint.matches) || (!!input.heldFile && !input.heldFile.matched);
  const unreachable = !input.source.compared && input.source.reason === 'unreachable';

  return {
    schema: REPORT_SCHEMA,
    checker: input.checker,
    ...(input.form ? { form: input.form } : {}),
    record,
    passed,
    file,
    source: input.source,
    dailyStatement: input.dailyStatement,
    statementFingerprint,
    ...(input.heldFile ? { heldFile: heldFileField(input.heldFile) } : {}),
    reason: input.verification.reason,
    sentences,
    exitCode: exitCodeOf(unreachable, failed),
  };
}

export interface SealsReportInput {
  checker: { name: string; version: string };
  form: string;
  reference: string;
  fingerprint: string | null;
  computedFingerprint: string;
  statementFingerprint: string | null;
  /** The record's entry count from its current word, or null. */
  entries: number | null;
  /** Seqs the form lists as queued. */
  queued: number[];
  verification: SealsFacts;
  source: SourceOutcome;
  disclosure: DisclosureOutcome | null;
  heldFile: HeldFileOutcome | null;
}

/** A seal history's report, alone or in a kept copy, with any disclosure checked against it. */
export function buildSealsReport(input: SealsReportInput): CheckReport {
  const v = input.verification;
  const failedCount = v.failedSeq.length;
  const record: CheckReport['record'] = {
    reference: input.reference,
    entries: input.entries,
    matched: Math.max(0, (input.entries ?? 0) - v.missingSeq.length - v.settlingSeq.length - failedCount),
    missing: v.missingSeq.map((seq) => seq + 1),
    unmatched: v.failedSeq.map((seq) => seq + 1),
  };
  const intact = v.digestOk;
  const file: CheckReport['file'] = { fingerprint: input.fingerprint ?? input.computedFingerprint, intact, exportedAt: null };
  const statementFingerprint = statementFingerprintOf(input.statementFingerprint, intact, file.fingerprint);
  const verdict = sealsVerdict(input.entries, v, input.queued);
  const disclosure = input.disclosure;
  const disclosureOk = !disclosure || disclosure.kind === 'verified';
  const passed = verdict.passed && v.verified && (input.source.compared ? input.source.matches : true) && disclosureOk;

  const sentences: string[] = [intact ? verdict.sentence : FILE_CHANGED_SENTENCE];
  if (disclosure?.kind === 'verified') {
    sentences.push(revealedLine(disclosure.revealed.length, input.entries ?? disclosure.revealed.length));
  } else if (disclosure?.kind === 'refused') {
    sentences.push(FIELDS_FAILED_SENTENCE, ...(disclosure.reason ? [disclosure.reason] : []));
  } else if (disclosure?.kind === 'root-not-read') {
    sentences.push(ROOT_NOT_READ_SENTENCE);
  }
  sentences.push(sourceSentence(input.source));
  sentences.push(dailyStatementSentence(null));
  const fingerprintLine = fingerprintSentence(intact, statementFingerprint);
  if (fingerprintLine) sentences.push(fingerprintLine);
  if (input.heldFile && disclosure?.kind === 'verified') sentences.push(...heldFileSentences(input.heldFile));
  sentences.push(SEALS_BOUNDARY_SENTENCE);

  const failed =
    !passed || (statementFingerprint !== null && !statementFingerprint.matches) || (!!input.heldFile && !input.heldFile.matched);
  const unreachable =
    (!input.source.compared && input.source.reason === 'unreachable') || disclosure?.kind === 'root-not-read';

  return {
    schema: REPORT_SCHEMA,
    checker: input.checker,
    form: input.form,
    record,
    passed,
    file,
    source: input.source,
    dailyStatement: null,
    statementFingerprint,
    ...(disclosure?.kind === 'verified' ? { revealed: disclosure.revealed, withheld: disclosure.withheld } : {}),
    ...(input.heldFile ? { heldFile: heldFileField(input.heldFile) } : {}),
    reason: v.reason,
    sentences,
    exitCode: exitCodeOf(unreachable, failed),
  };
}

/** The report as the terminal prints it: labeled facts in a column, then the sentences. */
export function renderReport(report: CheckReport): string {
  const facts: Array<[string, string]> = [
    ['Reference', report.record.reference],
    ['Fingerprint of this history', report.file.fingerprint ?? 'none'],
  ];
  if (report.file.exportedAt) facts.push(['Exported', `${report.file.exportedAt} (UTC)`]);
  if (report.source.compared) facts.push(['Proof layer', report.source.readsFrom]);
  const width = Math.max(...facts.map(([label]) => label.length));
  const lines = facts.map(([label, value]) => `${label.padEnd(width)}  ${value}`);
  lines.push('');
  lines.push(...report.sentences);
  return `${lines.join('\n')}\n`;
}

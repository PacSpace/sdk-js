/**
 * `shared-record-evidence/v1` (records prototype build, R7; HANDOFF R9 and 16 October section 4; D-42, D-45, D-46,
 * D-52): the evidence record a trail link's reader downloads, as data a machine can read, in two editions, Full and
 * For reviewers, made in the reader's browser (or the scripted reader, or the reader's MCP server) from what it
 * already holds, and signed by the device that made it with its v2 pair. The checker's `evidence` command re-checks
 * it offline against the proof layer.
 *
 * The keys follow the prototype's `evidence()` at the pin (`js/record.js` lines 693 to 732; K1's canon
 * `evidenceKeys`), with what a machine needs to repeat each check: every record's `record-seal-history/v1`, its close
 * facts as its join committed them, and in Full the `record-disclosure` each revealed or answered entry was opened
 * from. Exports and citations are added by the slices that build them (EX1, CI1); FL1's flag threads are carried
 * as `flagThreads` (optional, so a file made before FL1 still reads); the prototype's earlier `automaticAnswers` is
 * not carried, since `agentAnswers` says the same (D-22).
 *
 * Built only by `buildSharedRecordEvidenceV1`, an allowlist serializer like `shared-record/v1`'s, whose key sets
 * `sharedRecordEvidenceV1KeyProblems` walks per edition. For reviewers (D-52) leaves out every field the lab revealed,
 * its replies and its answers to flags (each answer's words, with `leftOut`), and (David, 2026-10-25) the agent lines (`agentAnswers`, `readerAgent`, both
 * null) and the lab's decline notes (each decline keeps its reason and day); it keeps results, references and seals,
 * lists each withholding with its date and category, and keeps only the count, the shortest and the longest of a
 * check's time to commit; its index and link record disclosures show each entry's title and payloads only. A file
 * for reviewers that carries any of these is refused. In both versions a decline names its reason by the answer
 * form's own reasons, never in free text.
 *
 * It never holds a reader's name or organisation, the workspace's own name for what is shared, a label, a source,
 * an environment, a whole handle, a code, a token or a session id (`sharedRecordEvidenceV1NeutralityProblems`).
 * Records are numbered as on the link and entries from 1, as the reader reads them.
 */
import { canonicalizeJcs } from '../proof/jcs';
import type { RecordSealHistoryV1 } from './record-seal-history-v1';
import type { SigningPublicKeyJwkV1 } from './signed-acknowledgment-v1';
import type { SharedRecordAckBodyV2 } from './shared-record-ack-v2';

export const SHARED_RECORD_EVIDENCE_SCHEMA_V1 = 'shared-record-evidence/v1' as const;
export const SHARED_RECORD_EVIDENCE_KIND_V1 = 'pacspace-evidence-record' as const;
export const SHARED_RECORD_EVIDENCE_SIGNING_LABEL_V1 = 'pacspace:shared-record-evidence:v1';
/** A reader refuses a larger file before parsing it. */
export const SHARED_RECORD_EVIDENCE_MAX_BYTES_V1 = 64 * 1024 * 1024;

export type SharedRecordEvidenceEditionV1 = 'full' | 'for reviewers';

/** The prototype's words for what a version leaves out (js/record.js). */
export const EVIDENCE_LEFT_OUT_V1 = 'Left out of this version';
export const EVIDENCE_WRITTEN_BY_NOT_SHOWN_V1 = 'Not shown on this link';
/** The prototype's note for the version for reviewers (js/record.js:690), with the operator named by the caller. */
export const evidenceForReviewersNoteV1 = (organization: string) =>
  `This version is for reviewers. It leaves out every field ${organization} revealed to the reader, its replies, and its answers to flags. Results, references and seals are kept, so the checks of the records and their entries can be repeated without them. Each entry ${organization} withheld from publication is listed with the date it was committed and its category.`;

export interface EvidenceEntryRefV1 {
  record: number;
  entry: number;
}

/** A record on the link, as the reader's check read it. */
export interface EvidenceRecordV1 {
  record: number;
  opened: string;
  closed: string | null;
  closedBy: 'code' | 'pacspace';
  joined: string;
  removed: { day: string; reason: string } | null;
  entries: number;
  /** Each entry's committed seal, in order, as its seal history holds them. */
  seals: string[];
  /** The close's facts as the record's join committed them on the index record (D-7). */
  close: { lastSeq: number; lastSeal: string; closedBy: 'code' | 'timeout'; ruleVersion: number };
  sealHistory: RecordSealHistoryV1;
  /** Full only, on a link that reveals fields: each revealed entry's fields by pointer, as shown, and both seals. */
  revealed?: Array<{ entry: number; fields: Record<string, unknown>; committed: string; recomputed: string | null }>;
  /** Full only: the `record-disclosure` the reveal opened to, which the checker verifies against the seal history. */
  disclosure?: unknown;
}

export interface EvidenceCheckV1 {
  ref: string;
  at: string;
  asOf?: string;
  durationMs: number;
  records: number;
  entries: number;
  /** D-46: what did the checking, its release read from the manifest the page was served under. */
  checkedBy: { on: string; where: 'browser'; tool: string; release: string };
  results: Array<{ check: string; result: string; matches?: boolean; word: string }>;
  /** D-43: Full lists each entry; For reviewers keeps the count, the shortest and the longest. */
  timeToCommit?:
    | Array<{ record: number; entry: number; happened: string; happenedAccordingTo: string; committed: string; seconds: number }>
    | { entries: number; shortestSeconds: number; longestSeconds: number; eachEntry: string };
}

export interface EvidenceRequestV1 {
  ref: string;
  at: string;
  sentBy: string;
  spread: string | null;
  sample: {
    method: 'pacspace-sample/v1';
    seed: string;
    randomPicks: number;
    spread: 'any' | 'records' | 'days';
    pool: Array<{ record: number; entries: number; openedOn: string }>;
    poolDigest: string;
    leftOut: EvidenceEntryRefV1[];
    removedByTheReader: EvidenceEntryRefV1[];
    readersMethod: unknown;
  } | null;
  linkAnswersWithin: string | null;
  picks: Array<EvidenceEntryRefV1 & { picked: 'at random' | 'chosen' | 'did not match its seal'; countsAgainstSample: boolean; seal: string }>;
  question: string | null;
  answered: boolean;
}

/** A decline's reason, by the answer form's own reasons (R6's AnswerDeclineV1 kinds); the lab's sentence rides only in `note`. */
export const EVIDENCE_DECLINE_REASONS_V1 = ['legal_hold', 'personal_data', 'beyond_sample', 'past_retention', 'other'] as const;
export type EvidenceDeclineReasonV1 = (typeof EVIDENCE_DECLINE_REASONS_V1)[number];

export type EvidenceAnswerEntryV1 =
  | (EvidenceEntryRefV1 & { declined: { reason: EvidenceDeclineReasonV1; note: string | null; day: string } })
  | (EvidenceEntryRefV1 & { notOpenedOnThisDevice: true })
  | (EvidenceEntryRefV1 & {
      seal: string;
      committed: string;
      recomputed: string | null;
      matchesSeal: boolean;
      /** Full only: the fields shown, by pointer, and the disclosure they were opened from. */
      fields?: Record<string, unknown>;
      disclosure?: unknown;
    });

export interface EvidenceAnswerV1 {
  request: string;
  at: string;
  /** "An agent at {organization}" or "A person at {organization}", never an agent's own name (D-22). */
  sentBy: string;
  approvedBy: string | null;
  /** Full: the reply as opened, or null; For reviewers: always null, with `replyLeftOut` when there was one. */
  reply: string | null;
  replyLeftOut?: true;
  /** D-22: whether the answer showed exactly the fields it declared. */
  declaredFields: { asDeclared: boolean };
  entries: EvidenceAnswerEntryV1[];
}

/**
 * An acknowledgment the link carries; `signed` when this device holds its body and signatures. A flag whose note the
 * body carries sealed (an encrypted workspace) says so with `noteSealed`, and its `note` is the reader's words as this
 * browser opened them, or null when this device holds no key to them: the words never leave the reader's browser but
 * in this file.
 */
export interface EvidenceAcknowledgmentV1 {
  ref: string;
  at: string;
  sentBy: string;
  check: string;
  /** The acknowledgment's own note, by the same rule as a flag's: `noteSealed` when the body carries it sealed. */
  note: string | null;
  noteSealed?: true;
  flags: Array<EvidenceEntryRefV1 & { result: string; note: string | null; noteSealed?: true }>;
  signed: { body: SharedRecordAckBodyV2; signature: string; mldsaSignature: string; p256Jwk: SigningPublicKeyJwkV1; mldsaPublicKey: string } | null;
}

/**
 * One event on a flag thread, as the prototype's `evidence()` states it (`js/record.js:727`): the flag sent in an
 * acknowledgment with the reader's note, an answer by "{organization}" or "An agent at {organization}" (never an
 * agent's own name), a reply in the reader's words, or the close. A note or an answer is the words as this browser
 * opened them, or null when this device holds no key to them; For reviewers leaves each answer's words out.
 */
export type EvidenceFlagEventV1 =
  | { kind: 'flagged'; at: string; in: string; note: string | null; noteSealed?: true }
  | { kind: 'answered'; at: string; by: string; text?: string | null; leftOut?: true }
  | { kind: 'replied'; at: string; text: string | null }
  | { kind: 'closed'; at: string };

/** A flag thread on the link, FL-0001 and up, where it stands, and its events in order (FL1). */
export interface EvidenceFlagThreadV1 extends EvidenceEntryRefV1 {
  ref: string;
  result: string;
  status: 'open' | 'answered' | 'closed';
  events: EvidenceFlagEventV1[];
}

/** A PacSpace-written record the reader holds the seals of, and a disclosure of its entries' kind, title and payloads. */
export interface EvidenceSystemRecordV1 {
  sealHistory: RecordSealHistoryV1;
  disclosure: unknown;
}

export interface EvidenceSignatureV1 {
  alg: ['ES256', 'ML-DSA-65'];
  /** The signing device's three public keys, so its id and code are worked out, never taken from the file. */
  device: { xwingPublicKey: string; p256Jwk: SigningPublicKeyJwkV1; mldsaPublicKey: string };
  signature: string;
  mldsaSignature: string;
}

export interface SharedRecordEvidenceV1 {
  schema: typeof SHARED_RECORD_EVIDENCE_SCHEMA_V1;
  kind: typeof SHARED_RECORD_EVIDENCE_KIND_V1;
  version: 1;
  edition: SharedRecordEvidenceEditionV1;
  ref: string;
  made: string;
  /** The link's address by its handle's prefix only, never the whole handle. */
  link: string;
  sharedBy: string;
  sharedOn: string;
  linkEnds: string;
  linkExtended: Array<{ on: string; from: string; to: string }>;
  sampleAllowance: { perMonth: number; changes: Array<{ day: string; from: number; to: number }> };
  agentAnswers: { since: string; toAPerson: string } | null;
  scope: string;
  linkReveals: string;
  linkRevealedLater?: Array<{ record: number; day: string }>;
  linkNotRevealedYet?: number[];
  ruleHistory: Array<{ day: string; change: string; scope: string | null; previousScope: string | null; reason: string | null }>;
  period: { from: string; to: string };
  erased: Array<EvidenceEntryRefV1 & { day: string; reason: string }>;
  records: EvidenceRecordV1[];
  checks: EvidenceCheckV1[];
  writtenBy: string | Array<{ runs: string | Array<{ version: number; from: string; model: string; builtOn: string | null; runtime: string | null; guardrails: string | null; records: number[] }>; statedBy: string; checkedByPacSpace: false }>;
  readerAgent: { name: string; since: string } | null;
  withheldFromPublication: { categories: Array<{ committed: string; list: string[] }>; entries: Array<EvidenceEntryRefV1 & { category: string; committed: string; by: string; label: string }> };
  requests: EvidenceRequestV1[];
  answers: EvidenceAnswerV1[];
  acknowledgments: EvidenceAcknowledgmentV1[];
  flags: Array<EvidenceEntryRefV1 & { result: string; note: string | null; sentIn: string | null }>;
  flagThreads?: EvidenceFlagThreadV1[];
  devices: Array<{ code: string; kind: 'browser' | 'agent'; status: 'unconfirmed' | 'confirmed' | 'revoked'; addedOn: string }>;
  /** The trail's index record and the link's reader record, when the reader holds their seals; null otherwise. */
  indexRecord: EvidenceSystemRecordV1 | null;
  readerRecord: EvidenceSystemRecordV1 | null;
  statement: string;
  whatACheckShows: string;
  notes: string[];
  checkAgain: { checker: string; package: string; version: string; reads: string; open: string; keptCopy: string; thePageItself: string; inTheNextRelease?: string[] };
  signature?: EvidenceSignatureV1;
}

type KeySet = { required: readonly string[]; optional?: readonly string[] };

const ENTRY = ['record', 'entry'];
const COMMON: Readonly<Record<string, KeySet>> = {
  '': {
    required: [
      'schema', 'kind', 'version', 'edition', 'ref', 'made', 'link', 'sharedBy', 'sharedOn', 'linkEnds', 'linkExtended', 'sampleAllowance', 'agentAnswers',
      'scope', 'linkReveals', 'ruleHistory', 'period', 'erased', 'records', 'checks', 'writtenBy', 'readerAgent', 'withheldFromPublication', 'requests',
      'answers', 'acknowledgments', 'flags', 'devices', 'indexRecord', 'readerRecord', 'statement', 'whatACheckShows', 'notes', 'checkAgain',
    ],
    optional: ['signature', 'flagThreads'],
  },
  'linkExtended[]': { required: ['on', 'from', 'to'] },
  sampleAllowance: { required: ['perMonth', 'changes'] },
  'sampleAllowance.changes[]': { required: ['day', 'from', 'to'] },
  agentAnswers: { required: ['since', 'toAPerson'] },
  'ruleHistory[]': { required: ['day', 'change', 'scope', 'previousScope', 'reason'] },
  period: { required: ['from', 'to'] },
  'erased[]': { required: [...ENTRY, 'day', 'reason'] },
  'records[].removed': { required: ['day', 'reason'] },
  'records[].close': { required: ['lastSeq', 'lastSeal', 'closedBy', 'ruleVersion'] },
  'checks[]': { required: ['ref', 'at', 'durationMs', 'records', 'entries', 'checkedBy', 'results'], optional: ['asOf', 'timeToCommit'] },
  'checks[].checkedBy': { required: ['on', 'where', 'tool', 'release'] },
  'checks[].results[]': { required: ['check', 'result', 'word'], optional: ['matches'] },
  'writtenBy[]': { required: ['runs', 'statedBy', 'checkedByPacSpace'] },
  'writtenBy[].runs[]': { required: ['version', 'from', 'model', 'builtOn', 'runtime', 'guardrails', 'records'] },
  readerAgent: { required: ['name', 'since'] },
  withheldFromPublication: { required: ['categories', 'entries'] },
  'withheldFromPublication.categories[]': { required: ['committed', 'list'] },
  'withheldFromPublication.entries[]': { required: [...ENTRY, 'category', 'committed', 'by', 'label'] },
  'requests[]': { required: ['ref', 'at', 'sentBy', 'spread', 'sample', 'linkAnswersWithin', 'picks', 'question', 'answered'] },
  'requests[].sample': { required: ['method', 'seed', 'randomPicks', 'spread', 'pool', 'poolDigest', 'leftOut', 'removedByTheReader', 'readersMethod'] },
  'requests[].sample.pool[]': { required: ['record', 'entries', 'openedOn'] },
  'requests[].sample.leftOut[]': { required: ENTRY },
  'requests[].sample.removedByTheReader[]': { required: ENTRY },
  'requests[].picks[]': { required: [...ENTRY, 'picked', 'countsAgainstSample', 'seal'] },
  'answers[].declaredFields': { required: ['asDeclared'] },
  'answers[].entries[].declined': { required: ['reason', 'note', 'day'] },
  'acknowledgments[]': { required: ['ref', 'at', 'sentBy', 'check', 'note', 'flags', 'signed'], optional: ['noteSealed'] },
  'acknowledgments[].flags[]': { required: [...ENTRY, 'result', 'note'], optional: ['noteSealed'] },
  'acknowledgments[].signed': { required: ['body', 'signature', 'mldsaSignature', 'p256Jwk', 'mldsaPublicKey'] },
  'flags[]': { required: [...ENTRY, 'result', 'note', 'sentIn'] },
  'flagThreads[]': { required: ['ref', ...ENTRY, 'result', 'status', 'events'] },
  'devices[]': { required: ['code', 'kind', 'status', 'addedOn'] },
  indexRecord: { required: ['sealHistory', 'disclosure'] },
  readerRecord: { required: ['sealHistory', 'disclosure'] },
  'notes[]': { required: [] },
  checkAgain: { required: ['checker', 'package', 'version', 'reads', 'open', 'keptCopy', 'thePageItself'], optional: ['inTheNextRelease'] },
  signature: { required: ['alg', 'device', 'signature', 'mldsaSignature'] },
  'signature.device': { required: ['xwingPublicKey', 'p256Jwk', 'mldsaPublicKey'] },
  'signature.device.p256Jwk': { required: ['kty', 'crv', 'x', 'y'] },
  'acknowledgments[].signed.p256Jwk': { required: ['kty', 'crv', 'x', 'y'] },
};

/** The exact key sets of each edition, by path (`[]` marks a list's items). Objects under a seal history, a disclosure or a signed body are their own forms'. */
export const SHARED_RECORD_EVIDENCE_V1_KEYS: Readonly<Record<SharedRecordEvidenceEditionV1, Readonly<Record<string, KeySet>>>> = {
  full: {
    ...COMMON,
    '': { required: COMMON[''].required, optional: ['signature', 'flagThreads', 'linkRevealedLater', 'linkNotRevealedYet'] },
    'flagThreads[].events[]': { required: ['kind', 'at'], optional: ['in', 'note', 'noteSealed', 'by', 'text'] },
    'linkRevealedLater[]': { required: ['record', 'day'] },
    'records[]': { required: ['record', 'opened', 'closed', 'closedBy', 'joined', 'removed', 'entries', 'seals', 'close', 'sealHistory'], optional: ['revealed', 'disclosure'] },
    'records[].revealed[]': { required: ['entry', 'fields', 'committed', 'recomputed'] },
    'checks[].timeToCommit[]': { required: [...ENTRY, 'happened', 'happenedAccordingTo', 'committed', 'seconds'] },
    'answers[]': { required: ['request', 'at', 'sentBy', 'approvedBy', 'reply', 'declaredFields', 'entries'] },
    'answers[].entries[]': { required: ENTRY, optional: ['declined', 'notOpenedOnThisDevice', 'seal', 'committed', 'recomputed', 'matchesSeal', 'fields', 'disclosure'] },
  },
  'for reviewers': {
    ...COMMON,
    'records[]': { required: ['record', 'opened', 'closed', 'closedBy', 'joined', 'removed', 'entries', 'seals', 'close', 'sealHistory'] },
    'checks[].timeToCommit': { required: ['entries', 'shortestSeconds', 'longestSeconds', 'eachEntry'] },
    'answers[]': { required: ['request', 'at', 'sentBy', 'approvedBy', 'reply', 'declaredFields', 'entries'], optional: ['replyLeftOut'] },
    'answers[].entries[]': { required: ENTRY, optional: ['declined', 'notOpenedOnThisDevice', 'seal', 'committed', 'recomputed', 'matchesSeal'] },
    'flagThreads[].events[]': { required: ['kind', 'at'], optional: ['in', 'note', 'noteSealed', 'by', 'text', 'leftOut'] },
  },
};

/** Paths whose objects belong to another form, checked by that form's own reader, never walked here. */
const OPAQUE = new Set([
  'records[].sealHistory',
  'records[].disclosure',
  'records[].revealed[].fields',
  'answers[].entries[].fields',
  'answers[].entries[].disclosure',
  'requests[].sample.readersMethod',
  'acknowledgments[].signed.body',
  'indexRecord.sealHistory',
  'indexRecord.disclosure',
  'readerRecord.sealHistory',
  'readerRecord.disclosure',
]);

const isPlain = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Every key out of place in an evidence file for its edition, as `path.key`; empty when it holds exactly the allowed keys. */
export function sharedRecordEvidenceV1KeyProblems(evidence: unknown): string[] {
  if (!isPlain(evidence)) return ['(root): not an object'];
  const edition = evidence.edition;
  if (edition !== 'full' && edition !== 'for reviewers') return ['edition: not an edition this version reads'];
  const sets = SHARED_RECORD_EVIDENCE_V1_KEYS[edition];
  const problems: string[] = [];
  const walk = (value: unknown, path: string): void => {
    if (OPAQUE.has(path)) return;
    if (Array.isArray(value)) {
      for (const item of value) walk(item, `${path}[]`);
      return;
    }
    if (!isPlain(value)) return;
    const set = sets[path];
    if (!set) {
      problems.push(`${path || '(root)'}: no object allowed here`);
      return;
    }
    const allowed = new Set([...set.required, ...(set.optional ?? [])]);
    for (const key of set.required) if (value[key] === undefined) problems.push(`${path ? `${path}.` : ''}${key}: missing`);
    for (const key of Object.keys(value)) {
      if (!allowed.has(key)) problems.push(`${path ? `${path}.` : ''}${key}: not allowed`);
      else walk(value[key], path ? `${path}.${key}` : key);
    }
  };
  walk(evidence, '');
  const declined = (Array.isArray(evidence.answers) ? evidence.answers : [])
    .flatMap((a) => (isPlain(a) && Array.isArray(a.entries) ? a.entries : []))
    .map((e) => (isPlain(e) ? e.declined : undefined));
  if (declined.some((d) => isPlain(d) && !EVIDENCE_DECLINE_REASONS_V1.includes(d.reason as EvidenceDeclineReasonV1))) {
    problems.push("answers[].entries[].declined.reason: not one of the answer form's reasons");
  }
  if (declined.some((d) => isPlain(d) && (typeof d.day !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d.day)))) problems.push('answers[].entries[].declined.day: not a day');
  if (edition === 'for reviewers') problems.push(...leftOutProblems(evidence));
  return problems;
}

/** A PacSpace-written record's disclosure in a file for reviewers shows each entry's title and payloads, and nothing else. */
const SYSTEM_POINTER = /^\/(title|payloads\/(0|[1-9][0-9]*))$/;
function showsOnlyTitlesAndPayloads(disclosure: unknown): boolean {
  if (!isPlain(disclosure) || !Array.isArray(disclosure.entries)) return false;
  return disclosure.entries.every(
    (e) => isPlain(e) && !('recordContent' in e) && Array.isArray(e.revealed) && e.revealed.every((r) => isPlain(r) && typeof r.pointer === 'string' && SYSTEM_POINTER.test(r.pointer)),
  );
}

/** What a file for reviewers must leave out (D-52; David, 2026-10-25), each as `path: left out of this version`. */
function leftOutProblems(evidence: Record<string, unknown>): string[] {
  const problems: string[] = [];
  const left = (path: string) => problems.push(`${path}: left out of this version`);
  if (evidence.agentAnswers !== null) left('agentAnswers');
  if (evidence.readerAgent !== null) left('readerAgent');
  if (evidence.linkReveals !== EVIDENCE_LEFT_OUT_V1) left('linkReveals');
  const answers = Array.isArray(evidence.answers) ? evidence.answers : [];
  if (answers.some((a) => isPlain(a) && a.reply !== null)) left('answers[].reply');
  const declined = answers.flatMap((a) => (isPlain(a) && Array.isArray(a.entries) ? a.entries : [])).map((e) => (isPlain(e) ? e.declined : undefined));
  if (declined.some((d) => isPlain(d) && d.note !== null)) left('answers[].entries[].declined.note');
  const events = (Array.isArray(evidence.flagThreads) ? evidence.flagThreads : []).flatMap((t) => (isPlain(t) && Array.isArray(t.events) ? t.events : []));
  if (events.some((e) => isPlain(e) && e.kind === 'answered' && e.text !== undefined)) left('flagThreads[].events[].text');
  const checks = Array.isArray(evidence.checks) ? evidence.checks : [];
  if (checks.some((c) => isPlain(c) && isPlain(c.timeToCommit) && c.timeToCommit.eachEntry !== EVIDENCE_LEFT_OUT_V1)) left('checks[].timeToCommit.eachEntry');
  for (const which of ['indexRecord', 'readerRecord'] as const) {
    const system = evidence[which];
    if (isPlain(system) && !showsOnlyTitlesAndPayloads(system.disclosure)) left(`${which}.disclosure`);
  }
  return problems;
}

/** Thrown by the builder when its own output breaks the allowlist or the neutrality rule. */
export class SharedRecordEvidenceShapeError extends Error {
  constructor(readonly problems: string[]) {
    super(`shared-record-evidence/v1: ${problems.join('; ')}`);
  }
}

/** What the builder takes: the Full record as the reader's browser holds it, without the four constant members. */
export type SharedRecordEvidenceInputV1 = Omit<SharedRecordEvidenceV1, 'schema' | 'kind' | 'version' | 'edition' | 'signature'>;

const refOf = (e: EvidenceEntryRefV1) => ({ record: e.record, entry: e.entry });
const copy = <T>(value: T): T => (value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T));

/**
 * The evidence in one edition, written key by key. For reviewers leaves out the revealed fields, the disclosures,
 * the replies and each time to commit, as D-52 defines it, and adds its note. Refuses its own output when a key is
 * out of place or a neutrality rule fails (`forbidden` names the reader's and the trail's own words to keep out).
 */
export function buildSharedRecordEvidenceV1(input: SharedRecordEvidenceInputV1, edition: SharedRecordEvidenceEditionV1, forbidden: readonly string[] = []): SharedRecordEvidenceV1 {
  const rev = edition === 'for reviewers';
  const out: SharedRecordEvidenceV1 = {
    schema: SHARED_RECORD_EVIDENCE_SCHEMA_V1,
    kind: SHARED_RECORD_EVIDENCE_KIND_V1,
    version: 1,
    edition,
    ref: input.ref,
    made: input.made,
    link: input.link,
    sharedBy: input.sharedBy,
    sharedOn: input.sharedOn,
    linkEnds: input.linkEnds,
    linkExtended: input.linkExtended.map((x) => ({ on: x.on, from: x.from, to: x.to })),
    sampleAllowance: { perMonth: input.sampleAllowance.perMonth, changes: input.sampleAllowance.changes.map((c) => ({ day: c.day, from: c.from, to: c.to })) },
    agentAnswers: !rev && input.agentAnswers ? { since: input.agentAnswers.since, toAPerson: input.agentAnswers.toAPerson } : null,
    scope: input.scope,
    linkReveals: rev ? EVIDENCE_LEFT_OUT_V1 : input.linkReveals,
    ruleHistory: input.ruleHistory.map((h) => ({ day: h.day, change: h.change, scope: h.scope, previousScope: h.previousScope, reason: h.reason })),
    period: { from: input.period.from, to: input.period.to },
    erased: input.erased.map((e) => ({ ...refOf(e), day: e.day, reason: e.reason })),
    records: input.records.map((r) => {
      const record: EvidenceRecordV1 = {
        record: r.record,
        opened: r.opened,
        closed: r.closed,
        closedBy: r.closedBy,
        joined: r.joined,
        removed: r.removed ? { day: r.removed.day, reason: r.removed.reason } : null,
        entries: r.entries,
        seals: [...r.seals],
        close: { lastSeq: r.close.lastSeq, lastSeal: r.close.lastSeal, closedBy: r.close.closedBy, ruleVersion: r.close.ruleVersion },
        sealHistory: copy(r.sealHistory),
      };
      if (!rev && r.revealed !== undefined) record.revealed = r.revealed.map((x) => ({ entry: x.entry, fields: copy(x.fields), committed: x.committed, recomputed: x.recomputed }));
      if (!rev && r.disclosure !== undefined) record.disclosure = copy(r.disclosure);
      return record;
    }),
    checks: input.checks.map((c) => {
      const check: EvidenceCheckV1 = {
        ref: c.ref,
        at: c.at,
        durationMs: c.durationMs,
        records: c.records,
        entries: c.entries,
        checkedBy: { on: c.checkedBy.on, where: c.checkedBy.where, tool: c.checkedBy.tool, release: c.checkedBy.release },
        results: c.results.map((x) => ({ check: x.check, result: x.result, ...(x.matches === undefined ? {} : { matches: x.matches }), word: x.word })),
      };
      if (c.asOf !== undefined) check.asOf = c.asOf;
      const gaps = c.timeToCommit;
      if (Array.isArray(gaps) && gaps.length) {
        check.timeToCommit = rev
          ? { entries: gaps.length, shortestSeconds: Math.min(...gaps.map((g) => g.seconds)), longestSeconds: Math.max(...gaps.map((g) => g.seconds)), eachEntry: EVIDENCE_LEFT_OUT_V1 }
          : gaps.map((g) => ({ ...refOf(g), happened: g.happened, happenedAccordingTo: g.happenedAccordingTo, committed: g.committed, seconds: g.seconds }));
      }
      return check;
    }),
    writtenBy:
      typeof input.writtenBy === 'string'
        ? input.writtenBy
        : input.writtenBy.map((w) => ({
            runs: typeof w.runs === 'string' ? w.runs : w.runs.map((v) => ({ version: v.version, from: v.from, model: v.model, builtOn: v.builtOn, runtime: v.runtime, guardrails: v.guardrails, records: [...v.records] })),
            statedBy: w.statedBy,
            checkedByPacSpace: false as const,
          })),
    readerAgent: !rev && input.readerAgent ? { name: input.readerAgent.name, since: input.readerAgent.since } : null,
    withheldFromPublication: {
      categories: input.withheldFromPublication.categories.map((c) => ({ committed: c.committed, list: [...c.list] })),
      entries: input.withheldFromPublication.entries.map((e) => ({ ...refOf(e), category: e.category, committed: e.committed, by: e.by, label: e.label })),
    },
    requests: input.requests.map((q) => ({
      ref: q.ref,
      at: q.at,
      sentBy: q.sentBy,
      spread: q.spread,
      sample: q.sample
        ? {
            method: q.sample.method,
            seed: q.sample.seed,
            randomPicks: q.sample.randomPicks,
            spread: q.sample.spread,
            pool: q.sample.pool.map((p) => ({ record: p.record, entries: p.entries, openedOn: p.openedOn })),
            poolDigest: q.sample.poolDigest,
            leftOut: q.sample.leftOut.map(refOf),
            removedByTheReader: q.sample.removedByTheReader.map(refOf),
            readersMethod: copy(q.sample.readersMethod ?? null),
          }
        : null,
      linkAnswersWithin: q.linkAnswersWithin,
      picks: q.picks.map((p) => ({ ...refOf(p), picked: p.picked, countsAgainstSample: p.countsAgainstSample, seal: p.seal })),
      question: q.question,
      answered: q.answered,
    })),
    answers: input.answers.map((a) => {
      const answer: EvidenceAnswerV1 = {
        request: a.request,
        at: a.at,
        sentBy: a.sentBy,
        approvedBy: a.approvedBy,
        reply: rev ? null : a.reply,
        declaredFields: { asDeclared: a.declaredFields.asDeclared },
        entries: a.entries.map((x) => {
          if ('declined' in x) return { ...refOf(x), declined: { reason: x.declined.reason, note: rev ? null : x.declined.note, day: x.declined.day } };
          if ('notOpenedOnThisDevice' in x) return { ...refOf(x), notOpenedOnThisDevice: true as const };
          const shown: EvidenceAnswerEntryV1 = { ...refOf(x), seal: x.seal, committed: x.committed, recomputed: x.recomputed, matchesSeal: x.matchesSeal };
          if (!rev && x.fields !== undefined) shown.fields = copy(x.fields);
          if (!rev && x.disclosure !== undefined) shown.disclosure = copy(x.disclosure);
          return shown;
        }),
      };
      if (rev && a.reply !== null) answer.replyLeftOut = true;
      return answer;
    }),
    acknowledgments: input.acknowledgments.map((k) => ({
      ref: k.ref,
      at: k.at,
      sentBy: k.sentBy,
      check: k.check,
      note: k.note,
      ...(k.noteSealed === true ? { noteSealed: true as const } : {}),
      flags: k.flags.map((f) => ({ ...refOf(f), result: f.result, note: f.note, ...(f.noteSealed === true ? { noteSealed: true as const } : {}) })),
      signed: k.signed
        ? {
            body: copy(k.signed.body),
            signature: k.signed.signature,
            mldsaSignature: k.signed.mldsaSignature,
            p256Jwk: { kty: k.signed.p256Jwk.kty, crv: k.signed.p256Jwk.crv, x: k.signed.p256Jwk.x, y: k.signed.p256Jwk.y },
            mldsaPublicKey: k.signed.mldsaPublicKey,
          }
        : null,
    })),
    flags: input.flags.map((f) => ({ ...refOf(f), result: f.result, note: f.note, sentIn: f.sentIn })),
    devices: input.devices.map((d) => ({ code: d.code, kind: d.kind, status: d.status, addedOn: d.addedOn })),
    indexRecord: input.indexRecord ? { sealHistory: copy(input.indexRecord.sealHistory), disclosure: copy(input.indexRecord.disclosure) } : null,
    readerRecord: input.readerRecord ? { sealHistory: copy(input.readerRecord.sealHistory), disclosure: copy(input.readerRecord.disclosure) } : null,
    statement: input.statement,
    whatACheckShows: input.whatACheckShows,
    notes: rev ? [...input.notes, evidenceForReviewersNoteV1(input.sharedBy)] : [...input.notes],
    checkAgain: {
      checker: input.checkAgain.checker,
      package: input.checkAgain.package,
      version: input.checkAgain.version,
      reads: input.checkAgain.reads,
      open: input.checkAgain.open,
      keptCopy: input.checkAgain.keptCopy,
      thePageItself: input.checkAgain.thePageItself,
      ...(input.checkAgain.inTheNextRelease ? { inTheNextRelease: [...input.checkAgain.inTheNextRelease] } : {}),
    },
  };
  if (input.flagThreads !== undefined) out.flagThreads = input.flagThreads.map((t) => ({ ref: t.ref, ...refOf(t), result: t.result, status: t.status, events: t.events.map((e) => flagEventOf(e, rev)) }));
  if (!rev && input.linkRevealedLater !== undefined) out.linkRevealedLater = input.linkRevealedLater.map((x) => ({ record: x.record, day: x.day }));
  if (!rev && input.linkNotRevealedYet !== undefined) out.linkNotRevealedYet = [...input.linkNotRevealedYet];
  const problems = [...sharedRecordEvidenceV1KeyProblems(out), ...sharedRecordEvidenceV1NeutralityProblems(out, forbidden)];
  if (problems.length) throw new SharedRecordEvidenceShapeError(problems);
  return out;
}

/** One thread event, member by member; For reviewers keeps who answered and when, and leaves the answer's words out. */
function flagEventOf(e: EvidenceFlagEventV1, rev: boolean): EvidenceFlagEventV1 {
  switch (e.kind) {
    case 'flagged':
      return { kind: 'flagged', at: e.at, in: e.in, note: e.note, ...(e.noteSealed === true ? { noteSealed: true as const } : {}) };
    case 'answered':
      return rev ? { kind: 'answered', at: e.at, by: e.by, leftOut: true } : { kind: 'answered', at: e.at, by: e.by, text: e.text ?? null };
    case 'replied':
      return { kind: 'replied', at: e.at, text: e.text };
    case 'closed':
      return { kind: 'closed', at: e.at };
  }
}

/** A whole `csh1_` handle: the file names a link by its handle's prefix only (13 characters and `...`). */
const WHOLE_HANDLE = /csh1_[A-Za-z0-9_-]{9,}/;
/** Bearer tokens, codes and session ids the link's routes answer with. */
// A code stands alone: '_' and '-' join base64url tokens, which can hold the code's shape by chance.
const SECRETS = [/(?<![A-Za-z0-9_-])[A-Z2-9]{4}-[A-Z2-9]{4}(?![A-Za-z0-9_-])/, /#dk=|#t=/, /\bsess_[A-Za-z0-9]+/];
/** Keys and signatures as encoded bytes: random text that can spell any word, so only the secret patterns apply. */
const ENCODED = new Set(
  ['acknowledgments[].signed', 'signature', 'signature.device'].flatMap((at) =>
    ['signature', 'mldsaSignature', 'mldsaPublicKey', 'xwingPublicKey', 'p256Jwk.x', 'p256Jwk.y'].map((k) => `${at}.${k}`),
  ),
);

/**
 * The evidence's neutrality rules (the prototype's `tests/shared_record.py:55`, and this plan's stricter one): no key
 * or value of the evidence's own members holds the word "trail" or any of the `forbidden` words (the reader's name and
 * organisation, the trail's name, its labels and sources, the environment); there is no top-level `rule` or `trail`
 * key; and nowhere, another form's members included, is there a whole handle, an access code, a link fragment or a
 * session id. The members of another form carried whole (a seal history, a disclosure's fields, a signed body) are the
 * lab's content or that form's own, and are checked by that form's reader.
 */
export function sharedRecordEvidenceV1NeutralityProblems(evidence: unknown, forbidden: readonly string[] = []): string[] {
  const problems: string[] = [];
  if (isPlain(evidence)) for (const key of ['rule', 'trail']) if (key in evidence) problems.push(`${key}: a top-level ${key} key`);
  const words = forbidden.filter((w) => w.trim().length > 0);
  const scan = (text: string, where: string, own: boolean) => {
    if (WHOLE_HANDLE.test(text)) problems.push(`${where}: holds a whole handle`);
    for (const pattern of SECRETS) if (pattern.test(text)) problems.push(`${where}: holds a code, a link fragment or a session id`);
    if (!own) return;
    if (/trail/i.test(text)) problems.push(`${where}: holds the word trail`);
    for (const word of words) if (text.toLowerCase().includes(word.toLowerCase())) problems.push(`${where}: holds a forbidden word`);
  };
  const walk = (value: unknown, path: string, own: boolean): void => {
    const mine = own && !OPAQUE.has(path) && !ENCODED.has(path);
    if (typeof value === 'string') {
      scan(value, path || '(root)', mine);
      return;
    }
    if (Array.isArray(value)) {
      for (const v of value) walk(v, `${path}[]`, mine);
      return;
    }
    if (!isPlain(value)) return;
    for (const [key, v] of Object.entries(value)) {
      const at = path ? `${path}.${key}` : key;
      scan(key, `${at} (key)`, mine);
      walk(v, at, mine);
    }
  };
  walk(evidence, '', true);
  return [...new Set(problems)];
}

/** The text both of the signing device's signatures cover: the label, a line break, and the JCS of every member but `signature`. */
export function sharedRecordEvidenceSigningMessageV1(evidence: SharedRecordEvidenceV1): string {
  const rest: Record<string, unknown> = { ...evidence };
  delete rest.signature;
  return `${SHARED_RECORD_EVIDENCE_SIGNING_LABEL_V1}\n${canonicalizeJcs(rest)}`;
}

/** The evidence with its signature member, made over `sharedRecordEvidenceSigningMessageV1`. */
export function withEvidenceSignatureV1(evidence: SharedRecordEvidenceV1, signature: Omit<EvidenceSignatureV1, 'alg'>): SharedRecordEvidenceV1 {
  const { signature: _old, ...rest } = evidence;
  return {
    ...rest,
    signature: {
      alg: ['ES256', 'ML-DSA-65'],
      device: { xwingPublicKey: signature.device.xwingPublicKey, p256Jwk: { ...signature.device.p256Jwk }, mldsaPublicKey: signature.device.mldsaPublicKey },
      signature: signature.signature,
      mldsaSignature: signature.mldsaSignature,
    },
  };
}

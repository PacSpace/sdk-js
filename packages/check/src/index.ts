/**
 * @pacspace-io/check: the checker a printed statement names (records buyer
 * posture plan, DfD-39 (A)). With a record's history file and the
 * fingerprint on the statement, the check can be run without the link,
 * without PacSpace, against the public source alone.
 */
export {
  CHECKER_NAME,
  CHECKER_VERSION,
  checkHistory,
  HISTORY_SCHEMAS,
  HistoryFileError,
  parseHistoryFile,
  revealsFileFingerprint,
} from './check';
export type { CheckOptions, HistoryFile, HistorySchema, StatementSequence } from './check';
export { checkRelease, DEFAULT_RELEASE_ORIGIN, releaseWords, RELEASES_SCHEMA, RELEASE_MANIFEST_FORMAT } from './release';
export type { ReleaseDifference, ReleaseOptions, ReleaseReport } from './release';
export {
  buildReport,
  buildSealsReport,
  countedSentence,
  dailyStatementSentence,
  dayOfUtc,
  fingerprintSentence,
  FILE_CHANGED_SENTENCE,
  HONESTY_SENTENCE,
  renderReport,
  REPORT_SCHEMA,
  SEALS_BOUNDARY_SENTENCE,
  sourceSentence,
} from './report';
export type {
  CheckReport,
  DailyStatementOutcome,
  DisclosureOutcome,
  HeldFileOutcome,
  ReportInput,
  SealsReportInput,
  SourceOutcome,
  VerificationFacts,
} from './report';

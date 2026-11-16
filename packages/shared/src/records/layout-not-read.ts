/**
 * A file written under a record layout this version does not carry.
 *
 * The checker, the SDKs and the browser carry the layouts
 * docs/spec/records/carried-layouts.json names. A history, a kept copy, a
 * seal history or a link copy that names any other layout id cannot be
 * checked by them: its fields, lifecycle and seal rules are not held here.
 * Each verifier reports that with this code and sentence, after the file's
 * own digest check, so a file that does not hold together is still reported
 * as changed. It is never a pass.
 */
export const RECORDS_LAYOUT_NOT_READ = 'RECORDS_LAYOUT_NOT_READ';
export const RECORDS_LAYOUT_NOT_READ_SENTENCE =
  'This file was written under a record layout this version does not read, so it could not be checked.';

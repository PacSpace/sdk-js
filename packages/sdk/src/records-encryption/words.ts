import { PacSpaceError } from '../errors';

/**
 * The SDK's refusals for encrypted records (L2d words list, W-L2d-23 to 37):
 * the same codes and sentences in TypeScript and Python. A sentence never
 * carries key bytes; an entry is named by its number, counting from 1.
 */
export const RECORDS_ENCRYPTION_WORDS = {
  RECORDS_SECRET_REQUIRED: 'Encrypted records need the workspace secret. Pass it as records.secret or records.secretProvider.',
  RECORDS_SECRET_INVALID: "The workspace secret isn't a pacspace-workspace-secret/v1 file this version reads.",
  RECORDS_VERSION_NOT_HELD: "This record is under version {v}, which this workspace secret doesn't hold.",
  RECORDS_ENTRY_UNOPENED: "Entry {seq} didn't open. The record or the workspace secret is not the one expected.",
  RECORDS_ENTRY_HASH_MISMATCH: "Entry {seq} opened, but its content doesn't match its sealed record hash.",
  RECORDS_ENTRY_REFS_MISMATCH: "Entry {seq} opened, but the entries it amends or references don't match the ones stored with it.",
  RECORDS_HISTORY_OTHER_RECORD: 'The history served is for another record. Nothing was opened.',
  RECORDS_CODE_REQUIRED: "Confirm this workspace's code with them outside PacSpace first, then pass it as confirmedCode.",
  RECORDS_CODE_MISMATCH: "The code computed for this workspace doesn't match the one confirmed. Nothing was wrapped. Confirm the code with them again.",
  RECORDS_PIN_CHANGED: "This workspace's identity changed since its code was confirmed. Nothing was wrapped. Confirm the new code with them.",
  RECORDS_NOT_ENCRYPTED: "This record isn't encrypted. Keep its history file instead.",
  RECORDS_LINK_NO_KEY: 'This link has no key after # and no wrap for your workspace.',
  RECORDS_REKEY_STOPPED: 'Re-encryption stopped at entry {seq}. Entries after it are done; run it again to finish.',
  RECORDS_ROTATE_NOT_NEXT: 'The new workspace secret must add exactly the next version and keep every earlier one.',
  RECORDS_IDENTITY_OTHER: "This workspace already registered another identity, which this workspace secret doesn't open.",
} as const;

export type RecordsEncryptionCode = keyof typeof RECORDS_ENCRYPTION_WORDS;

/** A client-side refusal on an encrypted path: a code and its sentence, never a key. */
export class RecordsEncryptionError extends PacSpaceError {
  constructor(code: RecordsEncryptionCode, values: { v?: number | string; seq?: number | string } = {}) {
    const sentence = RECORDS_ENCRYPTION_WORDS[code]
      .replace('{v}', String(values.v ?? ''))
      .replace('{seq}', String(values.seq ?? ''));
    super(sentence, 0, code);
    this.name = 'RecordsEncryptionError';
  }
}

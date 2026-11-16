/**
 * Encrypted records for a browser (L2e design v2, D5): the same client the
 * SDK uses, with no Node module on its path. A key page passes its own
 * transport, keys and pin store; nothing here is a second client.
 */
export {
  EncryptedRecords,
  RECORDS_GRANT_HEADER,
  RECORDS_HOLDER_HEADER,
  RECORDS_STEP_UP_HEADER,
  RECORDS_SUPPORT_HEADER,
  recordPathOf,
  type KeyChange,
} from './encrypted-records';
export { RecordsKeys, keyringOf, type Keyring } from './keys';
export { loadRecordsCrypto, type RecordsCrypto } from './loader';
export { memoryPinStore, type RecordsPin, type RecordsPinStore } from './pin-store';
export { transportError, type RecordsTransport } from './transport';
export { RECORDS_ENCRYPTION_WORDS, RecordsEncryptionError, type RecordsEncryptionCode } from './words';
export { generateWorkspaceSecret, nextWorkspaceSecret } from './workspace-secret';
export { PacSpaceError } from '../errors';

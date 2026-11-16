/**
 * records-crypto: the blinded fingerprint (`hmac-sha-256`), its blinding file
 * and the held-file rule (slot-encoding-v1 sections 6.1 and 6.2). Pure, no
 * I/O. Two real HMAC implementations, picked by runtime; no caller can pick.
 */
import type { PayloadByteSource, PayloadRefV1 } from '../proof/payload-ref-v1';
import { BLINDING_VALUE_BYTES, isNodeRuntime, loadNodeCrypto } from './blinding-value';
import { hmacNode } from './hmac-node';
import { hmacWeb } from './hmac-web';

export { BLINDING_FILE_SCHEMA_V1 } from '../proof/payload-ref-v1';
export { BLINDING_VALUE_BYTES, BlindingError, assertBlindingValue } from './blinding-value';
export {
  BLINDING_FILE_MAX_BYTES,
  parseBlindingFile,
  serializeBlindingFile,
  type BlindingFileRefusal,
  type BlindingFileV1,
  type ParsedBlindingFile,
} from './blinding-file';
export { matchHeldFile, type HeldFile, type HeldFileMatch } from './held-file';
export * from './record-hash-v2';
export * from './record-hash-v3';
export * from './record-disclosure-v1';
export * from './disclosure-envelope-v1';
export * from './wrap-shapes-v1';
export {
  RECORDS_ENCRYPTION_LABELS_V1,
  RECORDS_ENCRYPTION_PAD_BLOCK_V1,
  RECORD_ENTRY_PLAINTEXT_MAX_BYTES_V1,
  RECORD_ENTRY_CIPHERTEXT_MAX_BYTES_V1,
  RECORD_ENTRY_CIPHERTEXT_MAX_CHARS_V1,
  RECORD_ENTRY_BODY_MAX_BYTES_V1,
  RECORDS_KEYRING_MAX_BYTES_V1,
  RECORDS_KEYRING_SCHEMA_V1,
  WORKSPACE_SECRET_BYTES_V1,
  RecordsEncryptionError,
  RecordsIdKeyV1,
  RecordsKeyV1,
  RecordsWrapKeyV1,
  RecordKeyV1,
  RecordsContentTagKeyV2,
  RECORDS_CONTENT_TAG_LABELS_V2,
  RecordsKeyringV1,
  exportKeyBytesV1,
  generateWorkspaceSecretV1,
  deriveRecordsIdKeyV1,
  deriveRecordsKeysV1,
  importWorkspaceSecretKeyV1,
  deriveRecordsIdKeyFromBaseV1,
  deriveRecordsKeysFromBaseV1,
  recordKeyOfV1,
  recordKeyFromBytesV1,
  recordsKeyFromBytesV1,
  wireRecordIdV1,
  wireReferenceIdV1,
  contentTagV1,
  contentTagV2,
  recordEntryPlaintextV1,
  padRecordEntryV1,
  sealRecordEntryV1,
  readRecordEnvelopeShapeV1,
  openRecordEntryEnvelopeV1,
  encryptedWriteBodyBytesV1,
  checkEncryptedWriteSizeV1,
  entryRefsMatchV1,
  localRecordsKeyProviderV1,
  serializeRecordsKeyringFileV1,
  parseRecordsKeyringFileV1,
  type RecordsEncryptionCodeV1,
  type RecordsRefusalV1,
  type RecordEntryEnvelopeV1,
  type OpenRecordEntryResultV1,
  type RecordsKeyProviderV1,
  type RecordsBaseKeyProviderV1,
} from './records-encryption-v1';

/**
 * `node:crypto` when the runtime says Node and the module loads; otherwise
 * null, and WebCrypto is used (as digestPayload falls back).
 */
async function nodeCryptoOrNull(): Promise<typeof import('node:crypto') | null> {
  if (!isNodeRuntime()) return null;
  try {
    return await loadNodeCrypto();
  } catch {
    return null;
  }
}

/** HMAC-SHA256 of the source's bytes under a 32-byte blinding value, as a payload reference. */
export async function blindedDigest(source: PayloadByteSource, value: Uint8Array): Promise<PayloadRefV1> {
  return ((await nodeCryptoOrNull()) ? hmacNode : hmacWeb).blindedDigest(source, value);
}

/** 32 fresh random bytes. */
export async function newBlindingValue(): Promise<Uint8Array> {
  const nodeCrypto = await nodeCryptoOrNull();
  if (nodeCrypto) return new Uint8Array(nodeCrypto.randomBytes(BLINDING_VALUE_BYTES));
  return globalThis.crypto.getRandomValues(new Uint8Array(BLINDING_VALUE_BYTES));
}

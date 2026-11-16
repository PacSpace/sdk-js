import { canonicalizeJcs } from '../proof/jcs';
import type { LayoutRegistry } from '../proof/slot-encoding-v1';
import { sha256, utf8 } from '../records-crypto/platform-crypto';
import {
  RECORD_DISCLOSURE_MAX_BYTES_V1,
  verifyRecordDisclosureV1,
  type ChainBatchRootsV1,
  type RecordDisclosure,
  type RecordDisclosureVerificationV1,
} from '../records-crypto/record-disclosure-v1';
import {
  RECORD_SEAL_HISTORY_MAX_BYTES_V1,
  RECORD_SEAL_HISTORY_SCHEMA_V1,
  disclosureFormOfV1,
  verifyRecordSealHistoryV1,
  type RecordSealHistoryV1,
  type SealHistoryVerificationV1,
} from './record-seal-history-v1';

/**
 * record-link-copy/v1 (seals-first design, section 5.8): what "Keep a copy"
 * saves on a disclosure link. The seal history form and the decrypted
 * disclosure (or null), saved as the UTF-8 bytes of its JCS form. Its
 * SHA-256, as 64 lowercase hex characters with no prefix, is what the
 * acknowledgment names, so one value names both digests inside it.
 */
export const RECORD_LINK_COPY_SCHEMA_V1 = 'record-link-copy/v1' as const;
export const RECORD_LINK_COPY_MAX_BYTES_V1 = RECORD_SEAL_HISTORY_MAX_BYTES_V1 + RECORD_DISCLOSURE_MAX_BYTES_V1 + 1024;

export interface RecordLinkCopyV1 {
  schema: typeof RECORD_LINK_COPY_SCHEMA_V1;
  sealHistory: RecordSealHistoryV1;
  disclosure: RecordDisclosure | null;
}

export class RecordLinkCopyError extends Error {
  constructor(readonly code: 'LINK_COPY_MALFORMED') {
    super('This is not a kept copy this version can read.');
    this.name = 'RecordLinkCopyError';
  }
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const hasExactly = (v: Record<string, unknown>, keys: readonly string[]) => {
  const own = Object.keys(v);
  return own.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(v, k));
};
const toHex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function sameRecord(sealHistory: RecordSealHistoryV1, disclosure: RecordDisclosure): boolean {
  return (
    String(disclosure.recordKey).toLowerCase() === sealHistory.recordKey &&
    disclosure.chain?.chainId === sealHistory.chain.chainId &&
    String(disclosure.chain?.contractAddress).toLowerCase() === sealHistory.chain.contractAddress &&
    disclosure.layout?.layoutId === sealHistory.layout.layoutId &&
    disclosure.layout?.layoutVersion === sealHistory.layout.layoutVersion &&
    String(disclosure.layout?.layoutDigest).toLowerCase() === sealHistory.layout.layoutDigest
  );
}

/** The copy, its bytes (utf8 of its JCS form), their SHA-256 as 64 lowercase hex, and their length. */
export async function buildRecordLinkCopyV1(input: {
  sealHistory: RecordSealHistoryV1;
  disclosure: RecordDisclosure | null;
}): Promise<{ copy: RecordLinkCopyV1; bytes: Uint8Array; sha256: string; byteLength: number }> {
  if (!input || !isPlainObject(input.sealHistory) || input.sealHistory.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1) {
    throw new RecordLinkCopyError('LINK_COPY_MALFORMED');
  }
  if (input.disclosure !== null && !sameRecord(input.sealHistory, input.disclosure)) {
    throw new RecordLinkCopyError('LINK_COPY_MALFORMED');
  }
  const copy: RecordLinkCopyV1 = {
    schema: RECORD_LINK_COPY_SCHEMA_V1,
    sealHistory: input.sealHistory,
    disclosure: input.disclosure,
  };
  const bytes = utf8(canonicalizeJcs(copy));
  return { copy, bytes, sha256: toHex(await sha256(bytes)), byteLength: bytes.length };
}

/** Checks the copy's shape: exactly its three members, the seal history's schema, a disclosure or null. */
export function readRecordLinkCopyV1(json: unknown): { ok: true; copy: RecordLinkCopyV1 } | { ok: false; code: 'LINK_COPY_MALFORMED' } {
  const refuse = { ok: false as const, code: 'LINK_COPY_MALFORMED' as const };
  if (!isPlainObject(json) || !hasExactly(json, ['schema', 'sealHistory', 'disclosure'])) return refuse;
  if (json.schema !== RECORD_LINK_COPY_SCHEMA_V1) return refuse;
  if (!isPlainObject(json.sealHistory) || json.sealHistory.schema !== RECORD_SEAL_HISTORY_SCHEMA_V1) return refuse;
  if (json.disclosure !== null && !isPlainObject(json.disclosure)) return refuse;
  return { ok: true, copy: json as unknown as RecordLinkCopyV1 };
}

/**
 * What the checker runs offline (L1d): the seal history first, then, if it
 * passed and a disclosure is present, R2's verifier against its form, with
 * roots read from the chain by the caller.
 */
export async function verifyRecordLinkCopyV1(
  copy: RecordLinkCopyV1,
  options: { layouts: LayoutRegistry; chainWord?: string | null; chainRoots: ChainBatchRootsV1 },
): Promise<{ sealHistory: SealHistoryVerificationV1; disclosure: RecordDisclosureVerificationV1 | null; formUnavailable: boolean }> {
  const sealHistory = verifyRecordSealHistoryV1(copy.sealHistory, { layouts: options.layouts, chainWord: options.chainWord });
  if (!sealHistory.verified || copy.disclosure === null) return { sealHistory, disclosure: null, formUnavailable: false };
  const form = disclosureFormOfV1(copy.sealHistory, copy.disclosure);
  if (!form) return { sealHistory, disclosure: null, formUnavailable: true };
  const disclosure = await verifyRecordDisclosureV1({ form, chainRoots: options.chainRoots, disclosure: copy.disclosure });
  return { sealHistory, disclosure, formUnavailable: false };
}

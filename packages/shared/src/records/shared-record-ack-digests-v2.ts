/**
 * The two digests a `shared-record-ack/v2` body names (records prototype build, R7; David, 2026-10-28, "A, for
 * internal, keccak256 is ok"), so the reader's signature binds what the check read: every record's seal history, and
 * every disclosure it opened. Each is keccak256 over the JCS of a labelled list, each item's digest worked out from the
 * form itself, never read from it. The reader's browser, the scripted reader and the checker all use these. Kept apart
 * from `shared-record-ack-v2.ts`, which loads no hashing library.
 */
import { ethers } from 'ethers';
import { canonicalizeJcs } from '../proof/jcs';
import { computeRecordDisclosureDigest, type RecordDisclosure } from '../records-crypto/record-disclosure-v1';
import { computeSealHistoryDigestV1, type RecordSealHistoryV1 } from './record-seal-history-v1';

export const SHARED_RECORD_ACK_SEAL_HISTORIES_LABEL_V2 = 'pacspace:shared-record-ack:seal-histories:v2';
export const SHARED_RECORD_ACK_DISCLOSURES_LABEL_V2 = 'pacspace:shared-record-ack:disclosures:v2';

export class SharedRecordAckDigestError extends Error {
  constructor() {
    super('SHARED_RECORD_ACK_DIGEST_INPUT');
    this.name = 'SharedRecordAckDigestError';
  }
}

const keccakOfJcs = (value: unknown): string => ethers.keccak256(ethers.toUtf8Bytes(canonicalizeJcs(value)));
const isRecordNumber = (n: unknown): n is number => Number.isInteger(n) && (n as number) >= 1;

/**
 * `sealHistoryDigest`: keccak256(JCS({label, records: [{record, digest}]})), one item per record the check read, in
 * record order, each `digest` the record's seal history digest (`computeSealHistoryDigestV1`), lowercase.
 */
export function sharedRecordAckSealHistoryDigestV2(records: ReadonlyArray<{ record: number; sealHistory: RecordSealHistoryV1 }>): string {
  if (!Array.isArray(records) || records.length === 0 || records.some((r) => !isRecordNumber(r?.record))) throw new SharedRecordAckDigestError();
  const list = records.map((r) => ({ record: r.record, digest: computeSealHistoryDigestV1(r.sealHistory).toLowerCase() })).sort((a, b) => a.record - b.record);
  if (list.some((x, i) => i > 0 && list[i - 1].record === x.record)) throw new SharedRecordAckDigestError();
  return keccakOfJcs({ label: SHARED_RECORD_ACK_SEAL_HISTORIES_LABEL_V2, records: list });
}

/**
 * `disclosureDigest`: keccak256(JCS({label, disclosures: [{request, record, digest}]})) over each disclosure the check
 * opened, a record's reveal with `request` null and an answer's with its request's reference, each `digest` the
 * disclosure's own (`computeRecordDisclosureDigest`), lowercase. The same disclosure listed twice counts once. Items
 * sort by request (a reveal first), then record, then digest. Null when the check opened none.
 */
export async function sharedRecordAckDisclosureDigestV2(
  disclosures: ReadonlyArray<{ request: string | null; record: number; disclosure: RecordDisclosure }>,
): Promise<string | null> {
  if (!Array.isArray(disclosures)) throw new SharedRecordAckDigestError();
  if (disclosures.length === 0) return null;
  if (disclosures.some((d) => !isRecordNumber(d?.record) || (d.request !== null && typeof d.request !== 'string'))) throw new SharedRecordAckDigestError();
  const items = await Promise.all(disclosures.map(async (d) => ({ request: d.request, record: d.record, digest: (await computeRecordDisclosureDigest(d.disclosure)).toLowerCase() })));
  const unique = [...new Map(items.map((x) => [JSON.stringify([x.request, x.record, x.digest]), x])).values()];
  unique.sort((a, b) => {
    if (a.request !== b.request) return a.request === null ? -1 : b.request === null ? 1 : a.request < b.request ? -1 : 1;
    if (a.record !== b.record) return a.record - b.record;
    return a.digest < b.digest ? -1 : a.digest > b.digest ? 1 : 0;
  });
  return keccakOfJcs({ label: SHARED_RECORD_ACK_DISCLOSURES_LABEL_V2, disclosures: unique });
}

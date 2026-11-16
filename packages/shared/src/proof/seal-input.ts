import { ethers } from 'ethers';
import { normalizeProofHash } from './merkle-v2';

/**
 * The hash a seal is computed over (card 10, F1; record-hash spec, sealing).
 * Versions 1 and 2 seal the record hash itself. Version 3 seals
 * SHA-256("pacspace:record-hash-version:v1" || 0x00 || u8(3) || recordHash),
 * so a record's hash version is fixed on the ledger: a v3 hash read as v2, or
 * a v2 hash read as v3, reproduces no seal. Rows, receipts and forms carry the
 * raw record hash; only the seal's input is wrapped.
 *
 * A verifier passes 3 only for a hash it recomputed under the v3 member
 * algorithm, or on a seal-only path that claims no content.
 */
export type SealedRecordHashVersion = 1 | 2 | 3;

const LABEL = 'pacspace:record-hash-version:v1';

export function sealInputHash(version: SealedRecordHashVersion, recordHash: string): string {
  const hash = normalizeProofHash(recordHash, 'recordHash');
  if (version === 1 || version === 2) return hash;
  if (version !== 3) throw new Error(`record hash version ${String(version)} has no seal input`);
  return ethers.sha256(ethers.concat([ethers.toUtf8Bytes(LABEL), new Uint8Array([0, 3]), ethers.getBytes(hash)]));
}

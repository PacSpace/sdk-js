import { ethers } from 'ethers';
import { normalizeProofHash } from './merkle-v2';

/**
 * Ledger head (ADR 0012 section 3; slot-encoding-v1 section 13).
 *
 *   newHead = keccak256(abi.encode(previousHead, merkleRoot, batchId))
 *
 * One head per tenant contract, advanced on every batch commit on either lane
 * in the frame that stores the root, and emitted as
 * `LedgerHeadAdvanced(batchId, merkleRoot, previousHead, newHead)`.
 */

export interface LedgerBatchRef {
  batchId: number | bigint | string;
  merkleRoot: string;
}

export function nextLedgerHeadV1(previousHead: string, merkleRoot: string, batchId: number | bigint | string): string {
  const prev = normalizeProofHash(previousHead, 'previousHead');
  const root = normalizeProofHash(merkleRoot, 'merkleRoot');
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(['bytes32', 'bytes32', 'uint256'], [prev, root, BigInt(batchId)]),
  );
}

/** Heads after each batch, starting with the genesis head at index 0. */
export function recomputeLedgerHeadsV1(genesisHead: string, batches: LedgerBatchRef[]): string[] {
  const heads = [normalizeProofHash(genesisHead, 'genesisHead')];
  for (const b of batches) heads.push(nextLedgerHeadV1(heads[heads.length - 1], b.merkleRoot, b.batchId));
  return heads;
}

export interface LedgerChainCheck {
  verified: boolean;
  recomputedHead: string;
  passesThrough: boolean;
  endsAtExpected: boolean;
  reason: string;
}

/**
 * Verify that a receipt's (batchId, proofRoot) sits in a ledger described by
 * its batches from genesis, and that the recomputed chain ends at the head
 * read from the contract.
 */
export function verifyLedgerChainV1(input: {
  genesisHead: string;
  batches: LedgerBatchRef[];
  expectedHead: string;
  receipt: { batchId: number | bigint | string; proofRoot: string };
}): LedgerChainCheck {
  const heads = recomputeLedgerHeadsV1(input.genesisHead, input.batches);
  const recomputedHead = heads[heads.length - 1];
  const endsAtExpected = recomputedHead === normalizeProofHash(input.expectedHead, 'expectedHead');
  const wantId = BigInt(input.receipt.batchId);
  const wantRoot = normalizeProofHash(input.receipt.proofRoot, 'proofRoot');
  const passesThrough = input.batches.some(
    (b) => BigInt(b.batchId) === wantId && normalizeProofHash(b.merkleRoot, 'merkleRoot') === wantRoot,
  );
  const verified = endsAtExpected && passesThrough;
  return {
    verified,
    recomputedHead,
    passesThrough,
    endsAtExpected,
    reason: verified
      ? 'The batch sits unaltered in the ledger and the chain ends at the current head.'
      : !passesThrough
        ? 'No batch on the chain carries this receipt batch id and root.'
        : 'The recomputed head chain does not end at the head read from the contract.',
  };
}

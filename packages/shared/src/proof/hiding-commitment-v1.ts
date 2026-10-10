import { ethers } from 'ethers';
import {
  buildMerkleProofV2,
  computeMerkleItemsRootV2,
  normalizeProofHash,
} from './merkle-v2';

/**
 * Per-item hiding commitments (ADR 0008 §4).
 *
 * The canonical content fingerprint (`itemHash`) is unchanged. What gets
 * published is a position-bound hiding commitment derived from the fingerprint
 * plus a per-item opening, where every opening is derived from one random
 * per-batch seed:
 *
 *   itemOpening[i] = HMAC-SHA256(batchSeed,
 *     "pacspace:item-opening:v1" || 0x00 || uint32be(i) || itemHash[i])
 *
 *   publishedLeaf[i] = keccak256(
 *     "pacspace:published-leaf:v1" || 0x00 || uint32be(i) || itemHash[i]
 *     || itemOpening[i])
 *
 * The published root is the existing pair-sorted-keccak-v2 Merkle root over
 * `publishedLeaf[]`, never over raw fingerprints. A receipt disclosed for one
 * item carries only that item's index, opening, and proof path; sibling nodes
 * are themselves hiding commitments, so no other event's raw fingerprint is
 * ever disclosed.
 *
 * This module is intentionally implemented with ethers primitives only
 * (keccak256, computeHmac, randomBytes) so the verifier half stays usable in
 * browser bundles for independent, offline receipt verification.
 */

/**
 * Anchor-level proof algorithm identifier recorded for batches and
 * checkpoints whose published root commits to hiding commitments.
 */
export const PROOF_ALGORITHM_HIDING_COMMITMENT_V1 = 'hiding-commitment-v1';

const OPENING_DOMAIN = ethers.toUtf8Bytes('pacspace:item-opening:v1');
const LEAF_DOMAIN = ethers.toUtf8Bytes('pacspace:published-leaf:v1');
const SEPARATOR = new Uint8Array([0x00]);

function uint32be(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`item index ${value} is out of uint32 range.`);
  }
  const bytes = new Uint8Array(4);
  bytes[0] = (value >>> 24) & 0xff;
  bytes[1] = (value >>> 16) & 0xff;
  bytes[2] = (value >>> 8) & 0xff;
  bytes[3] = value & 0xff;
  return bytes;
}

/**
 * Generate a cryptographically random 32-byte batch or checkpoint seed.
 * The seed is availability-critical for receipt re-issuance: it must be
 * persisted encrypted at rest and must never appear in an API response,
 * log line, receipt, or calldata.
 */
export function generateBatchSeedV1(): string {
  return ethers.hexlify(ethers.randomBytes(32));
}

/**
 * Derive the undisclosed opening for one item position.
 */
export function deriveItemOpeningV1(
  batchSeed: string,
  itemIndex: number,
  itemHash: string,
): string {
  const seed = normalizeProofHash(batchSeed, 'batchSeed');
  const hash = normalizeProofHash(itemHash, 'itemHash');
  const message = ethers.concat([
    OPENING_DOMAIN,
    SEPARATOR,
    uint32be(itemIndex),
    ethers.getBytes(hash),
  ]);
  return ethers.computeHmac('sha256', seed, message);
}

/**
 * Compute the position-bound published leaf for one item.
 */
export function computePublishedLeafV1(
  itemIndex: number,
  itemHash: string,
  itemOpening: string,
): string {
  const hash = normalizeProofHash(itemHash, 'itemHash');
  const opening = normalizeProofHash(itemOpening, 'itemOpening');
  const message = ethers.concat([
    LEAF_DOMAIN,
    SEPARATOR,
    uint32be(itemIndex),
    ethers.getBytes(hash),
    ethers.getBytes(opening),
  ]);
  return ethers.keccak256(message);
}

export interface HidingCommitmentBatchV1 {
  /** One undisclosed opening per item position. Receipt material only. */
  itemOpenings: string[];
  /** Position-bound hiding commitments; these are the published leaves. */
  publishedLeaves: string[];
  /** pair-sorted-keccak-v2 root over publishedLeaves. */
  publishedRoot: string;
}

/**
 * Build the complete hiding-commitment set for a batch or checkpoint.
 * `itemHashes` must already be in canonical order (submission order for
 * batches, deterministic sorted order for checkpoints); the index of each
 * hash is bound into its commitment.
 */
export function buildHidingCommitmentsV1(
  batchSeed: string,
  itemHashes: string[],
): HidingCommitmentBatchV1 {
  if (!Array.isArray(itemHashes) || itemHashes.length === 0) {
    throw new Error('itemHashes must be a non-empty array.');
  }
  const itemOpenings: string[] = [];
  const publishedLeaves: string[] = [];
  for (let index = 0; index < itemHashes.length; index += 1) {
    const opening = deriveItemOpeningV1(batchSeed, index, itemHashes[index]);
    itemOpenings.push(opening);
    publishedLeaves.push(
      computePublishedLeafV1(index, itemHashes[index], opening),
    );
  }
  return {
    itemOpenings,
    publishedLeaves,
    publishedRoot: computeMerkleItemsRootV2(publishedLeaves),
  };
}

/**
 * Build the sorted-pair Merkle proof for one published leaf.
 */
export function buildPublishedLeafProofV1(
  publishedLeaves: string[],
  itemIndex: number,
): string[] {
  return buildMerkleProofV2(publishedLeaves, itemIndex);
}

export interface HiddenItemProofV1 {
  /** Canonical content fingerprint, recomputed by the caller from disclosed
   *  event content. Never accept this value from an untrusted proof blob
   *  without recomputing it. */
  itemHash: string;
  /** Position of the item inside the committed batch or checkpoint. */
  itemIndex: number;
  /** The opening disclosed in the authorized receipt for this item. */
  itemOpening: string;
  /** Sorted-pair sibling path from the published leaf to the root. */
  proof: string[];
  /** The published (on-chain) root to verify against. */
  expectedRoot: string;
}

/**
 * Verify that one disclosed event is committed under a published root.
 *
 * This is the canonical-event semantic verifier: it always recomputes the
 * position-bound leaf from (index, fingerprint, opening) before folding the
 * proof path. A bare 32-byte value is never accepted as a leaf, so a real
 * internal tree node with a shortened proof cannot masquerade as a usage
 * event (ADR 0008 Required Verification 12).
 */
export function verifyHiddenItemProofV1(input: HiddenItemProofV1): boolean {
  const root = normalizeProofHash(input.expectedRoot, 'expectedRoot');
  if (!Array.isArray(input.proof)) return false;
  let node: string;
  try {
    node = computePublishedLeafV1(
      input.itemIndex,
      input.itemHash,
      input.itemOpening,
    );
  } catch {
    return false;
  }
  try {
    for (let i = 0; i < input.proof.length; i += 1) {
      const sibling = normalizeProofHash(input.proof[i], `proof[${i}]`);
      const low = node < sibling ? node : sibling;
      const high = node < sibling ? sibling : node;
      node = ethers.keccak256(
        ethers.concat([ethers.getBytes(low), ethers.getBytes(high)]),
      );
    }
  } catch {
    return false;
  }
  return node === root;
}

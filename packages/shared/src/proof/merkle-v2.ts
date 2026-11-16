import { ethers } from 'ethers';

export const MERKLE_ITEMS_ROOT_ALGORITHM_V2 = 'pair-sorted-keccak-v2';

export function normalizeProofHash(value: string, fieldName = 'hash'): string {
  const normalized = String(value || '').trim().toLowerCase();
  if (!/^0x[a-f0-9]{64}$/.test(normalized)) {
    throw new Error(`${fieldName} must be a 32-byte hex value.`);
  }
  return normalized;
}

export function normalizeFingerprintList(fingerprints: string[]): string[] {
  if (!Array.isArray(fingerprints)) {
    throw new Error('fingerprints must be an array.');
  }
  return fingerprints.map((value, index) =>
    normalizeProofHash(value, `fingerprints[${index}]`),
  );
}

export function computeMerkleItemsRootV2(fingerprints: string[]): string {
  const normalized = normalizeFingerprintList(fingerprints);
  if (normalized.length === 0) return ethers.ZeroHash;
  if (normalized.length === 1) return normalized[0];

  let layer = [...normalized];
  while (layer.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] || left;
      const low = left < right ? left : right;
      const high = left < right ? right : left;
      next.push(
        ethers.keccak256(
          ethers.concat([ethers.getBytes(low), ethers.getBytes(high)]),
        ),
      );
    }
    layer = next;
  }
  return layer[0];
}

export function buildMerkleProofV2(
  fingerprints: string[],
  targetIndex: number,
): string[] {
  const normalized = normalizeFingerprintList(fingerprints);
  if (targetIndex < 0 || targetIndex >= normalized.length) {
    throw new Error(`targetIndex ${targetIndex} is out of range.`);
  }

  let layer = [...normalized];
  let index = targetIndex;
  const proof: string[] = [];

  while (layer.length > 1) {
    const siblingIndex = index ^ 1;
    proof.push(siblingIndex < layer.length ? layer[siblingIndex] : layer[index]);

    const next: string[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i];
      const right = layer[i + 1] || left;
      const low = left < right ? left : right;
      const high = left < right ? right : left;
      next.push(
        ethers.keccak256(
          ethers.concat([ethers.getBytes(low), ethers.getBytes(high)]),
        ),
      );
    }
    layer = next;
    index = Math.floor(index / 2);
  }

  return proof;
}

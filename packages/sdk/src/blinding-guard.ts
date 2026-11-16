import { RecordIntakeError, assertNoBlindingMaterial } from '@pacspace/shared';
import { Blinding } from './blinding';
import { PacSpaceError } from './errors';
import { isFingerprintResult } from './fingerprint';

const GUARD_WORDS = {
  material:
    "This payload includes a blinding file or its value. Pass the fingerprint's ref as the payload, and keep its blinding file with the file. Nothing was sent.",
  extraField: 'A blinded fingerprint carries only alg, digest and byteLength. Move any other field out of it. Nothing was sent.',
} as const;

function holdsSdkInstance(value: unknown, seen: Set<object>): boolean {
  if (!value || typeof value !== 'object') return false;
  if (value instanceof Blinding || isFingerprintResult(value)) return true;
  if (seen.has(value)) return false;
  seen.add(value);
  const fields = Array.isArray(value) ? value : Object.values(value);
  return fields.some((field) => holdsSdkInstance(field, seen));
}

/**
 * Refuse blinding material before anything is sent: a Blinding, a whole
 * fingerprint result, and Rule B (a blinding file, a ref paired with its
 * blinding, or a blinded ref with other fields) at any depth.
 */
export function refuseBlindingMaterial(content: unknown): void {
  if (holdsSdkInstance(content, new Set())) {
    throw new PacSpaceError(GUARD_WORDS.material, 400, 'RECORD_BLINDING_INCLUDED');
  }
  try {
    assertNoBlindingMaterial(content);
  } catch (error) {
    if (error instanceof RecordIntakeError) {
      if (error.code === 'RECORD_BLINDING_INCLUDED') {
        throw new PacSpaceError(error.rule === 'B3' ? GUARD_WORDS.extraField : GUARD_WORDS.material, 400, error.code);
      }
      throw new PacSpaceError(error.message, 400, error.code);
    }
    throw error;
  }
}

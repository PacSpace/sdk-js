import { drawSampleV1, samplePoolDigestV1, type SharedRecordEvidenceV1 } from '@pacspace/shared';
import { CHECKER_NAME, CHECKER_VERSION } from '../check';
import type { EvidenceLine } from '../evidence/evidence';
import { SAMPLE_WORDS as W } from '../evidence/words';

export const SAMPLE_REPORT_SCHEMA = 'pacspace-check-sample-report/v1' as const;

export interface SampleReport {
  schema: typeof SAMPLE_REPORT_SCHEMA;
  checker: { name: string; version: string };
  ref: string | null;
  lines: EvidenceLine[];
  /** 0 every random request's picks follow from its seed; 1 one's do not. */
  exitCode: 0 | 1;
}

const key = (p: { number: number; seq: number }) => `${p.number}:${p.seq}`;
const pick = (p: { record: number; entry: number }) => ({ number: p.record, seq: p.entry - 1 });

/**
 * `pacspace-check sample <file>` (R7; D-14): every request in an evidence record that drew at random, re-derived from
 * its committed seed. The pool's digest is the one the request committed; drawing the random picks and the picks the
 * reader took out again from the seed, over the pool less what was left out, with the same spread, gives exactly
 * the picks the request sent at random. Nothing is read from anywhere: the file alone.
 */
export async function checkSamples(file: SharedRecordEvidenceV1): Promise<SampleReport> {
  const lines: EvidenceLine[] = [];
  for (const request of file.requests) {
    const s = request.sample;
    if (!s) continue;
    const records = s.pool.map((p) => ({ number: p.record, entries: p.entries, openedOn: p.openedOn }));
    let poolOk = false;
    try {
      poolOk = (await samplePoolDigestV1(records)) === s.poolDigest.toLowerCase();
    } catch {
      poolOk = false;
    }
    if (!poolOk) {
      lines.push({ check: `sample ${request.ref}`, passed: false, sentence: W.poolDiffers(request.ref) });
      continue;
    }
    const random = request.picks.filter((p) => p.picked === 'at random').map(pick);
    const removed = s.removedByTheReader.map(pick);
    let ok = false;
    try {
      const drawn = await drawSampleV1({ seed: s.seed, records, leftOut: s.leftOut.map(pick), n: random.length + removed.length, spread: s.spread });
      const drawnKeys = new Set(drawn.map(key));
      const removedKeys = new Set(removed.map(key));
      const kept = drawn.filter((p) => !removedKeys.has(key(p))).map(key).sort();
      const sent = random.map(key).sort();
      ok = s.randomPicks === random.length && removed.every((p) => drawnKeys.has(key(p))) && kept.length === sent.length && kept.every((k, i) => k === sent[i]);
    } catch {
      ok = false;
    }
    lines.push({ check: `sample ${request.ref}`, passed: ok, sentence: ok ? W.matches(request.ref, random.length) : W.differs(request.ref) });
  }
  if (!lines.length) lines.push({ check: 'sample', passed: null, sentence: W.none });
  return {
    schema: SAMPLE_REPORT_SCHEMA,
    checker: { name: CHECKER_NAME, version: CHECKER_VERSION },
    ref: file.ref,
    lines,
    exitCode: lines.some((l) => l.passed === false) ? 1 : 0,
  };
}

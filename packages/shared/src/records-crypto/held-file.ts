/**
 * What is known about a file the reader holds. Digests are computed from the
 * file's bytes, never from decoded text. `hmac` is present only when a
 * blinding file is given: the file's HMAC under its value, and the blinding
 * file's own `digest` and `byteLength`. The value itself is never here.
 */
export interface HeldFile {
  sha256: string;
  byteLength: string;
  hmac?: { digest: string; blindingDigest: string; blindingByteLength: string };
}

export interface HeldFileMatch {
  matched: boolean;
  matchedIndex: number | null;
  /** The match was an `hmac-sha-256` item. */
  blinded: boolean;
  /** No match, no blinding given, and some item is blinded: a blinding file could decide it. */
  blindingNeeded: boolean;
  /** The blinding file does not describe the held file. */
  refused: null | 'blinding-length' | 'blinding-digest';
}

/**
 * The held-file rule for the SDK's `check` with files, the checker's
 * `--held-file` and the Shared Record. `items` is the record content's
 * top-level `payloads`; nested references are never matched.
 */
export function matchHeldFile(items: unknown, held: HeldFile): HeldFileMatch {
  const none = { matched: false, matchedIndex: null, blinded: false, blindingNeeded: false };
  if (held.hmac) {
    if (held.hmac.blindingByteLength !== held.byteLength) return { ...none, refused: 'blinding-length' };
    if (held.hmac.blindingDigest !== held.hmac.digest) return { ...none, refused: 'blinding-digest' };
  }
  const list = Array.isArray(items) ? items : [];
  for (let i = 0; i < list.length; i += 1) {
    const item = list[i];
    if (!item || typeof item !== 'object') continue;
    const { alg, digest, byteLength } = item as Record<string, unknown>;
    if (alg === 'hmac-sha-256') {
      if (held.hmac && digest === held.hmac.digest && String(byteLength) === held.byteLength) {
        return { matched: true, matchedIndex: i, blinded: true, blindingNeeded: false, refused: null };
      }
      continue;
    }
    if (digest === held.sha256 && (byteLength === undefined || byteLength === null || String(byteLength) === held.byteLength)) {
      return { matched: true, matchedIndex: i, blinded: false, blindingNeeded: false, refused: null };
    }
  }
  const blindingNeeded =
    !held.hmac && list.some((item) => !!item && typeof item === 'object' && (item as { alg?: unknown }).alg === 'hmac-sha-256');
  return { ...none, blindingNeeded, refused: null };
}

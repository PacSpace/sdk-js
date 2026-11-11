/**
 * Record labels (records prototype build, R3; D-4, D-23).
 *
 * A label is a `name=value` pair the writer's code puts on a record. Labels are metadata on the record row:
 * never in an entry's content, never committed. In a plaintext workspace a record holds them as an object;
 * in an encrypted workspace the writer blinds each one (`blindedLabelV1`) and the record holds the set of
 * blinded values, so PacSpace learns which records share a label, never the label.
 *
 * `parseLabels` is the prototype's (`js/core.js`), used by the rule form and the server alike. The limits
 * below are the platform's, narrower than the prototype's (the prototype rule: the platform owns limits).
 */

/** The prototype's grammar for one pair: a key of `[a-z0-9_.-]`, then `=` or `:`, then the value. */
export const LABEL_PAIR_RE = /^\s*([a-z0-9_.-]+)\s*[=:]\s*(.+?)\s*$/i;

export const LABELS_MAX = 10;
export const LABEL_KEY_RE = /^[a-z0-9_.-]{1,32}$/;
export const LABEL_VALUE_RE = /^[A-Za-z0-9._:/-]{1,64}$/;
/** `b1:` and 43 base64url characters: HMAC-SHA-256 of `name=value` under the workspace's id key. */
export const BLINDED_LABEL_RE = /^b1:[A-Za-z0-9_-]{43}$/;

/** A plaintext record's labels. */
export type PlainLabels = Record<string, string>;
/** An encrypted record's labels: the blinded values, as a set. */
export type BlindedLabels = { b: string[] };
export type StoredLabels = PlainLabels | BlindedLabels;

/**
 * The prototype's `parseLabels`: pairs split on `,`, `;` or a newline, each `k=v` or `k:v`, keys lowercased.
 * A part that does not read as a pair is dropped; `labelsUnreadable` says whether any was.
 */
export function parseLabels(input: unknown): PlainLabels {
  const out: PlainLabels = {};
  String(input ?? '')
    .split(/[,;\n]+/)
    .forEach((part) => {
      const m = part.match(LABEL_PAIR_RE);
      if (m) out[m[1].toLowerCase()] = m[2];
    });
  return out;
}

/** The prototype's `labelsBad`: a label the rule can't read would be dropped and quietly widen the rule. */
export function labelsUnreadable(input: unknown): boolean {
  return String(input ?? '')
    .split(/[,;\n]+/)
    .filter((part) => part.trim())
    .some((part) => !LABEL_PAIR_RE.test(part));
}

export type LabelsCheck =
  | { ok: true; kind: 'plain'; labels: PlainLabels }
  | { ok: true; kind: 'blinded'; labels: string[] }
  | { ok: false; code: 'RECORD_LABELS_INVALID' };

const invalid = { ok: false, code: 'RECORD_LABELS_INVALID' } as const;

/**
 * A write body's `labels`, as the server admits them: an object of up to 10 pairs with lowercase keys
 * (an uppercase key is refused, never lowercased here) and values the platform allows; or an array of up
 * to 10 blinded values. Whether the record may take which kind is the caller's rule.
 */
export function checkLabels(input: unknown): LabelsCheck {
  if (Array.isArray(input)) {
    if (input.length === 0 || input.length > LABELS_MAX) return invalid;
    if (!input.every((v) => typeof v === 'string' && BLINDED_LABEL_RE.test(v))) return invalid;
    return { ok: true, kind: 'blinded', labels: [...new Set(input as string[])] };
  }
  if (input === null || typeof input !== 'object') return invalid;
  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length === 0 || entries.length > LABELS_MAX) return invalid;
  for (const [key, value] of entries) {
    if (!LABEL_KEY_RE.test(key) || typeof value !== 'string' || !LABEL_VALUE_RE.test(value)) return invalid;
  }
  return { ok: true, kind: 'plain', labels: Object.fromEntries(entries) as PlainLabels };
}

export type LabelsMerge =
  | { ok: true; labels: StoredLabels; changed: boolean }
  | { ok: false; code: 'RECORD_LABEL_CONFLICT' | 'RECORD_LABELS_INVALID' };

/** Whether a stored value holds blinded labels. */
export function isBlindedLabels(stored: unknown): stored is BlindedLabels {
  return !!stored && typeof stored === 'object' && !Array.isArray(stored) && Array.isArray((stored as BlindedLabels).b);
}

/**
 * Merges admitted labels into what a record holds. Plain labels: the same key with another value is
 * `RECORD_LABEL_CONFLICT`. Blinded labels join the set, with no conflict rule. A record never holds both,
 * and never more than 10.
 */
export function mergeLabels(stored: unknown, incoming: Exclude<LabelsCheck, { ok: false }>): LabelsMerge {
  if (incoming.kind === 'blinded') {
    if (stored != null && !isBlindedLabels(stored)) return { ok: false, code: 'RECORD_LABELS_INVALID' };
    const held = stored ? stored.b : [];
    const next = [...new Set([...held, ...incoming.labels])];
    if (next.length > LABELS_MAX) return { ok: false, code: 'RECORD_LABELS_INVALID' };
    return { ok: true, labels: { b: next }, changed: next.length !== held.length };
  }
  if (stored != null && (isBlindedLabels(stored) || typeof stored !== 'object' || Array.isArray(stored))) {
    return { ok: false, code: 'RECORD_LABELS_INVALID' };
  }
  const held = (stored ?? {}) as PlainLabels;
  const next: PlainLabels = { ...held };
  let changed = false;
  for (const [key, value] of Object.entries(incoming.labels)) {
    if (key in held) {
      if (held[key] !== value) return { ok: false, code: 'RECORD_LABEL_CONFLICT' };
      continue;
    }
    next[key] = value;
    changed = true;
  }
  if (Object.keys(next).length > LABELS_MAX) return { ok: false, code: 'RECORD_LABELS_INVALID' };
  return { ok: true, labels: next, changed };
}

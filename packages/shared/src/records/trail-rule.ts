/**
 * A trail's rule (records prototype build, R4; D-4, D-23): which records join a trail.
 *
 * `ruleMatches` and `ruleSay` are the prototype's (`js/core.js` at the pin), ported to the stored form
 * `{"v":1,"sources":[ids],"labels":{k:v},"from":"YYYY-MM-DD","earlier":bool}`. A record matches when its source
 * is one of the rule's, it opened on or after `from`, and it carries every rule label with the same value; in an
 * encrypted workspace the rule's labels are blinded in the browser and each must be in the record's blinded set.
 *
 * `earlier` is not part of matching, exactly as in the prototype (`ruleMatches`, and `js/dashboard.js`, where
 * `earlier` only decides the initial joins). It decides whether records whose close committed before the
 * trail's rule commit join, through the backfill.
 *
 * `ruleToSql` builds the same predicate as parameterized SQL fragments, for previews and joins.
 */
import {
  BLINDED_LABEL_RE,
  LABELS_MAX,
  LABEL_KEY_RE,
  LABEL_VALUE_RE,
  isBlindedLabels,
  labelsUnreadable,
  parseLabels,
  type BlindedLabels,
  type PlainLabels,
} from './labels';

export interface TrailRuleV1 {
  v: 1;
  /** Source ids, sorted, no repeats. */
  sources: string[];
  /** `{}` when the rule names no label; `{ b: [...] }` blinded in an encrypted workspace. */
  labels: PlainLabels | BlindedLabels;
  /** The first day a record may have opened on, UTC. */
  from: string;
  earlier: boolean;
}

/** What a rule reads of a record. */
export interface TrailRuleRecord {
  sourceId: string | null;
  /** The UTC day the record opened (its first entry was accepted), `YYYY-MM-DD`. */
  openedOn: string;
  labels: unknown;
}

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const ISO_DAY = /^(\d{4})-(\d{2})-(\d{2})$/;
const WRITTEN_DAY = /^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$/;

/** The rule form's sentences, the prototype's (`js/dashboard.js`) where it has one. */
export const TRAIL_RULE_WORDS = {
  /** A source missing, removed, of another environment or of another workspace reads the same. */
  sourcesInvalid: 'Choose at least one source in this environment. Nothing was committed.',
  labelsUnreadable: 'Write each label as a name and a value. Nothing was committed.',
  dayUnreadable: 'Write the date as a day, a month and a year, for example 1 September 2026.',
  /** R3's label limits (RECORD_LABELS_INVALID), which no record label can exceed. */
  labelsOverLimit: 'Labels are up to 10 key=value pairs. Keys are lowercase.',
  labelsBlindedHere: 'This workspace encrypts its records, so a rule names labels blinded in the browser. Nothing was committed.',
  labelsPlainHere: 'This workspace keeps its records in plain form, so a rule names labels as a name and a value. Nothing was committed.',
} as const;

function validDay(year: number, month: number, day: number): string | null {
  const d = new Date(Date.UTC(year, month - 1, day));
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day) return null;
  return d.toISOString().slice(0, 10);
}

/** A day as the rule form takes it ("1 September 2026", the prototype's form) or as stored (`YYYY-MM-DD`). */
export function parseRuleDay(input: unknown): string | null {
  const text = String(input ?? '').trim();
  const iso = text.match(ISO_DAY);
  if (iso) return validDay(Number(iso[1]), Number(iso[2]), Number(iso[3]));
  const written = text.match(WRITTEN_DAY);
  if (!written) return null;
  const month = MONTHS.findIndex((m) => m.toLowerCase() === written[2].toLowerCase());
  if (month < 0) return null;
  return validDay(Number(written[3]), month + 1, Number(written[1]));
}

/** A stored day as the prototype writes it: "1 September 2026". */
export function formatRuleDay(iso: string): string {
  const m = String(iso).match(ISO_DAY);
  if (!m) return String(iso);
  return `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

function blindedRule(labels: TrailRuleV1['labels']): labels is BlindedLabels {
  return isBlindedLabels(labels);
}

/** The prototype's `ruleMatches`. */
export function ruleMatches(rule: TrailRuleV1, record: TrailRuleRecord): boolean {
  if (!rule || !record || record.sourceId === null || !rule.sources.includes(record.sourceId)) return false;
  if (record.openedOn < rule.from) return false;
  if (blindedRule(rule.labels)) {
    if (!isBlindedLabels(record.labels)) return rule.labels.b.length === 0;
    const held = new Set(record.labels.b);
    return rule.labels.b.every((value) => held.has(value));
  }
  const wanted = Object.entries(rule.labels);
  if (wanted.length === 0) return true;
  const held = record.labels;
  if (!held || typeof held !== 'object' || Array.isArray(held) || isBlindedLabels(held)) return false;
  return wanted.every(([key, value]) => (held as PlainLabels)[key] === value);
}

/** Two rules that pick the same records: the prototype's `ruleSame` (sources, labels and start day; not `earlier`). */
export function ruleSame(a: TrailRuleV1, b: TrailRuleV1): boolean {
  return JSON.stringify(ruleKey(a)) === JSON.stringify(ruleKey(b));
}

function ruleKey(rule: TrailRuleV1) {
  const labels = blindedRule(rule.labels)
    ? { b: [...rule.labels.b].sort() }
    : Object.fromEntries(Object.entries(rule.labels).sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
  return { sources: [...rule.sources].sort(), labels, from: rule.from };
}

export interface RuleSaySource {
  id: string;
  name: string;
  environment: string;
}

/**
 * The prototype's `ruleSay`, the rule in one sentence as the operator sees it. Blinded labels cannot be read
 * back, so in an encrypted workspace the caller passes the readable text it unsealed (`labelsText`).
 */
export function ruleSay(rule: TrailRuleV1, sources: readonly RuleSaySource[], labelsText?: string): string {
  const names = rule.sources.map((id) => {
    const source = sources.find((s) => s.id === id);
    return source ? `${source.name} (${source.environment === 'production' ? 'Production' : 'Sandbox'})` : 'A removed source ()';
  });
  const lab = (labelsText ?? (blindedRule(rule.labels) ? '' : Object.entries(rule.labels).map(([k, v]) => `${k}=${v}`).join(', '))).trim();
  return (
    'Records written by ' +
    (names.join(' and ') || 'no source') +
    (lab ? ', labelled ' + lab : '') +
    ', from ' +
    formatRuleDay(rule.from) +
    '. Records from before the trail existed are ' +
    (rule.earlier ? 'included.' : 'not included.')
  );
}

export type TrailRuleCheck = { ok: true; rule: TrailRuleV1 } | { ok: false; code: 'TRAIL_RULE_INVALID'; message: string };

export interface TrailRuleInput {
  sources?: unknown;
  /** The prototype's text ("model = m-0926, site = lab-2"), pairs as an object, or blinded values as an array. */
  labels?: unknown;
  from?: unknown;
  earlier?: unknown;
}

const invalid = (message: string): TrailRuleCheck => ({ ok: false, code: 'TRAIL_RULE_INVALID', message });

/**
 * A rule as the form sends it, read into the stored form. Sources and the start day must be present (the
 * caller checks they are the tenant's, in this environment); labels must be plain in a plaintext workspace and
 * blinded in an encrypted one (D-23), within R3's label limits.
 */
export function checkTrailRule(input: TrailRuleInput, options: { encrypted: boolean }): TrailRuleCheck {
  const sources = Array.isArray(input.sources) ? input.sources : [];
  if (sources.length === 0 || !sources.every((s) => typeof s === 'string' && s.length > 0 && s.length <= 30)) {
    return invalid(TRAIL_RULE_WORDS.sourcesInvalid);
  }
  const from = parseRuleDay(input.from);
  if (from === null) return invalid(TRAIL_RULE_WORDS.dayUnreadable);

  let labels: TrailRuleV1['labels'];
  const raw = input.labels ?? '';
  if (Array.isArray(raw)) {
    if (raw.length > 0 && !options.encrypted) return invalid(TRAIL_RULE_WORDS.labelsPlainHere);
    if (raw.length > LABELS_MAX || !raw.every((v) => typeof v === 'string' && BLINDED_LABEL_RE.test(v))) {
      return invalid(TRAIL_RULE_WORDS.labelsOverLimit);
    }
    labels = raw.length === 0 ? {} : { b: [...new Set(raw as string[])].sort() };
  } else {
    let pairs: PlainLabels;
    if (typeof raw === 'string') {
      if (labelsUnreadable(raw)) return invalid(TRAIL_RULE_WORDS.labelsUnreadable);
      pairs = parseLabels(raw);
    } else if (raw && typeof raw === 'object') {
      pairs = {};
      for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
        if (typeof v !== 'string') return invalid(TRAIL_RULE_WORDS.labelsUnreadable);
        pairs[k] = v;
      }
    } else {
      return invalid(TRAIL_RULE_WORDS.labelsUnreadable);
    }
    const entries = Object.entries(pairs);
    if (entries.length > 0 && options.encrypted) return invalid(TRAIL_RULE_WORDS.labelsBlindedHere);
    if (entries.length > LABELS_MAX || !entries.every(([k, v]) => LABEL_KEY_RE.test(k) && LABEL_VALUE_RE.test(v))) {
      return invalid(TRAIL_RULE_WORDS.labelsOverLimit);
    }
    labels = Object.fromEntries(entries.sort(([x], [y]) => (x < y ? -1 : x > y ? 1 : 0)));
  }
  return {
    ok: true,
    rule: { v: 1, sources: [...new Set(sources as string[])].sort(), labels, from, earlier: input.earlier !== false },
  };
}

/** A parameterized SQL fragment: the strings and values of a tagged template, as Prisma.Sql takes them. */
export interface SqlFragment {
  strings: string[];
  values: unknown[];
}

/**
 * The rule's predicate over a `slot_records` alias, with every value a parameter: the source is one of the
 * rule's, the record was created on or after `from` (UTC), and its labels contain the rule's (`@>`, which the
 * label GIN index serves; a blinded rule's values are each in the record's set).
 */
export function ruleToSql(rule: TrailRuleV1, alias = 'sr'): SqlFragment {
  if (!/^[a-z_][a-z0-9_]*$/.test(alias)) throw new Error('ruleToSql: the alias is a plain identifier');
  const strings = [`${alias}.source_id = ANY(`, `::varchar[]) AND ${alias}.created_at >= `, '::date'];
  const values: unknown[] = [[...rule.sources], rule.from];
  const hasLabels = blindedRule(rule.labels) ? rule.labels.b.length > 0 : Object.keys(rule.labels).length > 0;
  if (hasLabels) {
    strings[2] = `::date AND ${alias}.labels @> `;
    strings.push('::jsonb');
    values.push(JSON.stringify(rule.labels));
  }
  return { strings, values };
}

/** A fragment as text with `$1`-style placeholders from `offset + 1`, for logs and specs. */
export function sqlFragmentText(fragment: SqlFragment, offset = 0): string {
  return fragment.strings.reduce((text, part, i) => text + (i === 0 ? '' : `$${offset + i}`) + part, '');
}

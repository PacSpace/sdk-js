import { RecordIntakeError, RecordIntakeErrorCode } from '../proof/layout-document-v1';
import { PUBLISHED_RECORD_CONTENT_SCHEMAS_V1 } from './layouts.generated';
import type { RecordRef } from './model-record-link-v1';

/**
 * Sealed record-content schema (docs/spec/records/record-content/*.json).
 *
 * The schema names the fields a sealed record must and may carry for one
 * layout. It is a well-formedness contract for intake: PacSpace checks that
 * the required fields are present with the declared primitive type before
 * anything is queued, and never reads the values for any other purpose.
 */
export const RECORD_CONTENT_SCHEMA_V1 = 'record-content-schema/v1';

export type RecordContentFieldType =
  | 'string'
  | 'number'
  | 'integer'
  | 'boolean'
  | 'object'
  | 'array'
  | 'bytes32-hex'
  | 'payload-ref/v1'
  /** `{ recordKey, seq }`: one entry of one record (references[], amends). */
  | 'record-ref/v1'
  /** `{ referenceId }` or `{ recordId }`: the earlier Balance delta an entry corrects (adjusts). */
  | 'adjusts-ref/v1';

export interface RecordContentFieldSpec {
  type: RecordContentFieldType | string;
  format?: string;
  description?: string;
  /** Present on fields PacSpace writes itself (attempt and failure records). */
  when?: string;
  /** Element type for arrays. */
  items?: string;
  /** Minimum element count for arrays (`payloads` on the general layout). */
  minItems?: number;
  /** Maximum length for strings (`title` on the general layout). */
  maxLength?: number;
  /** Nested object fields (documentation only; not validated field by field). */
  fields?: Record<string, string>;
}

export interface RecordContentSchemaV1 {
  schema: typeof RECORD_CONTENT_SCHEMA_V1;
  /** `record-content/<layout name>`; equals the layout document's sealedRecordSchema. */
  name: string;
  layout: string;
  visibility: 'sealed';
  description?: string;
  requiredFields: string[];
  optionalFields?: string[];
  fields: Record<string, RecordContentFieldSpec>;
  /** Prose notes on what never belongs in a sealed record (documentation only). */
  excluded?: string[];
}

/** PacSpace bookkeeping that is never part of a sealed record's content. */
export const RECORD_CONTENT_RESERVED_FIELDS = ['seq', 'previousWord', 'newWord', 'anchorId', 'itemIndex', 'recordKey', 'batchSeed', 'recordOpening', 'itemOpening'] as const;

const BYTES32 = /^0x[0-9a-f]{64}$/i;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const SIGNED_DECIMAL = /^-?\d+(\.\d+)?$/;
const ISO_4217 = /^[A-Z]{3}$/;
/** Lowercase words joined by single hyphens (the general layout's `kind`). */
const LOWERCASE_HYPHEN = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export function getRecordContentSchema(name: string): RecordContentSchemaV1 | undefined {
  return PUBLISHED_RECORD_CONTENT_SCHEMAS_V1.find((s) => s.name === name);
}

export function listRecordContentSchemas(): RecordContentSchemaV1[] {
  return [...PUBLISHED_RECORD_CONTENT_SCHEMAS_V1];
}

/** `{ recordKey, seq }` naming one entry of one record (references[], amends, modelRecordRef). */
export function isRecordRefV1(value: unknown): value is RecordRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return typeof r.recordKey === 'string' && BYTES32.test(r.recordKey) && typeof r.seq === 'number' && Number.isInteger(r.seq) && r.seq >= 0;
}

/** `{ referenceId }` or `{ recordId }`, exactly one, each a non-empty string. */
export type AdjustsRefV1 = { referenceId: string } | { recordId: string };

export function isAdjustsRefV1(value: unknown): value is AdjustsRefV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  const keys = Object.keys(r);
  if (keys.length !== 1) return false;
  const key = keys[0];
  if (key !== 'referenceId' && key !== 'recordId') return false;
  return typeof r[key] === 'string' && (r[key] as string).length > 0;
}

/** CSV cell for an `adjusts` column: the original's referenceId or recordId. */
export function formatAdjustsRefV1(value: unknown): string {
  if (!isAdjustsRefV1(value)) return '';
  return 'referenceId' in value ? value.referenceId : value.recordId;
}

function itemMatches(items: string | undefined, value: unknown): boolean {
  switch (items) {
    case 'record-ref/v1':
      return isRecordRefV1(value);
    case 'payload-ref/v1':
      return !!value && typeof value === 'object' && !Array.isArray(value);
    case 'string':
      return typeof value === 'string';
    default:
      return true;
  }
}

function typeMatches(spec: RecordContentFieldSpec, value: unknown): boolean {
  switch (spec.type) {
    case 'string':
      if (typeof value !== 'string') return false;
      if (spec.format === 'rfc3339-utc') return RFC3339_UTC.test(value);
      if (spec.format === 'signed-decimal') return SIGNED_DECIMAL.test(value);
      if (spec.format === 'iso-4217') return ISO_4217.test(value);
      if (spec.format === 'lowercase-hyphen') return LOWERCASE_HYPHEN.test(value);
      return true;
    case 'number':
      return typeof value === 'number' && Number.isFinite(value);
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value);
    case 'boolean':
      return typeof value === 'boolean';
    case 'array':
      return Array.isArray(value) && value.every((v) => itemMatches(spec.items, v));
    case 'object':
    case 'payload-ref/v1':
      return !!value && typeof value === 'object' && !Array.isArray(value);
    case 'bytes32-hex':
      return typeof value === 'string' && BYTES32.test(value);
    case 'record-ref/v1':
      return isRecordRefV1(value);
    case 'adjusts-ref/v1':
      return isAdjustsRefV1(value);
    default:
      return true;
  }
}

function describeType(spec: RecordContentFieldSpec): string {
  if (spec.type === 'array' && spec.items) return `an array of ${spec.items}`;
  if (spec.type === 'record-ref/v1') return '{ recordKey, seq }';
  if (spec.type === 'adjusts-ref/v1') return '{ referenceId } or { recordId }';
  return `${spec.type}${spec.format ? ` (${spec.format})` : ''}`;
}

/**
 * The code a missing or empty array field carries. `payloads[]` on the general
 * layout has its own code (RECORD_PAYLOADS_REQUIRED, the Denial Codes row);
 * every other minimum falls back to RECORD_CONTENT_INVALID.
 */
function minimumCode(field: string): RecordIntakeErrorCode {
  return field === 'payloads' ? 'RECORD_PAYLOADS_REQUIRED' : 'RECORD_CONTENT_INVALID';
}

/**
 * Check a sealed record's content against its layout's content schema.
 * Throws `RecordIntakeError('RECORD_CONTENT_INVALID')` naming the first
 * offending field, `RECORD_PAYLOADS_REQUIRED` when a schema's `payloads[]`
 * minimum is not met, and `RECORD_TITLE_TOO_LONG` when `title` exceeds the
 * schema's `maxLength`. Fields the schema does not name are allowed (the
 * tenant owns the record); attempt- and failure-record fields
 * (`attemptedTarget`, `ruleId`, `failureClass`) are written by PacSpace and
 * are rejected when a caller supplies them.
 *
 * `references[]` and `amends` are checked here for shape only, each
 * `{ recordKey, seq }`; whether the named entries exist, are committed, and
 * precede this one is the D17 rule at intake and in the verifier.
 */
export function validateRecordContentV1(schemaName: string, content: Record<string, unknown>): RecordContentSchemaV1 {
  const schema = getRecordContentSchema(schemaName);
  if (!schema) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `record-content schema ${schemaName} is not published`);
  }
  if (!content || typeof content !== 'object' || Array.isArray(content)) {
    throw new RecordIntakeError('RECORD_CONTENT_INVALID', 'content must be an object');
  }
  for (const field of schema.requiredFields) {
    if (!(field in content) || content[field] === null || content[field] === undefined) {
      const spec = schema.fields[field];
      if (spec && spec.type === 'array' && spec.minItems) {
        throw new RecordIntakeError(minimumCode(field), `content.${field} must carry at least ${spec.minItems} ${spec.items ?? 'item'}${spec.minItems === 1 ? '' : 's'}`);
      }
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `content.${field} is required by ${schema.name}`);
    }
  }
  for (const field of RECORD_CONTENT_RESERVED_FIELDS) {
    if (field in content) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `content.${field} is PacSpace bookkeeping and is never part of a sealed record`);
    }
  }
  for (const [field, spec] of Object.entries(schema.fields)) {
    if (!(field in content)) continue;
    if (spec.when && /attempt record|failure record/.test(spec.when)) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `content.${field} is written by PacSpace and cannot be supplied`);
    }
    const value = content[field];
    if (!typeMatches(spec, value)) {
      throw new RecordIntakeError('RECORD_CONTENT_INVALID', `content.${field} must be ${describeType(spec)}`);
    }
    if (spec.type === 'array' && spec.minItems && (value as unknown[]).length < spec.minItems) {
      throw new RecordIntakeError(minimumCode(field), `content.${field} must carry at least ${spec.minItems} ${spec.items ?? 'item'}${spec.minItems === 1 ? '' : 's'}`);
    }
    if (spec.type === 'string' && spec.maxLength && (value as string).length > spec.maxLength) {
      throw new RecordIntakeError(
        field === 'title' ? 'RECORD_TITLE_TOO_LONG' : 'RECORD_CONTENT_INVALID',
        `content.${field} is longer than ${spec.maxLength} characters`,
      );
    }
  }
  return schema;
}

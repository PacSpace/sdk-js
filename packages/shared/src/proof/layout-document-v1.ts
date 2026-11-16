import { ethers } from 'ethers';
import { canonicalizeJcs } from './jcs';

/**
 * layout-document/v1 (ADR 0012 section 4; slot-encoding-v1 sections 4 and 5).
 *
 * A layout document is the public description of a record type's state
 * region: typed fields packed most significant first, a lifecycle table, and
 * the name of the sealed record schema. Its digest, keccak256 over the JCS
 * bytes, is what the operator registers on the contract. This module packs
 * and decodes state words under a layout and validates well-formedness only;
 * it never scores plausibility (PacSpace records and never decides).
 */

export const LAYOUT_DOCUMENT_SCHEMA_V1 = 'layout-document/v1';

export type LayoutFieldType = 'enum' | 'flags' | 'counter' | 'quantity' | 'reserved';

export interface LayoutFieldBase {
  name: string;
  type: LayoutFieldType;
  bits: number;
}
export interface LayoutEnumField extends LayoutFieldBase {
  type: 'enum';
  values: Record<string, number>;
}
export interface LayoutFlagsField extends LayoutFieldBase {
  type: 'flags';
  bitNames: Record<string, number>;
}
export interface LayoutCounterField extends LayoutFieldBase {
  type: 'counter';
  fixed?: number;
}
export interface LayoutQuantityField extends LayoutFieldBase {
  type: 'quantity';
  unitCode: string;
  scale: number;
  semantics: 'perRecord' | 'cumulative';
}
export interface LayoutReservedField extends LayoutFieldBase {
  type: 'reserved';
}
export type LayoutField =
  | LayoutEnumField
  | LayoutFlagsField
  | LayoutCounterField
  | LayoutQuantityField
  | LayoutReservedField;

export interface LayoutLifecycle {
  field: string;
  genesis: string[];
  terminal: string[];
  transitions: Record<string, string[]>;
}

export interface LayoutDocumentV1 {
  schema: typeof LAYOUT_DOCUMENT_SCHEMA_V1;
  layoutId: number;
  layoutVersion: number;
  name: string;
  recordTypeId: string;
  encodingVersion: number;
  stateBits: number;
  sealBits: number;
  public: boolean;
  recordAttempts: boolean;
  fields: LayoutField[];
  lifecycle: LayoutLifecycle;
  sealedRecordSchema: string;
  notes?: string[];
}

/** Registered error codes for intake rejections (well-formedness only). */
export type RecordIntakeErrorCode =
  | 'LAYOUT_NOT_FOUND'
  | 'RECORD_LAYOUT_MISMATCH'
  | 'RECORD_STATE_UNKNOWN'
  | 'RECORD_RESERVED_BITS_SET'
  | 'RECORD_QUANTITY_OVERFLOW'
  | 'RECORD_FLAG_UNKNOWN'
  | 'RECORD_TRANSITION_FORBIDDEN'
  | 'RECORD_GENESIS_MISMATCH'
  | 'RECORD_PAYLOAD_ALG_UNSUPPORTED'
  | 'RECORD_CONTENT_INVALID'
  | 'RECORD_LAYOUT_INVALID'
  // Records buyer posture plan, Slice B: the sealed-content minimums of the
  // general layout (record-content/machine-action-record/v1).
  | 'RECORD_PAYLOADS_REQUIRED'
  | 'RECORD_TITLE_TOO_LONG'
  | 'RECORD_BLINDING_INCLUDED';

/** The part of Rule B (slot-encoding-v1 section 6.1) that refused blinding material. */
export type BlindingMaterialRule = 'B1' | 'B2' | 'B3';

export class RecordIntakeError extends Error {
  readonly code: RecordIntakeErrorCode;
  /** Set only by Rule B. */
  readonly rule?: BlindingMaterialRule;
  constructor(code: RecordIntakeErrorCode, message?: string, rule?: BlindingMaterialRule) {
    super(message || code);
    this.name = 'RecordIntakeError';
    this.code = code;
    if (rule) this.rule = rule;
  }
}

/** Values a caller supplies for the state fields (enum by name, flags by name list, counters/quantities as integers). */
export type StateFieldValues = Record<string, string | number | bigint | string[] | undefined>;

/** Decoded state: enum names, flag name lists, counters and quantities as decimal strings. */
export type DecodedState = Record<string, string | string[]>;

export function computeLayoutDigestV1(doc: LayoutDocumentV1): string {
  return ethers.keccak256(ethers.toUtf8Bytes(canonicalizeJcs(doc)));
}

export function validateLayoutDocumentV1(doc: LayoutDocumentV1): void {
  if (!doc || doc.schema !== LAYOUT_DOCUMENT_SCHEMA_V1) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', 'layout document schema must be layout-document/v1');
  }
  if (!Number.isInteger(doc.layoutId) || doc.layoutId <= 0 || doc.layoutId > 0xffff) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', 'layoutId must be a uint16 greater than zero');
  }
  if (!Number.isInteger(doc.layoutVersion) || doc.layoutVersion <= 0 || doc.layoutVersion > 0xff) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', 'layoutVersion must be a uint8 greater than zero');
  }
  if (doc.stateBits + doc.sealBits !== 256) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', 'stateBits and sealBits must total 256');
  }
  const total = doc.fields.reduce((n, f) => n + f.bits, 0);
  if (total !== doc.stateBits) {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `fields total ${total} bits, layout declares ${doc.stateBits}`);
  }
  const names = new Set<string>();
  for (const f of doc.fields) {
    if (names.has(f.name)) throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `duplicate field ${f.name}`);
    names.add(f.name);
    if (!Number.isInteger(f.bits) || f.bits <= 0) {
      throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `field ${f.name} has an invalid width`);
    }
    if (f.type === 'enum') {
      for (const [name, value] of Object.entries(f.values)) {
        if (!Number.isInteger(value) || value < 0 || value >= 2 ** f.bits) {
          throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `enum ${f.name}.${name} does not fit ${f.bits} bits`);
        }
      }
    }
    if (f.type === 'flags') {
      for (const [name, bit] of Object.entries(f.bitNames)) {
        if (!Number.isInteger(bit) || bit < 0 || bit >= f.bits) {
          throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `flag ${f.name}.${name} is outside ${f.bits} bits`);
        }
      }
    }
  }
  const lifecycleField = doc.fields.find((f) => f.name === doc.lifecycle.field);
  if (!lifecycleField || lifecycleField.type !== 'enum') {
    throw new RecordIntakeError('RECORD_LAYOUT_INVALID', 'lifecycle.field must name an enum field');
  }
  const states = new Set(Object.keys(lifecycleField.values));
  for (const s of [...doc.lifecycle.genesis, ...doc.lifecycle.terminal]) {
    if (!states.has(s)) throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `lifecycle state ${s} is not in the enum`);
  }
  for (const [from, tos] of Object.entries(doc.lifecycle.transitions)) {
    if (!states.has(from)) throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `transition source ${from} is not a state`);
    for (const to of tos) {
      if (!states.has(to)) throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `transition target ${to} is not a state`);
    }
  }
  for (const t of doc.lifecycle.terminal) {
    if ((doc.lifecycle.transitions[t] ?? []).length > 0) {
      throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `terminal state ${t} has outgoing transitions`);
    }
  }
}

export function getLayoutField(doc: LayoutDocumentV1, name: string): LayoutField | undefined {
  return doc.fields.find((f) => f.name === name);
}

export function lifecycleValues(doc: LayoutDocumentV1): Record<string, number> {
  const f = getLayoutField(doc, doc.lifecycle.field);
  if (!f || f.type !== 'enum') return {};
  return f.values;
}

export function isTransitionAllowedV1(doc: LayoutDocumentV1, from: string, to: string): boolean {
  return (doc.lifecycle.transitions[from] ?? []).includes(to);
}

function toBigInt(value: string | number | bigint | undefined, field: string): bigint {
  if (value === undefined) return 0n;
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value)) throw new RecordIntakeError('RECORD_QUANTITY_OVERFLOW', `${field} must be an integer`);
    return BigInt(value);
  }
  if (!/^-?\d+$/.test(value)) throw new RecordIntakeError('RECORD_QUANTITY_OVERFLOW', `${field} must be a decimal integer`);
  return BigInt(value);
}

/**
 * Pack named field values into the state region. Rejects malformed input
 * with a registered code; never wraps or saturates.
 */
export function packStateV1(doc: LayoutDocumentV1, values: StateFieldValues): bigint {
  let state = 0n;
  for (const f of doc.fields) {
    let v: bigint;
    const width = BigInt(f.bits);
    switch (f.type) {
      case 'reserved': {
        v = toBigInt(values[f.name] as string | number | bigint | undefined, f.name);
        if (v !== 0n) throw new RecordIntakeError('RECORD_RESERVED_BITS_SET', `${f.name} must be zero`);
        break;
      }
      case 'enum': {
        const name = values[f.name];
        if (typeof name !== 'string' || !(name in f.values)) {
          throw new RecordIntakeError('RECORD_STATE_UNKNOWN', `${f.name}=${String(name)} is not in the layout`);
        }
        v = BigInt(f.values[name]);
        break;
      }
      case 'flags': {
        const names = (values[f.name] ?? []) as string[];
        if (!Array.isArray(names)) throw new RecordIntakeError('RECORD_FLAG_UNKNOWN', `${f.name} must be a list of flag names`);
        v = 0n;
        for (const n of names) {
          if (!(n in f.bitNames)) throw new RecordIntakeError('RECORD_FLAG_UNKNOWN', `${f.name}:${n} is not in the layout`);
          v |= 1n << BigInt(f.bitNames[n]);
        }
        break;
      }
      case 'counter':
      case 'quantity': {
        const fixed = f.type === 'counter' ? f.fixed : undefined;
        v = toBigInt((values[f.name] ?? fixed) as string | number | bigint | undefined, f.name);
        if (fixed !== undefined && v !== BigInt(fixed)) {
          throw new RecordIntakeError('RECORD_LAYOUT_MISMATCH', `${f.name} must be ${fixed}`);
        }
        if (v < 0n || v >= 1n << width) {
          throw new RecordIntakeError('RECORD_QUANTITY_OVERFLOW', `${f.name}=${v} exceeds ${f.bits} bits`);
        }
        break;
      }
      default:
        throw new RecordIntakeError('RECORD_LAYOUT_INVALID', `unknown field type`);
    }
    state = (state << width) | v;
  }
  return state;
}

/** Decode a state region under a layout. Unknown enum values decode as `unknown(n)`. */
export function decodeStateV1(doc: LayoutDocumentV1, state96: bigint): DecodedState {
  const out: DecodedState = {};
  let remaining = BigInt(state96);
  for (const f of [...doc.fields].reverse()) {
    const mask = (1n << BigInt(f.bits)) - 1n;
    const raw = remaining & mask;
    remaining >>= BigInt(f.bits);
    if (f.type === 'enum') {
      const found = Object.entries(f.values).find(([, n]) => BigInt(n) === raw);
      out[f.name] = found ? found[0] : `unknown(${raw})`;
    } else if (f.type === 'flags') {
      out[f.name] = Object.entries(f.bitNames)
        .filter(([, bit]) => ((raw >> BigInt(bit)) & 1n) === 1n)
        .map(([n]) => n);
    } else {
      out[f.name] = raw.toString();
    }
  }
  const ordered: DecodedState = {};
  for (const f of doc.fields) ordered[f.name] = out[f.name];
  return ordered;
}

/** Read the layout id and version from the top 24 bits of a state region. */
export function readLayoutIdFromState(state96: bigint): { layoutId: number; layoutVersion: number } {
  const s = BigInt(state96);
  return { layoutId: Number(s >> 80n), layoutVersion: Number((s >> 72n) & 0xffn) };
}

/** Format a quantity field for display, e.g. `250 api_call` or `12.50 USD`. */
export function formatQuantityV1(field: LayoutQuantityField, raw: string | bigint): string {
  const v = BigInt(raw);
  if (field.scale === 0) return `${v.toString()} ${field.unitCode}`;
  const divisor = 10n ** BigInt(field.scale);
  const whole = v / divisor;
  const frac = (v % divisor).toString().padStart(field.scale, '0');
  return `${whole.toString()}.${frac} ${field.unitCode}`;
}

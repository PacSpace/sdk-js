/**
 * RFC 8785 JSON Canonicalization Scheme (JCS), restricted to the JSON value
 * space: null, boolean, finite number, string, array, plain object.
 *
 * Object keys are sorted by UTF-16 code units; strings and numbers are
 * serialized as ECMAScript JSON.stringify does, which is what RFC 8785
 * specifies. No whitespace. Used for layout documents (`layoutDigest`) and
 * record content (`recordHash`) so two honest serializations of the same
 * record hash the same (slot-encoding-v1 sections 4 and 6).
 */
export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JcsError';
  }
}

function compareUtf16(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i += 1) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

export function canonicalizeJcs(value: unknown): string {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return JSON.stringify(value);
  if (type === 'number') {
    if (!Number.isFinite(value as number)) {
      throw new JcsError('JCS cannot encode a non-finite number.');
    }
    return JSON.stringify(value);
  }
  if (type === 'bigint') {
    throw new JcsError('JCS cannot encode a bigint; use a decimal string.');
  }
  if (type === 'undefined' || type === 'function' || type === 'symbol') {
    throw new JcsError(`JCS cannot encode a value of type ${type}.`);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJcs(item)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort(compareUtf16);
  const parts: string[] = [];
  for (const key of keys) {
    const item = record[key];
    if (item === undefined) continue; // JSON.stringify drops undefined members
    parts.push(`${JSON.stringify(key)}:${canonicalizeJcs(item)}`);
  }
  return `{${parts.join(',')}}`;
}

// Minimal RFC 8785 JCS canonicalization.
//
// This implementation is sufficient for receipts that contain strings,
// integers, booleans, nulls, objects, and arrays. It does not handle every
// edge case of IEEE-754 number serialization; for production use, prefer a
// battle-tested JCS library (e.g., the `canonicalize` npm package).
//
// Shared between the Node sample-generator and the browser verifier so both
// sides produce byte-identical canonical forms.

export function canonicalize(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number');
    if (Object.is(value, -0)) return '0';
    if (Number.isInteger(value)) return String(value);
    // Non-integer floats not exercised by the demo receipts; fall back to
    // default toString.
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
  }
  throw new Error('JCS: unsupported value type: ' + typeof value);
}

// Convenience: returns a Uint8Array of the UTF-8 encoded canonical form.
export function canonicalizeBytes(value) {
  return new TextEncoder().encode(canonicalize(value));
}

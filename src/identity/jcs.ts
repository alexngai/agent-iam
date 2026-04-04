/**
 * JSON Canonicalization Scheme (JCS) — RFC 8785
 *
 * Produces a deterministic JSON serialization by:
 * 1. Sorting object keys lexicographically (by UTF-16 code units)
 * 2. Using ES6/JSON number serialization rules
 * 3. No whitespace
 *
 * This is the subset needed for signing VC-format endorsements.
 * We don't handle the full unicode normalization edge cases since
 * our payloads are ASCII-safe (DIDs, PEM keys, ISO dates, claims).
 *
 * Reference: https://datatracker.ietf.org/doc/html/rfc8785
 */

/**
 * Canonicalize a JSON-serializable value per RFC 8785.
 * Returns a deterministic string representation.
 */
export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "number") {
    if (!isFinite(value)) {
      throw new Error("JCS does not support Infinity or NaN");
    }
    // JSON.stringify handles ES6 number serialization correctly
    return JSON.stringify(value);
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalize(item));
    return `[${items.join(",")}]`;
  }

  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Sort keys lexicographically by UTF-16 code units (JS default sort)
    const sortedKeys = Object.keys(obj).sort();
    const entries = sortedKeys
      .filter((key) => obj[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonicalize(obj[key])}`);
    return `{${entries.join(",")}}`;
  }

  throw new Error(`JCS: unsupported type ${typeof value}`);
}

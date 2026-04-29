/**
 * Vendored minimal `server.json` schema for MCP Registry manifests.
 *
 * The official MCP Registry publishes a versioned schema at:
 *   https://static.modelcontextprotocol.io/schemas/<DATE>/server.schema.json
 *
 * No npm package ships it. Rather than fetching an external URL at runtime
 * (or vendoring the full schema and tracking upstream breaking changes),
 * we validate against a minimal structural schema that covers the fields
 * agent-iam actually reads. This is a *structural* check, not full
 * upstream-schema parity.
 *
 * If/when stronger conformance is required, vendor the full dated schema
 * into `schemas/server-<DATE>.schema.json` and swap this loader.
 */

import Ajv2020 from "ajv/dist/2020.js";
import type { ValidateFunction } from "ajv/dist/2020.js";

/** The minimal manifest fields agent-iam consumes. */
export interface ServerManifest {
  name: string;
  version: string;
  repository?: { url: string; source?: string };
  description?: string;
  // Permissive — additional fields are allowed and preserved.
  [key: string]: unknown;
}

const SERVER_MANIFEST_SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  required: ["name", "version"],
  properties: {
    name: { type: "string", minLength: 1 },
    version: { type: "string", minLength: 1 },
    description: { type: "string" },
    repository: {
      type: "object",
      required: ["url"],
      properties: {
        url: { type: "string", minLength: 1 },
        source: { type: "string" },
      },
    },
  },
  additionalProperties: true,
} as const;

const ajv = new Ajv2020({ allErrors: true });
const validator: ValidateFunction<ServerManifest> =
  ajv.compile<ServerManifest>(SERVER_MANIFEST_SCHEMA);

/** Validate that a JSON value structurally matches the minimal MCP server manifest shape. */
export function validateServerManifest(
  value: unknown
): { valid: true; manifest: ServerManifest } | { valid: false; errors: string[] } {
  if (validator(value)) {
    return { valid: true, manifest: value };
  }
  const errors = (validator.errors ?? []).map(
    (e) => `${e.instancePath || "(root)"} ${e.message ?? "invalid"}`
  );
  return { valid: false, errors };
}

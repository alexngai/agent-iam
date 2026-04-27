/**
 * MCP (Model Context Protocol) access-control module.
 *
 * Provides:
 *   - Tool-schema TOFU pinning (rug-pull defense)
 *
 * Future workstream items wire in alongside:
 *   - Allow/deny scope checking (`mcp:<server>:<tool>`)
 *   - RFC 8707 audience binding on broker-issued credentials
 *   - Annotation-aware policy primitives
 *   - Optional server-identity verification
 */

export type { MCPTool, MCPToolAnnotations } from "./types.js";

export {
  canonicalToolHash,
  FileSchemaPinRegistry,
  MemorySchemaPinRegistry,
  verifyToolSchema,
} from "./schema-pin.js";
export type {
  PinnedTool,
  SchemaPinRegistry,
  SchemaVerification,
} from "./schema-pin.js";

export { checkMCPCall, formatDecision } from "./policy.js";
export type { Decision, CheckMCPCallOptions } from "./policy.js";

export { issueMCPCredential, verifyMCPCredential } from "./credential.js";
export type {
  IssueMCPCredentialOptions,
  MCPCredential,
  VerifyMCPCredentialOptions,
  VerifiedMCPCredential,
} from "./credential.js";

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
  CorruptPinFileError,
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

export { requireApprovalIf, denyIf } from "./annotations.js";
export type { AnnotationHint } from "./annotations.js";

export { verifyServerIdentity, artifactSha256 } from "./server-trust.js";
export type {
  MCPServerBinding,
  ObservedServerManifest,
  SigstoreVerifier,
  VerifyServerIdentityOptions,
  ServerTrustCheckResult,
  ServerTrustVerification,
} from "./server-trust.js";

export { validateServerManifest } from "./server-schema.js";
export type { ServerManifest } from "./server-schema.js";

export {
  buildDecisionEvent,
  ConsoleAuditSink,
  CompositeAuditSink,
  FileAuditSink,
  MemoryAuditSink,
  NullAuditSink,
} from "./audit.js";
export type {
  MCPAuditEvent,
  MCPAuditSink,
  BuildDecisionEventArgs,
} from "./audit.js";

export {
  getOrCreateMCPSigningKey,
  publicKeyToJwk,
  publicKeyToJwks,
} from "./signing-key.js";
export type { MCPSigningKey } from "./signing-key.js";

export { HttpSchemaPinRegistry } from "./http-pin-registry.js";
export type { HttpSchemaPinRegistryOptions } from "./http-pin-registry.js";

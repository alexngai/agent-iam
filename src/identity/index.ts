/**
 * Persistent Agent Identity Module
 *
 * Provides pluggable identity providers for establishing persistent,
 * verifiable agent identities that survive across sessions.
 */

export { IdentityService } from "./identity-service.js";
export type { IdentityServiceConfig } from "./identity-service.js";

export { KeypairIdentityProvider } from "./keypair-provider.js";
export { PlatformIdentityProvider } from "./platform-provider.js";
export {
  verifyIdentityProof,
  createEndorsement,
} from "./standalone-verifier.js";
export type {
  StandaloneVerificationResult,
  VerifiedEndorsement,
} from "./standalone-verifier.js";

export type {
  IdentityType,
  PersistentIdentity,
  IdentityProof,
  IdentityProvider,
  CreateIdentityOptions,
  TrustClaimType,
  TrustAttestation,
  TrustScore,
  TrustStore,
  AgentResourceType,
  AgentResource,
  AgentResourceRegistry,
} from "./types.js";

// Re-export token-level types related to identity
export type { AuthorityEndorsement } from "../types.js";

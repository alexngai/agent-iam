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
export { SpiffeIdentityProvider } from "./spiffe-provider.js";
export type { SpiffeCreateOptions } from "./spiffe-provider.js";
export { DidWebIdentityProvider } from "./did-web-provider.js";
export type {
  DidWebCreateOptions,
  DidDocument,
  DidVerificationMethod,
  DidService,
} from "./did-web-provider.js";
export {
  verifyIdentityProof,
  createEndorsement,
  createVcEndorsement,
  computeVcSigningPayload,
} from "./standalone-verifier.js";

// Trust store
export {
  InMemoryTrustStore,
  TrustScorer,
  createAttestation,
  signAttestation,
  verifyAttestation,
  DEFAULT_SCORING_CONFIG,
} from "./trust-store.js";
export type {
  TrustScoringConfig,
  InMemoryTrustStoreOptions,
} from "./trust-store.js";
export type {
  StandaloneVerificationResult,
  VerifiedEndorsement,
} from "./standalone-verifier.js";

// DID:key utilities
export {
  publicKeyToDidKey,
  didKeyToRawPublicKey,
  rawPublicKeyToPem,
  publicKeyToJwk,
  jwkToPem,
  isDidKey,
  isLegacyKeyId,
  base58btcEncode,
  base58btcDecode,
} from "./did-key.js";

// JCS canonicalization
export { canonicalize } from "./jcs.js";

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
export type {
  AuthorityEndorsement,
  VerifiableCredential,
  Endorsement,
} from "../types.js";
export {
  isVerifiableCredential,
  isLegacyEndorsement,
} from "../types.js";

/**
 * Agent Credential Broker
 *
 * A lightweight credential broker for AI agents that:
 * - Issues short-lived provider credentials (GitHub tokens, etc.)
 * - Uses capability tokens to control what agents can request
 * - Supports hierarchical delegation with automatic scope attenuation
 */

export { Broker } from "./broker.js";
export type { BrokerStatus } from "./broker.js";

export { TokenService, generateSecret, scopeMatches, resourceMatches } from "./token.js";

export { ConfigService } from "./config.js";

export { GitHubProvider } from "./providers/github.js";
export { GoogleProvider } from "./providers/google.js";
export { AWSProvider } from "./providers/aws.js";
export { APIKeyProvider, APIKeyProviderFactory } from "./providers/apikey.js";
export { SlackProvider } from "./providers/slack.js";

// Distributed mode
export {
  LeaderServer,
  FollowerClient,
  SigningKeyManager,
  RevocationList,
  BrokerMode,
  FollowerState,
  STATE_THRESHOLDS,
} from "./distributed/index.js";
export type {
  SyncRequest,
  SyncResponse,
  DistributedStatus,
  FollowerConfig,
  LeaderConfig,
  RevokedToken,
  VersionedKey,
} from "./distributed/index.js";

export {
  AgentRuntime,
  withRuntime,
  withRuntimeFromEnv,
  AGENT_TOKEN_ENV,
} from "./runtime.js";
export type { RuntimeConfig, RuntimeStatus } from "./runtime.js";

export type {
  AgentToken,
  DelegationRequest,
  VerificationResult,
  CredentialResult,
  Constraints,
  ScopeConstraint,
  GitHubProviderConfig,
  GoogleProviderConfig,
  AWSProviderConfig,
  APIKeyProviderConfig,
  SlackProviderConfig,
  BrokerConfig,
  SerializedToken,
  // MAP integration types
  CreateRootTokenParams,
  IdentityBinding,
  ExternalAuthInfo,
  FederatedIdentity,
  FederationMetadata,
  AgentCapabilities,
} from "./types.js";

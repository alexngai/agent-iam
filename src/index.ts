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

export type {
  AgentToken,
  DelegationRequest,
  VerificationResult,
  CredentialResult,
  Constraints,
  ScopeConstraint,
  GitHubProviderConfig,
  BrokerConfig,
  SerializedToken,
} from "./types.js";

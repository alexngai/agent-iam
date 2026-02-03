/**
 * Core types for the Agent Credential Broker
 */

/** Constraint applied to a specific scope */
export interface ScopeConstraint {
  /** Allowed resource patterns (glob-style) */
  resources?: string[];
  /** Not valid before this time */
  notBefore?: string;
  /** Not valid after this time */
  notAfter?: string;
  /** Maximum number of uses */
  maxUses?: number;
}

/** Constraints map: scope -> constraint */
export type Constraints = Record<string, ScopeConstraint>;

/** The core capability token issued to agents */
export interface AgentToken {
  /** Unique identifier for this agent */
  agentId: string;
  /** ID of parent token (undefined for root) */
  parentId?: string;
  /** Allowed scopes (e.g., "github:repo:read") */
  scopes: string[];
  /** Constraints per scope */
  constraints: Constraints;
  /** Whether this token can delegate to children */
  delegatable: boolean;
  /** Maximum delegation depth allowed */
  maxDelegationDepth: number;
  /** Current depth in delegation chain (0 for root) */
  currentDepth: number;
  /** Expiration timestamp (ISO 8601) */
  expiresAt?: string;
  /** Maximum expiration for refreshed tokens */
  maxExpiresAt?: string;
  /** HMAC signature */
  signature?: string;
}

/** Request to delegate capabilities to a child agent */
export interface DelegationRequest {
  /** ID for the new agent (auto-generated if not provided) */
  agentId?: string;
  /** Requested scopes (must be subset of parent) */
  requestedScopes: string[];
  /** Requested constraints (must be narrower than parent) */
  requestedConstraints?: Constraints;
  /** Whether child can further delegate */
  delegatable?: boolean;
  /** TTL in minutes */
  ttlMinutes?: number;
}

/** Result of token verification */
export interface VerificationResult {
  valid: boolean;
  error?: string;
}

/** Provider credential result */
export interface CredentialResult {
  /** Type of credential */
  credentialType: "bearer_token" | "aws_credentials" | "api_key";
  /** Provider-specific credential data */
  credential: Record<string, unknown>;
  /** When the credential expires */
  expiresAt?: string;
}

/** GitHub provider configuration */
export interface GitHubProviderConfig {
  /** GitHub App ID */
  appId: string;
  /** Installation ID */
  installationId: string;
  /** Path to private key PEM file */
  privateKeyPath: string;
}

/** Generic provider configuration */
export interface GenericProviderConfig {
  /** API key or token */
  apiKey: string;
}

/** Provider configurations */
export interface ProvidersConfig {
  github?: GitHubProviderConfig;
  [provider: string]: GitHubProviderConfig | GenericProviderConfig | undefined;
}

/** Broker configuration stored in config.json */
export interface BrokerConfig {
  providers: ProvidersConfig;
}

/** Serialized token for passing between processes */
export type SerializedToken = string;

/**
 * Core types for the Agent Credential Broker
 *
 * This module defines types that are:
 * - Standalone: Works without any external dependencies
 * - MAP-compatible: Optional fields align with Multi-Agent Protocol concepts
 *
 * When used standalone, the identity/federation/agentCapabilities fields are ignored.
 * When integrated with MAP (or other systems), these fields provide integration points.
 */

// ============================================================================
// Identity Binding Types
// ============================================================================

/**
 * External authentication information
 * Captures proof of authentication from an external IdP
 */
export interface ExternalAuthInfo {
  /** The identity provider (e.g., "okta", "azure-ad", "google") */
  issuer: string;
  /** Subject identifier from the IdP */
  subject: string;
  /** When authentication occurred (ISO 8601) */
  authenticatedAt: string;
  /** Original claims from the IdP (for audit) */
  claims?: Record<string, unknown>;
}

/**
 * Federated identity information
 * Tracks identity origin when token crosses system boundaries
 */
export interface FederatedIdentity {
  /** The organization that originally issued the identity */
  sourceOrganization: string;
  /** Original principal identifier */
  originalPrincipalId: string;
  /** Original system that created the token */
  originalSystemId: string;
  /** When federation occurred (ISO 8601) */
  federatedAt: string;
}

/**
 * Identity binding for an agent token
 * Links the token to an identity context (optional for standalone use)
 */
export interface IdentityBinding {
  /** System that issued this token (e.g., "map-system-alpha") */
  systemId: string;
  /** Principal (human/service) responsible for this agent (for audit) */
  principalId?: string;
  /** Type of principal */
  principalType?: "human" | "service" | "agent";
  /** Tenant identifier (for multi-tenant deployments) */
  tenantId?: string;
  /** Organization identifier */
  organizationId?: string;
  /** External authentication proof (if authenticated via external IdP) */
  externalAuth?: ExternalAuthInfo;
  /** Federated identity info (if token originated from another system) */
  federatedFrom?: FederatedIdentity;
}

// ============================================================================
// Federation Types
// ============================================================================

/**
 * Federation metadata for cross-system token usage
 * Controls how tokens can be used across system boundaries
 */
export interface FederationMetadata {
  /** Whether this token can be used across system boundaries */
  crossSystemAllowed: boolean;
  /** Specific systems where this token is allowed (undefined = all trusted) */
  allowedSystems?: string[];
  /** The system that originally created this token */
  originSystem?: string;
  /** Current hop count (incremented at each system boundary) */
  hopCount?: number;
  /** Maximum allowed hops (prevents routing loops) */
  maxHops?: number;
  /** Whether further federation is allowed (can be more restrictive than parent) */
  allowFurtherFederation?: boolean;
}

// ============================================================================
// Agent Capabilities Types
// ============================================================================

/**
 * Agent-level capabilities (beyond scope-based permissions)
 * These define what the agent can do within the system itself
 *
 * Note: These are intentionally generic. MAP or other systems can
 * map these to their specific capability models.
 */
export interface AgentCapabilities {
  /** Can this agent spawn/create child agents? */
  canSpawn?: boolean;
  /** Can this agent participate in federation? */
  canFederate?: boolean;
  /** Can this agent create scopes/groups? */
  canCreateScopes?: boolean;
  /** Visibility level of this agent */
  visibility?: "public" | "parent-only" | "scope" | "system";
  /** Can this agent send messages to other agents? */
  canMessage?: boolean;
  /** Can this agent receive messages from other agents? */
  canReceive?: boolean;
  /** Can this agent observe system events? */
  canObserve?: boolean;
  /** Custom capabilities (for extensibility) */
  custom?: Record<string, boolean>;
}

// ============================================================================
// Core Types
// ============================================================================

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

  // ==========================================================================
  // Optional fields for MAP integration (ignored in standalone mode)
  // ==========================================================================

  /**
   * Identity binding (optional)
   * Links this token to an identity context for audit and cross-system use.
   * When present, inherited through delegation chain.
   */
  identity?: IdentityBinding;

  /**
   * Federation metadata (optional)
   * Controls cross-system token usage.
   * When present, constrains how token can be used across system boundaries.
   */
  federation?: FederationMetadata;

  /**
   * Agent-level capabilities (optional)
   * Defines what the agent can do within the system (spawn, message, etc.).
   * Separate from scope-based resource access.
   */
  agentCapabilities?: AgentCapabilities;
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

  // ==========================================================================
  // Optional fields for MAP integration
  // ==========================================================================

  /**
   * Agent capabilities for the child (optional)
   * If not specified, inherits from parent with attenuation.
   * Can only be equal or more restrictive than parent.
   */
  agentCapabilities?: AgentCapabilities;

  /**
   * Whether to inherit parent's identity binding (default: true)
   * When true, child token carries parent's identity for audit trail.
   * When false, identity is cleared (useful for anonymized delegation).
   */
  inheritIdentity?: boolean;

  /**
   * Federation settings for the child (optional)
   * Can only be equal or more restrictive than parent.
   */
  federation?: Partial<FederationMetadata>;
}

/**
 * Parameters for creating a root token
 * Supports both standalone and MAP-integrated modes
 */
export interface CreateRootTokenParams {
  /** Unique identifier for this agent */
  agentId: string;
  /** Allowed scopes (e.g., "github:repo:read") */
  scopes: string[];
  /** Constraints per scope (optional) */
  constraints?: Constraints;
  /** Whether this token can delegate to children (default: true) */
  delegatable?: boolean;
  /** Maximum delegation depth allowed (default: 3) */
  maxDelegationDepth?: number;
  /** TTL in days (optional) */
  ttlDays?: number;

  // ==========================================================================
  // Optional fields for MAP integration
  // ==========================================================================

  /** Identity binding (optional) - links token to identity context */
  identity?: IdentityBinding;
  /** Federation metadata (optional) - controls cross-system usage */
  federation?: FederationMetadata;
  /** Agent-level capabilities (optional) - spawn, message, etc. */
  agentCapabilities?: AgentCapabilities;
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

/** Google OAuth provider configuration */
export interface GoogleProviderConfig {
  /** OAuth2 Client ID */
  clientId: string;
  /** OAuth2 Client Secret */
  clientSecret: string;
  /** Refresh token from initial OAuth flow */
  refreshToken: string;
}

/** AWS STS provider configuration */
export interface AWSProviderConfig {
  /** AWS region */
  region: string;
  /** IAM Role ARN to assume */
  roleArn: string;
  /** External ID for role assumption (optional) */
  externalId?: string;
  /** Session duration in seconds (default: 3600) */
  sessionDuration?: number;
  /** AWS access key ID (optional, uses default credential chain if not provided) */
  accessKeyId?: string;
  /** AWS secret access key (optional) */
  secretAccessKey?: string;
}

/** API Key provider configuration */
export interface APIKeyProviderConfig {
  /** The API key/token */
  apiKey: string;
  /** Provider name for identification (e.g., "openai", "anthropic") */
  providerName: string;
  /** How long credentials should be considered valid (in minutes, default: 60) */
  ttlMinutes?: number;
  /** Optional base URL for the API */
  baseUrl?: string;
  /** Additional headers to include */
  additionalHeaders?: Record<string, string>;
}

/** Provider configurations */
export interface ProvidersConfig {
  github?: GitHubProviderConfig;
  google?: GoogleProviderConfig;
  aws?: AWSProviderConfig;
  apikeys?: Record<string, APIKeyProviderConfig>;
  [provider: string]: GitHubProviderConfig | GoogleProviderConfig | AWSProviderConfig | Record<string, APIKeyProviderConfig> | undefined;
}

/** Broker configuration stored in config.json */
export interface BrokerConfig {
  providers: ProvidersConfig;
}

/** Serialized token for passing between processes */
export type SerializedToken = string;

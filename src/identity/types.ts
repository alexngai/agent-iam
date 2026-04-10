/**
 * Persistent Agent Identity Types
 *
 * Defines the core types for agent identity that persists across sessions.
 * Identity ("who you are") is separate from capability ("what you can do").
 *
 * Supports a pluggable provider model:
 * - keypair: Agent-owned Ed25519 keys (standalone / local-first)
 * - platform: Broker-assigned UUID with registry (team / enterprise)
 * - attested: Environment-derived identity (cloud / dynamic)
 * - decentralized: Self-sovereign DID (cross-org / portable)
 */

// ============================================================================
// Identity Type Discriminator
// ============================================================================

export type IdentityType = "keypair" | "platform" | "attested" | "decentralized";

// ============================================================================
// Core Identity Types
// ============================================================================

/**
 * Persistent identity that survives across sessions.
 * This is the core type stored on disk and embedded in tokens.
 */
export interface PersistentIdentity {
  /** Stable identifier across sessions (fingerprint, UUID, SPIFFE URI, or DID) */
  persistentId: string;
  /** How this identity was established */
  identityType: IdentityType;
  /** When this identity was first created (ISO 8601) */
  createdAt: string;
  /** Human-readable label for this agent instance */
  label?: string;
  /** Type-specific metadata (public key, issuer info, attestation details, etc.) */
  metadata: Record<string, unknown>;
}

/**
 * Identity proof that binds a persistent identity to a specific token or challenge.
 * Embedded in AgentToken to prove the token holder controls the identity.
 */
export interface IdentityProof {
  /** The persistent ID this proof is for */
  persistentId: string;
  /** Identity type (determines how to verify the proof) */
  identityType: IdentityType;
  /** The challenge/nonce that was signed (prevents replay) */
  challenge: string;
  /** Cryptographic proof (signature, attestation doc, etc.) */
  proof: string;
  /** When the proof was generated (ISO 8601) */
  provenAt: string;
}

// ============================================================================
// Identity Provider Interface
// ============================================================================

/** Options for creating a new identity */
export interface CreateIdentityOptions {
  /** Human-readable label */
  label?: string;
  /** Provider-specific options */
  [key: string]: unknown;
}

/**
 * Interface that all identity providers implement.
 * Handles the full lifecycle: create, load, prove, verify, list, revoke.
 */
export interface IdentityProvider {
  /** Which identity type this provider handles */
  readonly type: IdentityType;

  /** Create a new persistent identity */
  create(options?: CreateIdentityOptions): Promise<PersistentIdentity>;

  /** Load an existing identity by its persistent ID */
  load(persistentId: string): Promise<PersistentIdentity | null>;

  /** List all identities managed by this provider */
  list(): Promise<PersistentIdentity[]>;

  /**
   * Generate a proof binding this identity to a challenge.
   * The challenge is typically derived from token contents to prevent replay.
   */
  prove(persistentId: string, challenge: string): Promise<IdentityProof>;

  /**
   * Verify an identity proof against a challenge.
   * Returns true if the proof is valid and matches the challenge.
   */
  verify(proof: IdentityProof, challenge: string): Promise<boolean>;

  /** Revoke / delete an identity and its secrets */
  revoke(persistentId: string): Promise<void>;
}

// ============================================================================
// Trust Accumulation Types (future — interfaces only, no implementation yet)
// ============================================================================

/** Types of trust claims that can be made about an agent */
export type TrustClaimType =
  | "task-completion"
  | "security-clean"
  | "quality-score"
  | "permission-compliance"
  | "custom";

/**
 * A trust attestation about an agent's behavior.
 * Signed by the attesting party, linked to a persistent identity.
 */
export interface TrustAttestation {
  /** Unique ID for this attestation */
  attestationId: string;
  /** The agent this attestation is about */
  subjectId: string;
  /** What is being attested */
  claim: {
    type: TrustClaimType;
    /** Numeric score (0-1) or boolean or string, depending on type */
    value: unknown;
    /** Additional context (e.g., "repo:myorg/myrepo", "task:code-review") */
    context?: string;
  };
  /** Who is making this attestation (persistent ID or system ID) */
  attesterId: string;
  /** When the attestation was created (ISO 8601) */
  issuedAt: string;
  /** When this attestation expires / decays (ISO 8601) */
  expiresAt?: string;
  /** HMAC or cryptographic signature by the attester */
  signature: string;
}

/** Aggregated trust score for an agent */
export interface TrustScore {
  /** The agent's persistent ID */
  persistentId: string;
  /** Overall trust level */
  level: "unknown" | "low" | "medium" | "high";
  /** Numeric score (0–1) for finer-grained decisions than level */
  numericScore: number;
  /** Total number of (non-expired) attestations */
  attestationCount: number;
  /** Number of distinct attesters (for diversity signal) */
  attesterCount: number;
  /** Breakdown by claim type */
  breakdown: Record<string, { count: number; avgScore?: number }>;
  /** When the score was last computed */
  computedAt: string;
}

/**
 * Store for trust attestations.
 * Queried when making authorization decisions or adjusting permissions.
 *
 * **Not yet implemented** — interface only. See design doc for roadmap.
 */
export interface TrustStore {
  /** Record a new attestation */
  attest(attestation: TrustAttestation): Promise<void>;

  /** Get all non-expired attestations for an agent */
  getAttestations(persistentId: string): Promise<TrustAttestation[]>;

  /** Compute aggregate trust score */
  getTrustScore(persistentId: string): Promise<TrustScore>;

  /** Remove expired attestations */
  pruneExpired(): Promise<number>;
}

// ============================================================================
// Resource Binding Types (future — interfaces only, no implementation yet)
// ============================================================================

/** Types of resources that can be bound to an agent identity */
export type AgentResourceType =
  | "memory-store"
  | "skill-registry"
  | "preference-set"
  | "custom";

/** A resource bound to an agent's persistent identity */
export interface AgentResource {
  /** Unique resource ID */
  resourceId: string;
  /** Resource type */
  type: AgentResourceType;
  /** Where to find this resource (file path, URL, etc.) */
  endpoint: string;
  /** When this binding was created */
  boundAt: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Registry of resources bound to agent identities.
 * The persistent ID is the key — resources follow the agent across sessions.
 *
 * **Not yet implemented** — interface only. See design doc for roadmap.
 */
export interface AgentResourceRegistry {
  /** Bind a resource to an agent */
  bind(persistentId: string, resource: AgentResource): Promise<void>;

  /** Look up resources for an agent, optionally filtered by type */
  lookup(persistentId: string, type?: AgentResourceType): Promise<AgentResource[]>;

  /** Unbind a resource */
  unbind(persistentId: string, resourceId: string): Promise<void>;

  /** List all bindings for an agent */
  listAll(persistentId: string): Promise<AgentResource[]>;
}

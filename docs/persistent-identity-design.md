# Persistent Agent Identity: Design Exploration

**Status:** RFC / Brainstorm  
**Date:** April 2026

---

## Problem Statement

Today, agent-iam's `agentId` is a role label ("code-reviewer"), not a persistent instance identifier. Every session starts fresh. There is no mechanism for an agent to prove "I am the same agent that worked with you yesterday."

This limits several valuable patterns:
- **Trust accumulation** — gradually expanding permissions based on track record
- **Long-term memory** — binding persistent context/knowledge to a specific agent
- **Skill continuity** — an agent that has learned workflows doesn't lose them
- **Accountability** — audit trails that span sessions
- **Relationship building** — agents that develop working rapport with humans and other agents

## Design Goals

1. Give agents a cryptographically verifiable, persistent identity across sessions
2. Separate identity (who you are) from capability (what you can do) — they compose but don't conflate
3. Identity should survive token expiration and renewal
4. Identity should work across the existing deployment modes (standalone, distributed, federated)
5. Minimize changes to the existing capability token system

---

## Approach 1: SSH/GPG-Like — Agent-Owned Keypairs

### Concept

Each agent instance generates an asymmetric keypair on first creation. The private key is stored locally (e.g., `~/.agent-iam/identities/`). The public key becomes the agent's verifiable identity. Services and humans register trust in the public key.

### How it works

```
First session:
  Agent generates Ed25519 keypair
  → private key stored at ~/.agent-iam/identities/{agent-id}.key
  → public key registered with broker / trust store
  → fingerprint becomes the persistent identity

Subsequent sessions:
  Agent loads private key
  → signs a challenge/nonce to prove identity
  → broker issues capability token bound to this identity
```

### Types

```typescript
interface AgentKeyIdentity {
  /** Approach marker */
  type: "keypair";
  /** Stable identifier derived from public key (fingerprint) */
  persistentId: string;
  /** The public key (Ed25519, base64url) */
  publicKey: string;
  /** Key creation timestamp */
  createdAt: string;
  /** Human-readable label */
  label?: string;
}
```

### Integration with AgentToken

```typescript
interface AgentToken {
  agentId: string;              // role label (existing)
  persistentIdentity?: {        // NEW — links to long-lived identity
    persistentId: string;       // fingerprint / stable ID
    identityProof: string;      // signature over token contents using private key
    identityType: "keypair";
  };
  // ... rest unchanged
}
```

### Pros
- Agent truly owns its identity — no central authority needed
- Works offline / standalone
- Simple mental model developers already understand
- Natural revocation: delete the key, identity gone

### Cons
- Key management burden — what if the key is lost? identity is gone forever
- Key storage security — private key on disk is a theft target
- No built-in recovery — unlike OAuth, there's no "forgot password"
- Doesn't naturally support platform-managed agents (cloud-hosted agents don't have a stable filesystem)

### Best for
- Local-first / developer-machine agents
- High-autonomy agents that should own their identity
- Scenarios where decentralization matters

---

## Approach 2: OAuth/OIDC-Like — Platform-Issued Identity

### Concept

A central authority (the broker, or an external IdP) issues persistent identifiers to agents. The agent doesn't generate its own identity — it receives one. Identity persists because the authority remembers the mapping.

### How it works

```
Registration:
  Broker (or IdP) creates agent record
  → assigns persistent ID (UUID or URI)
  → stores metadata (role, owner, creation date)
  → issues long-lived refresh token bound to this identity

Each session:
  Agent presents refresh token
  → broker validates, issues short-lived capability token
  → capability token carries persistent ID claim
  → refresh token optionally rotated
```

### Types

```typescript
interface PlatformIssuedIdentity {
  type: "platform";
  /** Stable agent identifier (UUID or URI) */
  persistentId: string;
  /** The authority that issued this identity */
  issuer: string;
  /** When the identity was created */
  createdAt: string;
  /** The principal (human/service) that registered this agent */
  registeredBy: string;
  /** Long-lived refresh token for session continuity */
  refreshToken?: string;
  /** Refresh token expiry (can be very long-lived) */
  refreshExpiresAt?: string;
}
```

### Integration with AgentToken

```typescript
interface AgentToken {
  agentId: string;
  persistentIdentity?: {
    persistentId: string;       // platform-assigned UUID
    issuer: string;             // who vouches for this identity
    identityType: "platform";
  };
  // ... rest unchanged
}
```

### Pros
- Central authority can manage lifecycle (revocation, rotation, recovery)
- Fits naturally into enterprise/team deployments
- Broker already exists — it just needs a registry
- Recovery possible — authority can re-issue identity to the same agent
- Maps cleanly to existing `IdentityBinding.systemId` concept

### Cons
- Central dependency — identity is only as available as the authority
- Agent doesn't truly "own" its identity — it's granted by the platform
- Requires persistent storage in the broker (agent registry)
- Less natural for standalone/local-first use cases

### Best for
- Team / enterprise deployments
- Cloud-hosted agents
- Scenarios needing administrative control over agent lifecycle

---

## Approach 3: SPIFFE-Like — Workload-Attested Identity

### Concept

Identity is derived from verifiable properties of the agent's environment (attestation), not from a stored secret. The agent's identity is a URI like `spiffe://example.com/agent/code-reviewer/instance/abc123`, and proof comes from platform attestation rather than a long-lived key.

### How it works

```
Identity establishment:
  Agent starts in a known environment (container, process, user session)
  → attestor verifies environment properties (pid, user, binary hash, etc.)
  → issues short-lived identity document (SVID) bound to SPIFFE ID
  → SPIFFE ID is the persistent identity; SVIDs rotate frequently

Cross-session continuity:
  SPIFFE ID remains stable: spiffe://trust-domain/agent/{role}/{instance-id}
  → instance-id derived from stable properties (user + machine + config hash)
  → each session gets a fresh SVID, but the underlying ID is the same
```

### Types

```typescript
interface WorkloadAttestedIdentity {
  type: "attested";
  /** SPIFFE-style URI: agent://{trust-domain}/{role}/{instance-id} */
  persistentId: string;
  /** Trust domain this identity belongs to */
  trustDomain: string;
  /** How identity was attested */
  attestation: {
    method: "process" | "container" | "cloud-metadata" | "token-exchange";
    /** Attested properties used to derive identity */
    properties: Record<string, string>;
    /** When attestation occurred */
    attestedAt: string;
  };
  /** Short-lived identity document (signed by attestor) */
  svid?: string;
  svidExpiresAt?: string;
}
```

### Integration with AgentToken

```typescript
interface AgentToken {
  agentId: string;
  persistentIdentity?: {
    persistentId: string;       // agent://trust-domain/role/instance
    attestation: string;        // method used
    identityType: "attested";
  };
  // ... rest unchanged
}
```

### Pros
- No long-lived secrets to steal or lose
- Identity is verifiable from environment, not just claimed
- Short-lived documents mean compromise is time-bounded
- Scales well to dynamic environments (containers, cloud functions)
- Natural fit for agent-iam's existing short-lived token philosophy

### Cons
- Requires an attestor component (additional infrastructure)
- Attestation properties may not be stable enough (what if agent moves machines?)
- More complex to implement than keypair or platform approaches
- "Stable properties" for agents are harder to define than for traditional workloads

### Best for
- Distributed / cloud deployments
- High-security environments
- Dynamic infrastructure where agents move between hosts

---

## Approach 4: DID/VC-Like — Self-Sovereign with Verifiable Credentials

### Concept

Agents create their own decentralized identifier (DID) and accumulate verifiable credentials (VCs) signed by others. The agent carries its own identity and proof of trust — no central authority needed to verify.

### How it works

```
Identity creation:
  Agent generates DID: did:agent:{method-specific-id}
  → DID document contains public key, service endpoints
  → stored locally or on a decentralized registry

Trust accumulation:
  After completing tasks, agent receives VCs:
  → "completed 50 tasks for user@example.com" (signed by user's DID)
  → "no security violations in 30 days" (signed by security auditor)
  → VCs are portable — agent carries them to new contexts

Presenting identity:
  Agent presents DID + relevant VCs
  → verifier checks VC signatures against issuer DIDs
  → no central lookup needed
```

### Types

```typescript
interface DecentralizedIdentity {
  type: "decentralized";
  /** DID URI: did:agent:{id} */
  persistentId: string;
  /** DID Document (contains public keys, services) */
  document: {
    id: string;
    verificationMethod: Array<{
      id: string;
      type: string;
      publicKeyMultibase: string;
    }>;
    service?: Array<{
      id: string;
      type: string;
      serviceEndpoint: string;
    }>;
  };
  /** Verifiable Credentials accumulated over time */
  credentials: VerifiableCredential[];
}

interface VerifiableCredential {
  /** What this credential attests */
  type: string;
  /** Who issued it */
  issuer: string;
  /** When it was issued */
  issuanceDate: string;
  /** Optional expiry */
  expirationDate?: string;
  /** The claims */
  credentialSubject: Record<string, unknown>;
  /** Issuer's signature */
  proof: string;
}
```

### Integration with AgentToken

```typescript
interface AgentToken {
  agentId: string;
  persistentIdentity?: {
    persistentId: string;       // did:agent:abc123
    credentials?: string[];     // relevant VC IDs (full VCs fetched separately)
    identityType: "decentralized";
  };
  // ... rest unchanged
}
```

### Pros
- Fully portable — agent carries identity and credentials everywhere
- No central dependency for verification
- Trust accumulation is a first-class concept (VCs)
- Composable — different credentials from different issuers
- Most aligned with the "agent as autonomous entity" philosophy

### Cons
- Most complex to implement
- DID ecosystem is still maturing, standards are heavy
- Credential management is non-trivial (storage, expiry, revocation)
- Overkill for single-user local deployments
- Verification requires understanding of DID methods

### Best for
- Cross-organizational agent interactions
- Agents that need portable trust (move between platforms)
- Long-lived agents that build reputation over time

---

## Comparison Matrix

| Dimension | Keypair (SSH) | Platform (OAuth) | Attested (SPIFFE) | Decentralized (DID) |
|---|---|---|---|---|
| **Identity owned by** | Agent | Platform | Environment | Agent |
| **Persistence mechanism** | Private key on disk | Registry record | Stable env properties | DID document |
| **Secret management** | Agent stores key | Platform stores mapping | No long-lived secret | Agent stores key |
| **Recovery** | Not possible (key loss = identity loss) | Platform re-issues | Re-attest | Not possible (key loss) |
| **Trust accumulation** | External (authorized_keys) | External (platform policy) | External (policy engine) | Built-in (VCs) |
| **Cross-system portability** | Manual (copy pubkey) | Federation protocols | Trust domain peering | Fully portable |
| **Standalone friendly** | Yes | Needs registry | Needs attestor | Yes |
| **Implementation complexity** | Low | Medium | High | High |
| **Best deployment mode** | Standalone | Distributed / Federated | Distributed | Federated / Cross-org |

---

## Recommended Approach: Layered Hybrid

Rather than picking one approach, agent-iam could support a **pluggable identity layer** where the persistent identity mechanism is chosen based on deployment mode:

```
┌─────────────────────────────────────────────────────────┐
│                    AgentToken                            │
│  ┌───────────┐  ┌──────────────────────────────┐        │
│  │ agentId   │  │ persistentIdentity?          │        │
│  │ (role)    │  │ ┌──────────────────────────┐ │        │
│  │           │  │ │ persistentId: string     │ │        │
│  └───────────┘  │ │ identityType: IdentType  │ │        │
│                 │ │ proof: string            │ │        │
│  ┌───────────┐  │ └──────────────────────────┘ │        │
│  │ scopes    │  └──────────────────────────────┘        │
│  │ (caps)    │                                          │
│  └───────────┘  Capability (what) is separate from      │
│                 Identity (who). They compose.            │
└─────────────────────────────────────────────────────────┘

Identity providers (pluggable):

  ┌──────────────────┐  Standalone deployments
  │ KeypairIdentity  │  Agent generates Ed25519 keypair
  │ Provider         │  Stored in ~/.agent-iam/identities/
  └──────────────────┘

  ┌──────────────────┐  Team / enterprise deployments
  │ PlatformIdentity │  Broker assigns UUID
  │ Provider         │  Backed by agent registry
  └──────────────────┘

  ┌──────────────────┐  Cloud / dynamic deployments
  │ AttestedIdentity │  Derived from environment
  │ Provider         │  Short-lived SVIDs
  └──────────────────┘

  ┌──────────────────┐  Cross-org / portable agents
  │ DecentralizedId  │  Self-sovereign DID
  │ Provider         │  Carries VCs for trust
  └──────────────────┘
```

### Core Interface (Shared by all providers)

```typescript
/**
 * Persistent identity that survives across sessions.
 * Separate from capability tokens — identity is "who",
 * tokens are "what you can do".
 */
interface PersistentIdentity {
  /** Stable identifier across sessions */
  persistentId: string;
  /** How this identity was established */
  identityType: "keypair" | "platform" | "attested" | "decentralized";
  /** Cryptographic proof of identity (type-specific) */
  proof: string;
  /** When this identity was first created */
  createdAt: string;
  /** Human-readable label for this agent instance */
  label?: string;
  /** Type-specific metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Interface that all identity providers implement.
 * Handles lifecycle: create, prove, verify, store, recover.
 */
interface IdentityProvider {
  readonly type: PersistentIdentity["identityType"];

  /** Create a new persistent identity */
  create(options: CreateIdentityOptions): Promise<PersistentIdentity>;

  /** Load an existing identity (returns null if not found) */
  load(persistentId: string): Promise<PersistentIdentity | null>;

  /** Generate proof for binding identity to a token */
  prove(identity: PersistentIdentity, challenge: string): Promise<string>;

  /** Verify an identity proof */
  verify(identity: PersistentIdentity, challenge: string, proof: string): Promise<boolean>;

  /** List all known identities managed by this provider */
  list(): Promise<PersistentIdentity[]>;

  /** Revoke / delete an identity */
  revoke(persistentId: string): Promise<void>;
}
```

### Trust Accumulation (Identity-Adjacent)

Regardless of which identity provider is used, trust can accumulate against the `persistentId`:

```typescript
/**
 * A trust attestation about an agent's behavior.
 * Signed by the attesting party, linked to persistentId.
 */
interface TrustAttestation {
  /** The agent this attestation is about */
  subjectId: string;
  /** What is being attested */
  claim: {
    type: "task-completion" | "security-clean" | "quality-score" | "custom";
    value: unknown;
    context?: string;
  };
  /** Who is making this attestation */
  attesterId: string;
  /** When */
  issuedAt: string;
  /** Expiry (trust can decay) */
  expiresAt?: string;
  /** Signature by attester */
  signature: string;
}

/**
 * Trust store that accumulates attestations for agents.
 * Queried when making authorization decisions.
 */
interface TrustStore {
  /** Record a new attestation */
  attest(attestation: TrustAttestation): Promise<void>;

  /** Get all attestations for an agent */
  getAttestations(persistentId: string): Promise<TrustAttestation[]>;

  /** Compute aggregate trust score */
  getTrustScore(persistentId: string): Promise<TrustScore>;
}

interface TrustScore {
  /** Overall trust level */
  level: "unknown" | "low" | "medium" | "high";
  /** Number of attestations */
  attestationCount: number;
  /** Breakdown by claim type */
  breakdown: Record<string, { count: number; avgScore?: number }>;
}
```

### Resource Binding (Identity as a Key)

The persistent ID becomes a lookup key for agent-specific resources:

```typescript
/**
 * Registry of resources bound to an agent's persistent identity.
 * The persistent ID is the key — resources follow the agent across sessions.
 */
interface AgentResourceRegistry {
  /** Bind a resource to an agent */
  bind(persistentId: string, resource: AgentResource): Promise<void>;

  /** Look up resources for an agent */
  lookup(persistentId: string, type?: string): Promise<AgentResource[]>;

  /** Unbind a resource */
  unbind(persistentId: string, resourceId: string): Promise<void>;
}

interface AgentResource {
  resourceId: string;
  type: "memory-store" | "skill-registry" | "preference-set" | "custom";
  /** Where to find this resource */
  endpoint: string;
  /** Access metadata */
  metadata?: Record<string, unknown>;
}
```

---

## Self-Certifying Verification & Authority Endorsements

### The Problem: Remote Verification Without Broker Access

A key scenario: an agent runs locally with a local broker, but needs to prove its identity to a remote online service. The service has no access to the broker.

### Solution: Self-Certifying Tokens

The token carries everything needed for verification:

```
Token.persistentIdentity = {
  persistentId: "key:abc123...",           // Fingerprint of public key
  identityType: "keypair",
  publicKey: "-----BEGIN PUBLIC KEY-----\n...",  // Full public key (PEM)
  challenge: "agent-id:timestamp:nonce",   // What was signed
  proof: "base64url-ed25519-signature",    // Ed25519 signature over challenge
  endorsements?: [...]                     // Optional authority endorsements
}
```

A remote verifier checks three things:
1. **Fingerprint match**: SHA-256(publicKey) == persistentId → the key matches the claimed identity
2. **Proof verification**: Ed25519.verify(challenge, proof, publicKey) → the creator held the private key
3. **Endorsements** (optional): authority signatures over (persistentId + publicKey + claim)

No broker access needed. No network call. Pure cryptographic verification.

### Trust Model: TOFU + Progressive Endorsement

```
┌──────────────────────────────────────────────────────────────────────┐
│                        TRUST PROGRESSION                             │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Day 1: Self-Signed (TOFU)                                           │
│  ┌─────────────────────────────────┐                                 │
│  │ Agent presents token            │  Trust: "I've seen this key     │
│  │ Service verifies Ed25519 proof  │         before" (low)           │
│  │ Service stores publicKey        │                                 │
│  └─────────────────────────────────┘                                 │
│                                                                       │
│  Day 30: Behavioral Trust                                            │
│  ┌─────────────────────────────────┐                                 │
│  │ Same key, 100 interactions      │  Trust: "This agent is          │
│  │ Service recognizes publicKey    │         reliable" (accumulated) │
│  └─────────────────────────────────┘                                 │
│                                                                       │
│  Day 45: Authority-Endorsed                                          │
│  ┌─────────────────────────────────┐                                 │
│  │ Token now includes endorsement  │  Trust: "Reliable AND vouched   │
│  │ from "acme-corp" signing the    │         for by Acme" (high)     │
│  │ agent's public key + claim      │                                 │
│  └─────────────────────────────────┘                                 │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### Authority Endorsements

An endorsement is an authority's Ed25519 signature over `(persistentId + publicKey + claim)`:

```typescript
interface AuthorityEndorsement {
  authorityId: string;           // "acme-corp"
  authorityPublicKey: string;    // Authority's Ed25519 public key
  claim: string;                 // "member-of:acme-engineering"
  signature: string;             // Ed25519 sign(persistentId + publicKey + claim)
  issuedAt: string;
  expiresAt?: string;
}
```

Verification:
- The remote service has a set of trusted authority public keys
- For each endorsement, check: `authorityPublicKey ∈ trustedAuthorities` AND `Ed25519.verify(payload, signature, authorityPublicKey)`
- Untrusted/expired endorsements are silently ignored (identity is still valid via self-signed)

### Symmetric vs Asymmetric Identity

| Property | Keypair (Ed25519) | Platform (HMAC) |
|---|---|---|
| **Standalone verification** | Yes — public key in token | No — needs broker's shared secret |
| **Remote verification** | Yes — anyone with public key | No — only broker can verify |
| **Key management** | Agent owns private key | Broker owns shared secret |
| **Best for** | Cross-system, remote services | Local/internal, broker-mediated |

Platform (HMAC) identities intentionally cannot be verified standalone — this is a fundamental property of symmetric cryptography. When `createRootTokenWithIdentity()` is called with a platform identity, the token's `publicKey` field will be `undefined` (since HMAC has no public key). This means `verifyIdentityProof()` will reject the token — use `Broker.verifyTokenIdentity()` instead. For remote verification scenarios where the verifier has no broker access, keypair identities are required.

### Standalone Verifier API

```typescript
import { verifyIdentityProof, createEndorsement } from "agent-iam";

// Remote service verifies agent identity (no broker needed)
const result = verifyIdentityProof(token, {
  trustedAuthorities: {
    "acme-corp": acmePublicKeyPem,
  },
});

if (result.valid) {
  console.log(`Agent: ${result.persistentId}`);
  console.log(`Public key: ${result.publicKey}`);
  console.log(`Endorsements: ${result.verifiedEndorsements}`);
}

// Authority creates an endorsement for an agent
const endorsement = createEndorsement(
  "acme-corp",
  authorityPrivateKey,
  authorityPublicKey,
  agentPersistentId,
  agentPublicKey,
  "member-of:acme-engineering",
  "2027-01-01T00:00:00Z" // optional expiry
);
```

---

## Implementation Phases

### Phase 1: Core Identity Layer ✅
- `PersistentIdentity` type and `IdentityProvider` interface
- `KeypairIdentityProvider` (Ed25519, file-backed, standalone-friendly)
- `PlatformIdentityProvider` (HMAC, registry-backed, team/enterprise)
- `IdentityService` orchestrator with pluggable providers
- `persistentIdentity` field on `AgentToken`
- Token creation/delegation/refresh preserves identity binding

### Phase 2: Proof-of-Possession ✅
- `createRootTokenWithIdentity()` calls `prove()` and embeds cryptographic proof
- `verifyTokenIdentity()` on broker verifies proof against identity provider
- Impersonation prevention via Ed25519 signature / HMAC verification

### Phase 3: Self-Certifying Verification ✅
- Public key embedded in token for brokerless verification
- `verifyIdentityProof()` standalone function — pure crypto, no broker needed
- Fingerprint check: public key hash must match claimed persistentId
- Authority endorsement creation and verification
- TOFU support for remote services

### Phase 4: Trust Accumulation (future)
- `TrustAttestation` and `TrustStore` interfaces (types defined)
- Local file-based trust store
- Basic trust scoring

### Phase 5: Resource Binding (future)
- `AgentResourceRegistry` interface (types defined)
- Memory store and skill registry bindings
- Cross-session resource continuity

### Phase 6: Additional Providers (future)
- `AttestedIdentityProvider` (SPIFFE-like, for cloud deployments)
- `DecentralizedIdentityProvider` (DID-based, for cross-org)
- Federation of identities across trust domains

---

## Open Questions

1. **Identity granularity**: Is one identity per agent role sufficient, or do we need per-user-per-role identities? (e.g., "code-reviewer for alice" vs "code-reviewer for bob")

2. **Identity portability**: If an agent moves from Claude to GPT-4 (same role, different model), is it the same identity? Does the model matter for identity, or only the role + context?

3. **Delegation and identity**: When a parent delegates to a child, should the child inherit the parent's persistent identity, get its own, or both (linked)?

4. **Trust decay**: Should trust attestations expire? If an agent hasn't been used in 6 months, should its trust level reset?

5. **Multi-tenant identity**: In enterprise deployments, should an agent have one identity per tenant, or one global identity with per-tenant trust?

6. **Identity and model updates**: When the underlying model is updated (Claude 3 → Claude 4), does the agent retain its identity? The "personality" has changed — is it still the same agent?

7. **Key rotation**: How should an agent rotate its keypair while maintaining continuity of identity? Could the old key sign a "succession" endorsement for the new key?

8. **Endorsement revocation**: If an authority revokes an endorsement, how do verifiers learn about it? CRL-like list? Short-lived endorsements that must be refreshed?

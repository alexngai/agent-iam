# Agent IAM

A capability-based credential broker for AI agents. Manages what agents can do through cryptographically signed tokens that support hierarchical delegation with automatic scope attenuation. Includes a persistent identity system for cross-session agent identity with self-certifying verification.

## Features

- **Capability Tokens**: HMAC-SHA256 signed tokens defining allowed scopes and constraints
- **Hierarchical Delegation**: Agents can delegate narrower capabilities to sub-agents
- **Persistent Identity**: Ed25519 keypair or platform-assigned identities that survive across sessions
- **Self-Certifying Verification**: Remote services can verify agent identity without broker access
- **Authority Endorsements**: Trusted parties can vouch for agent identities (X.509/VC-like)
- **Provider Adapters**: GitHub, Google OAuth, AWS STS, Slack, and generic API keys
- **MCP Tool Access Control**: Allow/deny scopes, tool-schema TOFU pinning (rug-pull defense), RFC 8707 audience-bound credentials, server-identity verification, structured audit pipeline, and a shared HTTP pin registry for ephemeral agents. See [docs/mcp-policy.md](docs/mcp-policy.md) for the integrator contract.
- **Distributed Mode**: Leader/follower sync for multi-region deployments (signing keys, provider configs, MCP deny policy, revocations)
- **Token Refresh**: Background refresh for long-running agents
- **CLI & Library**: Use programmatically or via command line

## Installation

```bash
npm install agent-iam
```

## Quick Start

### 1. Create and Delegate Tokens

```typescript
import { Broker } from "agent-iam";

const broker = new Broker();

// Create root token for orchestrator
const rootToken = broker.createRootToken({
  agentId: "orchestrator",
  scopes: ["github:repo:read", "github:repo:write", "openai:chat:*"],
  constraints: {
    "github:repo:*": { resources: ["myorg/*"] },
  },
  maxDelegationDepth: 3,
  ttlDays: 7,
});

// Delegate narrower capabilities to sub-agent
const childToken = broker.delegate(rootToken, {
  agentId: "code-reviewer",
  requestedScopes: ["github:repo:read"],  // Only read access
  requestedConstraints: {
    "github:repo:read": { resources: ["myorg/frontend"] },  // Single repo
  },
  ttlMinutes: 60,
});

// Verify and check permissions
const result = broker.verifyToken(childToken);
console.log(result.valid);  // true

const canRead = broker.checkPermission(childToken, "github:repo:read", "myorg/frontend");
console.log(canRead.valid);  // true

const canWrite = broker.checkPermission(childToken, "github:repo:write", "myorg/frontend");
console.log(canWrite.valid);  // false
```

### 2. Pass Tokens to Subprocesses

```typescript
import { Broker, AgentRuntime, AGENT_TOKEN_ENV } from "agent-iam";
import { spawn } from "child_process";

const broker = new Broker();
const token = broker.createRootToken({
  agentId: "parent",
  scopes: ["github:repo:read"],
  ttlDays: 1,
});

const runtime = new AgentRuntime(token);
runtime.start();

// Create environment for subprocess
const childEnv = runtime.createSubprocessEnv({
  agentId: "child-task",
  requestedScopes: ["github:repo:read"],
  ttlMinutes: 30,
});

// Token passed via AGENT_TOKEN environment variable
spawn("node", ["child.js"], { env: { ...process.env, ...childEnv } });

// In child.js:
const childRuntime = AgentRuntime.fromEnvironment();
childRuntime.start();
```

### 3. Get Provider Credentials

```typescript
const broker = new Broker();

// Configure providers
broker.initProvider("github", {
  appId: "12345",
  installationId: "67890",
  privateKeyPath: "./github-app.pem",
});

broker.addAPIKey({
  name: "openai",
  providerName: "openai",
  apiKey: "sk-...",
});

// Create token and get credentials
const token = broker.createRootToken({
  agentId: "my-agent",
  scopes: ["github:repo:read", "openai:chat:*"],
  ttlDays: 1,
});

const githubCred = await broker.getCredential(token, "github:repo:read", "myorg/repo");
// { credentialType: "bearer_token", credential: { token: "ghs_..." }, expiresAt: "..." }

const openaiCred = await broker.getCredential(token, "openai:chat:completions", "");
// { credentialType: "api_key", credential: { apiKey: "sk-...", headers: {...} }, expiresAt: "..." }
```

### 4. Persistent Agent Identity

Give agents a cryptographic identity that persists across sessions. Identity ("who you are") is separate from capabilities ("what you can do").

```typescript
import { Broker, verifyIdentityProof, createEndorsement } from "agent-iam";

const broker = new Broker();

// Create a persistent identity (Ed25519 keypair stored locally)
const identity = await broker.createIdentity({ type: "keypair", label: "my-code-reviewer" });
// identity.persistentId === "key:a1b2c3..."

// Create token bound to the identity (proof-of-possession)
const token = await broker.createRootTokenWithIdentity(
  { agentId: "code-reviewer", scopes: ["github:repo:read"], ttlDays: 7 },
  identity.persistentId
);
// Token now contains: public key + Ed25519 signature proving key ownership
```

#### Remote Verification (No Broker Needed)

A remote service can verify the agent's identity using only the token — no broker access required:

```typescript
// On the remote service (no broker, no shared secrets)
import { verifyIdentityProof } from "agent-iam";

const result = verifyIdentityProof(token);
if (result.valid) {
  console.log(`Verified agent: ${result.persistentId}`);
  console.log(`Public key: ${result.publicKey}`);
  // Store the public key for future recognition (TOFU)
}
```

#### Authority Endorsements

Trusted authorities can vouch for an agent's identity:

```typescript
// Authority signs the agent's public key + claim
const endorsement = createEndorsement(
  "acme-corp",                      // Authority ID
  authorityPrivateKey,              // Authority's Ed25519 private key
  authorityPublicKey,               // Authority's Ed25519 public key
  identity.persistentId,            // Agent's persistent ID
  token.persistentIdentity.publicKey, // Agent's public key
  "member-of:acme-engineering"      // What the authority attests
);

// Attach to token
token.persistentIdentity.endorsements = [endorsement];

// Remote service verifies with trusted authority keys
const result = verifyIdentityProof(token, {
  trustedAuthorities: { "acme-corp": acmePublicKeyPem },
});
// result.verifiedEndorsements === [{ authorityId: "acme-corp", claim: "member-of:acme-engineering" }]
```

#### Identity Management CLI

```bash
# Create identities
agent-iam identity create --type keypair --label "my-agent"
agent-iam identity create --type platform --label "team-agent"

# List and inspect
agent-iam identity list
agent-iam identity show key:a1b2c3...

# Bind to token
agent-iam token create-root --agent-id myagent --scopes "github:repo:read" --identity key:a1b2c3...

# Revoke
agent-iam identity revoke key:a1b2c3...
```

#### Trust Model

| Level | Mechanism | What it proves |
|-------|-----------|---------------|
| **Self-signed (TOFU)** | Ed25519 proof in token | "This is the same agent I've seen before" |
| **Behavioral** | Service tracks interactions | "This agent has been reliable over 100 requests" |
| **Authority-endorsed** | Authority signature on public key | "A trusted party vouches for this agent" |

### 5. MCP Tool Access Control

Agent-iam ships a defense-in-depth toolkit for agents that connect to MCP
servers. The agent harness — the trusted code around an LLM that
dispatches tool calls — owns enforcement; agent-iam distributes signed
policy and pure-function helpers.

```typescript
import {
  Broker,
  checkMCPCall,
  verifyToolSchema,
  requireApprovalIf,
  denyIf,
  formatDecision,
  FileSchemaPinRegistry,
  FileAuditSink,
  buildDecisionEvent,
} from "agent-iam";

const broker = new Broker();
const pinRegistry = new FileSchemaPinRegistry();
const auditSink = new FileAuditSink("/var/log/agent-iam/audit.jsonl");

async function dispatchToolCall(token, server, toolDef, args) {
  // 1. Schema TOFU — detects tool rug-pulls (CVE-2025-54136 class).
  const pin = await verifyToolSchema(server, toolDef, pinRegistry);
  if (!pin.valid) return askUser(`Schema for ${server}/${toolDef.name} changed`);

  // 2. Allow/deny scope policy with org-wide deny override.
  let decision = checkMCPCall(token, server, toolDef.name, args, {
    brokerDenyPolicy: broker.getMCPDenyPolicy(),
  });

  // 3. Annotation-aware escalation (only for trusted servers).
  decision = requireApprovalIf(decision, toolDef.annotations, "destructiveHint");
  decision = denyIf(decision, toolDef.annotations, "openWorldHint");

  // 4. Structured audit log.
  await auditSink.record(buildDecisionEvent({
    agentId: token.agentId, server, tool: toolDef.name, decision,
  }));

  if (decision.kind === "deny") throw new PermissionError(decision.reason);
  if (decision.kind === "ask")  await promptHuman(decision.reason);
  return invokeTool(server, toolDef.name, args);
}
```

#### RFC 8707 audience-bound credentials

When an MCP server uses OAuth-style auth, the broker signs a per-server
JWT bound to the server's canonical URI. Tokens cannot be replayed across
servers — the MCP authorization spec **MUSTs** this.

```typescript
const cred = await broker.issueForMCPServer({
  agentToken: token,
  serverURI: "https://filesystem.example.com",
  scopes: ["mcp:filesystem:read_file"],
  ttlSeconds: 300,
});
// Pass cred.jwt to the MCP server's Authorization header.
```

The broker manages its own EdDSA keypair under
`~/.agent-credentials/mcp-signing.{key,pub}`. Distribute the public key as
JWKS:

```bash
agent-iam mcp jwks > /srv/www/.well-known/jwks.json
```

#### Org-wide deny policy

Persisted in broker config; propagates leader → follower automatically in
distributed mode.

```bash
agent-iam mcp deny add 'mcp:shell:*'   # nobody runs shell tools, ever
agent-iam mcp deny list
```

#### Reference harness

A complete integration in ~80 lines lives at
[examples/mcp-harness/](examples/mcp-harness/). The full integrator
contract — including the HTTP pin-registry contract for shared
deployments and the four call sites in dispatch order — is in
[docs/mcp-policy.md](docs/mcp-policy.md).

## Scope Format

Scopes follow `provider:resource:action` pattern:

| Scope | Description |
|-------|-------------|
| `github:repo:read` | Read GitHub repositories |
| `github:repo:write` | Write to repositories |
| `github:repo:*` | All repo operations |
| `aws:s3:read` | Read from S3 |
| `aws:s3:write` | Write to S3 |
| `openai:chat:*` | All chat operations |
| `openai:embeddings:create` | Create embeddings |
| `system:token:refresh` | Can refresh own token |

## Constraints

Constraints restrict when/where a scope can be used:

```typescript
const token = broker.createRootToken({
  agentId: "restricted-agent",
  scopes: ["github:repo:read"],
  constraints: {
    "github:repo:read": {
      resources: ["myorg/*", "partner/shared-*"],  // Glob patterns
      notBefore: "2024-01-01T00:00:00Z",           // Time window start
      notAfter: "2024-12-31T23:59:59Z",            // Time window end
      maxUses: 100,                                 // Usage limit
    },
  },
  ttlDays: 30,
});
```

## CLI Usage

```bash
# Configuration
agent-iam config show
agent-iam config init github --app-id 123 --installation-id 456 --private-key ./key.pem
agent-iam config init google --client-id ... --client-secret ... --refresh-token ...
agent-iam config init aws --region us-east-1 --role-arn arn:aws:iam::123456789012:role/MyRole

# API Keys
agent-iam apikey add --name openai --provider openai --key sk-...
agent-iam apikey list
agent-iam apikey remove openai

# Identity
agent-iam identity create --type keypair --label "my-agent"
agent-iam identity create --type platform --label "team-agent"
agent-iam identity list
agent-iam identity show key:a1b2c3...
agent-iam identity revoke key:a1b2c3...

# Tokens
agent-iam token create-root --agent-id myagent --scopes "github:repo:read" --ttl-days 7
agent-iam token create-root --agent-id myagent --scopes "github:repo:read" --identity key:a1b2c3...
agent-iam token delegate --parent <token> --scopes "github:repo:read" --ttl-minutes 60
agent-iam token verify <token>
agent-iam token show <token>

# Credentials
agent-iam cred github:repo:read myorg/myrepo --token <token>

# MCP access control
agent-iam mcp test --token <token> [--broker-deny <pat...>] <server> <tool>
agent-iam mcp deny list
agent-iam mcp deny add 'mcp:shell:*'
agent-iam mcp deny remove 'mcp:shell:*'
agent-iam mcp pin-list [--server <name>]
agent-iam mcp pin-clear <server> [tool]
agent-iam mcp jwks                                         # publish broker pubkey
agent-iam mcp issue-cred <serverURI> --token <T> --scopes <S...> [--ttl <s>] [--issuer <iss>]

# Status
agent-iam status
```

## Distributed Mode

For multi-region deployments with leader/follower sync:

```bash
# Start leader server
agent-iam serve --port 8443 --auth-token <secret>

# Start follower
agent-iam follower --leader-url https://leader:8443 --auth-token <secret> --follower-id region-b

# Operations
agent-iam rotate-key                          # Rotate signing key
agent-iam revoke <token-id> --reason "..."    # Revoke token
agent-iam sync --leader-url ... --auth-token ... --follower-id ...  # Force sync
```

```typescript
import { Broker, LeaderServer, FollowerClient } from "agent-iam";

// Leader
const leader = new LeaderServer(broker, configDir, {
  port: 8443,
  followerAuthToken: "shared-secret",
});
await leader.start();

// Follower
const follower = new FollowerClient(broker, configDir, {
  leaderUrl: "https://leader:8443",
  leaderAuthToken: "shared-secret",
  followerId: "region-b",
});
await follower.start();
```

## Security Model

1. **Cryptographic Verification**: All tokens signed with HMAC-SHA256
2. **Proof-of-Possession**: Identity bound to tokens via Ed25519 signatures
3. **Self-Certifying**: Tokens carry public keys for broker-free verification
4. **Least Privilege**: Delegation can only narrow capabilities, never widen
5. **Anti-Impersonation**: Public key fingerprint must match claimed persistentId
6. **Time-Bounded**: All tokens expire; constraints can add time windows
7. **Tamper-Proof**: Any token modification invalidates signature
8. **Revocation**: Centralized revocation synced to followers; identity revocation supported
9. **Key Rotation**: Supports key rotation with grace period for old tokens

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Broker                                   │
│  - Token creation, verification, delegation                      │
│  - Credential issuance from providers                           │
│  - Identity management (create, prove, verify, revoke)          │
│  - Configuration management                                      │
└──────────┬──────────────────────────┬───────────────────────────┘
           │                          │
   ┌───────┴───────┐        ┌────────┴────────┐
   │   Providers   │        │ Identity Service │
   ├───────────────┤        ├─────────────────┤
   │ GitHub        │        │ Keypair (Ed25519)│  ← Self-certifying
   │ Google OAuth  │        │ Platform (HMAC)  │  ← Broker-managed
   │ AWS STS       │        │ (pluggable)      │
   │ Slack         │        └─────────────────┘
   │ API Keys      │
   └───────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      AgentRuntime                                │
│  - Token lifecycle management                                   │
│  - Persistent identity access (getPersistentId())               │
│  - Background refresh                                           │
│  - Subprocess environment creation                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│              Standalone Verifier (no broker needed)              │
│  - verifyIdentityProof() — Ed25519 proof verification           │
│  - Fingerprint check (public key → persistentId)                │
│  - Authority endorsement verification                           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Distributed Mode                              │
│  Leader ◄──────sync──────► Follower                             │
│  - Signing keys, revocation lists, provider configs             │
└─────────────────────────────────────────────────────────────────┘
```

## API Reference

### Broker

```typescript
class Broker {
  constructor(configDir?: string);

  // Token operations
  createRootToken(params: CreateRootTokenParams): AgentToken;
  delegate(parent: AgentToken, request: DelegationRequest): AgentToken;
  verifyToken(token: AgentToken): VerificationResult;
  checkPermission(token: AgentToken, scope: string, resource: string): VerificationResult;
  refreshToken(token: AgentToken, ttlMinutes?: number): AgentToken;

  // Identity operations
  createIdentity(options?: { label?: string; type?: "keypair" | "platform" }): Promise<PersistentIdentity>;
  loadIdentity(persistentId: string): Promise<PersistentIdentity | null>;
  listIdentities(): Promise<PersistentIdentity[]>;
  revokeIdentity(persistentId: string): Promise<void>;
  createRootTokenWithIdentity(params: CreateRootTokenParams, persistentId: string): Promise<AgentToken>;
  verifyTokenIdentity(token: AgentToken): Promise<VerificationResult & { persistentId?: string }>;

  // Serialization
  serializeToken(token: AgentToken): string;
  deserializeToken(serialized: string): AgentToken;

  // Credentials
  getCredential(token: AgentToken, scope: string, resource: string): Promise<CredentialResult>;

  // Configuration
  initProvider(provider: string, config: Record<string, string>): void;
  addAPIKey(params): void;
  removeAPIKey(name: string): boolean;
  getStatus(): BrokerStatus;
  showConfig(): Record<string, unknown>;
}
```

### Standalone Verifier

```typescript
// Verify agent identity without broker access (works anywhere)
function verifyIdentityProof(
  token: AgentToken,
  options?: {
    trustedAuthorities?: Record<string, string>;  // authorityId → public key PEM
    requireFingerprintMatch?: boolean;             // default: true
  }
): StandaloneVerificationResult;

// Create an authority endorsement for an agent
function createEndorsement(
  authorityId: string,
  authorityPrivateKey: string,
  authorityPublicKey: string,
  agentPersistentId: string,
  agentPublicKey: string,
  claim: string,
  expiresAt?: string
): AuthorityEndorsement;
```

### AgentRuntime

```typescript
class AgentRuntime {
  constructor(token: AgentToken, config?: RuntimeConfig);
  static fromSerialized(serialized: string, config?: RuntimeConfig): AgentRuntime;
  static fromEnvironment(config?: RuntimeConfig): AgentRuntime;

  start(): void;
  stop(): void;

  checkPermission(scope: string, resource: string): boolean;
  delegate(request: DelegationRequest): AgentToken;
  createSubprocessEnv(request: DelegationRequest): Record<string, string>;

  getToken(): AgentToken;
  getSerializedToken(): string;
  getStatus(): RuntimeStatus;
  refresh(): Promise<void>;
}
```

### Types

```typescript
interface AgentToken {
  agentId: string;
  parentId?: string;
  scopes: string[];
  constraints: Record<string, ScopeConstraint>;
  delegatable: boolean;
  maxDelegationDepth: number;
  currentDepth: number;
  expiresAt?: string;
  maxExpiresAt?: string;
  signature?: string;
  // Persistent identity (optional)
  persistentIdentity?: {
    persistentId: string;          // "key:abc..." or "platform:uuid"
    identityType: string;          // "keypair" or "platform"
    proof?: string;                // Ed25519 signature or HMAC
    challenge?: string;            // What was signed
    publicKey?: string;            // PEM public key for standalone verification
    endorsements?: AuthorityEndorsement[];
  };
}

interface PersistentIdentity {
  persistentId: string;
  identityType: "keypair" | "platform" | "attested" | "decentralized";
  createdAt: string;
  label?: string;
  metadata: Record<string, unknown>;
}

interface AuthorityEndorsement {
  authorityId: string;
  authorityPublicKey: string;
  claim: string;
  signature: string;
  issuedAt: string;
  expiresAt?: string;
}

interface StandaloneVerificationResult {
  valid: boolean;
  error?: string;
  persistentId?: string;
  publicKey?: string;
  verifiedEndorsements?: VerifiedEndorsement[];
}

interface DelegationRequest {
  agentId?: string;
  requestedScopes: string[];
  requestedConstraints?: Record<string, ScopeConstraint>;
  delegatable?: boolean;
  ttlMinutes?: number;
  inheritPersistentIdentity?: boolean;  // default: true
  persistentIdentity?: { ... };         // override child identity
}
```

## MAP Protocol Integration

Agent-IAM is designed to work standalone or as an IAM provider for the [Multi-Agent Protocol (MAP)](https://github.com/multi-agent-protocol/multi-agent-protocol). The token format includes optional fields for identity binding, federation, and agent-level capabilities that integrate seamlessly with MAP.

### Identity Binding

Link tokens to external identity contexts for audit trails and cross-system traceability:

```typescript
const token = broker.createRootToken({
  agentId: "coordinator",
  scopes: ["github:repo:*"],
  identity: {
    systemId: "map-system-alpha",          // MAP system identifier
    principalId: "user@example.com",       // Human/service responsible
    principalType: "human",                // "human" | "service" | "agent"
    tenantId: "acme-corp",                 // Multi-tenant isolation
    externalAuth: {                        // External IdP proof (optional)
      issuer: "https://auth.example.com",
      subject: "oauth-user-123",
      authenticatedAt: new Date().toISOString(),
    },
  },
  ttlDays: 7,
});

// Identity is inherited through delegation chain
const childToken = broker.delegate(token, {
  agentId: "worker",
  requestedScopes: ["github:repo:read"],
});
// childToken.identity.principalId === "user@example.com"

// Or opt out of inheritance for anonymized delegation
const anonToken = broker.delegate(token, {
  agentId: "anonymous-worker",
  requestedScopes: ["github:repo:read"],
  inheritIdentity: false,
});
```

### Federation Metadata

Control cross-system token usage for MAP federation:

```typescript
const token = broker.createRootToken({
  agentId: "coordinator",
  scopes: ["github:repo:*"],
  federation: {
    crossSystemAllowed: true,              // Can be used across MAP systems
    allowedSystems: ["system-beta"],       // Specific systems allowed
    originSystem: "map-system-alpha",      // Original issuing system
    maxHops: 3,                            // Prevent routing loops
    allowFurtherFederation: true,          // Can delegate federated tokens
  },
  ttlDays: 7,
});

// Delegation attenuates federation (can only restrict, never widen)
const childToken = broker.delegate(token, {
  agentId: "worker",
  requestedScopes: ["github:repo:read"],
  federation: {
    crossSystemAllowed: false,  // Disable cross-system for this child
    maxHops: 1,                 // More restrictive than parent
  },
});
```

### Agent Capabilities

Define what agents can do within the MAP system (separate from resource access scopes):

```typescript
const token = broker.createRootToken({
  agentId: "coordinator",
  scopes: ["github:repo:*"],
  agentCapabilities: {
    canSpawn: true,                        // Can create child agents
    canFederate: true,                     // Can participate in federation
    canCreateScopes: true,                 // Can create MAP scopes
    canMessage: true,                      // Can send messages
    canReceive: true,                      // Can receive messages
    canObserve: true,                      // Can observe system events
    visibility: "public",                  // "public" | "scope" | "parent-only" | "system"
    custom: {                              // Extensible capabilities
      canAccessInternalAPIs: true,
    },
  },
  ttlDays: 7,
});

// Capabilities attenuate through delegation (can only disable, never enable)
const childToken = broker.delegate(token, {
  agentId: "worker",
  requestedScopes: ["github:repo:read"],
  agentCapabilities: {
    canSpawn: false,            // Disable spawning for worker
    visibility: "parent-only",  // More restrictive visibility
  },
});
// childToken.agentCapabilities.canSpawn === false
// childToken.agentCapabilities.canMessage === true (inherited)
```

### MAP Integration Types

```typescript
interface IdentityBinding {
  systemId: string;
  principalId?: string;
  principalType?: "human" | "service" | "agent";
  tenantId?: string;
  organizationId?: string;
  externalAuth?: ExternalAuthInfo;
  federatedFrom?: FederatedIdentity;
}

interface FederationMetadata {
  crossSystemAllowed: boolean;
  allowedSystems?: string[];
  originSystem?: string;
  hopCount?: number;
  maxHops?: number;
  allowFurtherFederation?: boolean;
}

interface AgentCapabilities {
  canSpawn?: boolean;
  canFederate?: boolean;
  canCreateScopes?: boolean;
  visibility?: "public" | "parent-only" | "scope" | "system";
  canMessage?: boolean;
  canReceive?: boolean;
  canObserve?: boolean;
  custom?: Record<string, boolean>;
}
```

### Standalone vs MAP Mode

All MAP integration fields are **optional**. When not provided, agent-iam works as a standalone capability broker:

```typescript
// Standalone mode (no MAP fields)
const standaloneToken = broker.createRootToken({
  agentId: "standalone-agent",
  scopes: ["github:repo:read"],
  ttlDays: 1,
});
// token.identity === undefined
// token.federation === undefined
// token.agentCapabilities === undefined

// MAP mode (with integration fields)
const mapToken = broker.createRootToken({
  agentId: "map-agent",
  scopes: ["github:repo:read"],
  identity: { systemId: "alpha", principalId: "user@corp.com" },
  federation: { crossSystemAllowed: true, maxHops: 3 },
  agentCapabilities: { canSpawn: true, visibility: "public" },
  ttlDays: 1,
});
```

All fields are cryptographically protected by the HMAC signature - any tampering invalidates the token.

## Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Run tests (318 tests)
npm test

# Run CLI
npm run cli -- status
```

## License

MIT

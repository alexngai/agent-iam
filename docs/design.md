# Agent Credential Broker: Design Specification

**Version:** 1.1  
**Status:** Draft  
**Last Updated:** February 2025

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Background & Motivation](#2-background--motivation)
3. [Requirements](#3-requirements)
4. [Design Decisions](#4-design-decisions)
5. [Architecture](#5-architecture)
6. [Security Model](#6-security-model)
7. [Component Specifications](#7-component-specifications)
8. [Distributed Extension](#8-distributed-extension)
9. [API Reference](#9-api-reference)
10. [Implementation Roadmap](#10-implementation-roadmap)
11. [Appendices](#11-appendices)

---

## 1. Executive Summary

### 1.1 Problem Statement

Autonomous AI agents need to access external services (GitHub, Google, AWS, etc.) on behalf of users. This requires:

- **Credential acquisition**: Agents need actual tokens/keys to call APIs
- **Scope control**: Agents should only access what they need
- **Delegation**: Parent agents spawning sub-agents must limit their capabilities
- **Least privilege**: Sub-agents must not exceed their parent's permissions

### 1.2 Proposed Solution

A lightweight, local-first credential broker that:

- Issues short-lived provider credentials (GitHub tokens, Google OAuth, AWS STS)
- Uses capability tokens to control what agents can request
- Supports hierarchical delegation with automatic scope attenuation
- Runs entirely locally with minimal resource requirements (~150MB RAM)
- **Optionally scales to distributed deployments** with leader/follower synchronization

### 1.3 Key Design Principles

| Principle | Description |
|-----------|-------------|
| **Local-first** | Runs on developer machine, no server infrastructure required |
| **Minimal dependencies** | JSON file storage, single Python process |
| **Capability-based security** | Tokens represent capabilities, not identities |
| **Attenuation only** | Delegated tokens can narrow but never widen permissions |
| **Short-lived credentials** | Provider tokens fetched on-demand, cached briefly |
| **Graceful degradation** | Distributed mode degrades to standalone when disconnected |

### 1.4 Deployment Modes

The system supports three deployment modes that share the same core components:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DEPLOYMENT MODE SPECTRUM                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   STANDALONE              DISTRIBUTED                 FEDERATED              │
│   (Single Machine)        (Leader/Follower)           (Central Authority)    │
│                                                                              │
│   ┌─────────────┐        ┌─────────────┐             ┌─────────────┐        │
│   │   Broker    │        │   Leader    │             │  Authority  │        │
│   │             │        │   Broker    │             │  (Vault/etc)│        │
│   │ • All local │        └──────┬──────┘             └──────┬──────┘        │
│   │ • No sync   │               │                          │               │
│   │ • Simplest  │        ┌──────┴──────┐             ┌──────┴──────┐        │
│   └─────────────┘        │             │             │   Leader    │        │
│                          ▼             ▼             │   Broker    │        │
│                    ┌──────────┐ ┌──────────┐        └──────┬──────┘        │
│                    │ Follower │ │ Follower │               │               │
│                    │    A     │ │    B     │        ┌──────┴──────┐        │
│                    └──────────┘ └──────────┘        │             │        │
│                                                      ▼             ▼        │
│                                                ┌──────────┐ ┌──────────┐   │
│                                                │ Follower │ │ Follower │   │
│                                                └──────────┘ └──────────┘   │
│                                                                              │
│   Use case:              Use case:                   Use case:              │
│   • Local dev            • Multi-region agents       • Enterprise           │
│   • Single user          • Edge deployments          • Compliance needs     │
│   • Quick start          • Team sharing              • Audit requirements   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key insight**: A follower with no leader configured **is** a standalone broker. The same code handles both cases.

---

## 2. Background & Motivation

### 2.1 The Agent Authorization Problem

Traditional authorization systems assume:

```
User → clicks button → System checks permission → Action executes
```

Agent-based systems operate differently:

```
User → sets goal → Agent decides actions → Agent decides sequence → Agent accesses resources
```

This creates new challenges:

1. **Indirection**: The user isn't directly triggering each action
2. **Autonomy**: Agents make independent decisions about what to access
3. **Composition**: Agents may spawn sub-agents with their own needs
4. **Scope creep**: Without controls, agents may access more than necessary

### 2.2 Existing Solutions and Their Limitations

| Solution | Limitation for Local Agent Use |
|----------|--------------------------------|
| **HashiCorp Vault** | Heavy (8GB+ RAM), complex HA setup, unsealing ceremony |
| **Infisical** | Lighter but still 512MB+, requires Postgres, server-oriented |
| **Akeyless** | SaaS-only, no self-hosted option |
| **Cloud KMS** (AWS/GCP/Azure) | Vendor lock-in, no cross-provider support |
| **MCP OAuth** | Per-server, doesn't handle multi-agent delegation |

### 2.3 Why Build a Custom Solution?

For local single-user multi-agent systems:

- **Grants layer is implicit**: You are the user; if you configured it, you granted it
- **No network security needed**: Everything runs locally
- **No HA required**: Single process is fine
- **Minimal storage**: JSON files sufficient

A purpose-built solution can be ~500 lines (standalone) or ~1200 lines (with distributed support) vs. deploying enterprise infrastructure.

### 2.4 Scope

**In Scope:**
- Local multi-agent credential management
- Hierarchical capability delegation
- Provider credential issuance (GitHub, Google, AWS, generic)
- Token refresh mechanisms
- Credential caching
- **Distributed deployment with leader/follower sync** (optional extension)
- **Central authority integration** (optional extension)

**Out of Scope:**
- Web UI
- Multi-user access control within a single broker
- Compliance certifications (SOC2, HIPAA)
- Hardware security module (HSM) integration

---

## 3. Requirements

### 3.1 Functional Requirements

#### FR-1: Provider Credential Issuance

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-1.1 | System SHALL issue GitHub installation tokens scoped to specific repos/permissions | Must |
| FR-1.2 | System SHALL issue Google OAuth access tokens from refresh tokens | Must |
| FR-1.3 | System SHALL issue AWS STS temporary credentials via AssumeRole | Must |
| FR-1.4 | System SHALL support generic API key retrieval | Must |
| FR-1.5 | System SHOULD support additional providers via adapter pattern | Should |

#### FR-2: Capability Tokens

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-2.1 | System SHALL issue signed capability tokens defining agent permissions | Must |
| FR-2.2 | Tokens SHALL specify allowed scopes (e.g., `github:repo:read`) | Must |
| FR-2.3 | Tokens SHALL support resource constraints (e.g., specific repos) | Must |
| FR-2.4 | Tokens SHALL have configurable expiration | Must |
| FR-2.5 | Tokens SHALL be cryptographically signed to prevent tampering | Must |

#### FR-3: Delegation

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-3.1 | Agents SHALL be able to delegate subsets of their capabilities to sub-agents | Must |
| FR-3.2 | Delegated tokens SHALL NOT exceed parent token scopes | Must |
| FR-3.3 | Delegated token constraints SHALL be equal or narrower than parent | Must |
| FR-3.4 | Delegation depth SHALL be configurable and enforced | Must |
| FR-3.5 | Parent SHALL be able to disable further delegation by children | Should |

#### FR-4: Token Lifecycle

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-4.1 | Tokens SHALL support self-refresh when granted `system:token:refresh` scope | Must |
| FR-4.2 | System SHALL support background automatic token refresh | Should |
| FR-4.3 | Provider credentials SHALL be cached with TTL-aware expiration | Should |
| FR-4.4 | Refresh SHALL NOT extend token beyond original maximum lifetime (if set) | Must |

#### FR-5: Distributed Operation (Extension)

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-5.1 | System SHOULD support leader/follower topology | Should |
| FR-5.2 | Followers SHALL sync signing keys from leader | Should |
| FR-5.3 | Followers SHALL sync provider configurations from leader | Should |
| FR-5.4 | Followers SHALL sync revocation lists from leader | Should |
| FR-5.5 | System SHALL operate in degraded mode when leader is unreachable | Should |
| FR-5.6 | Leader SHOULD support push notifications for urgent updates (revocations) | Could |
| FR-5.7 | Leader SHOULD support syncing from a central authority (Vault, etc.) | Could |

### 3.2 Non-Functional Requirements

#### NFR-1: Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1.1 | Credential issuance latency | < 500ms (cached), < 2s (fresh) |
| NFR-1.2 | Token validation latency | < 1ms |
| NFR-1.3 | Memory footprint (standalone) | < 150MB |
| NFR-1.4 | Memory footprint (distributed) | < 200MB |
| NFR-1.5 | Startup time | < 1s (standalone), < 5s (distributed initial sync) |

#### NFR-2: Security

| ID | Requirement |
|----|-------------|
| NFR-2.1 | Provider secrets SHALL be stored with filesystem permissions (600) |
| NFR-2.2 | Token signing key SHALL be auto-generated and protected |
| NFR-2.3 | Provider credentials SHALL be short-lived (≤ 1 hour typical) |
| NFR-2.4 | System SHALL NOT log sensitive credential values |
| NFR-2.5 | Distributed sync SHALL use authenticated channels (mTLS or bearer tokens) |

#### NFR-3: Usability

| ID | Requirement |
|----|-------------|
| NFR-3.1 | System SHALL be usable as CLI tool |
| NFR-3.2 | System SHALL be usable as Python library |
| NFR-3.3 | Initial setup SHALL require < 5 minutes per provider |
| NFR-3.4 | System SHALL provide clear error messages for authorization failures |
| NFR-3.5 | Standalone mode SHALL require zero configuration beyond providers |

#### NFR-4: Availability (Distributed)

| ID | Requirement |
|----|-------------|
| NFR-4.1 | Followers SHALL continue operating when leader is temporarily unavailable |
| NFR-4.2 | System SHALL cache sufficient state for offline operation |
| NFR-4.3 | System SHALL clearly indicate degraded operation state |

---

## 4. Design Decisions

### 4.1 Capability Tokens vs. Identity-Based Access

**Decision:** Use capability-based tokens rather than identity-based access control.

**Rationale:**

| Approach | Description | Fit for Local Agents |
|----------|-------------|----------------------|
| **Identity-based** (RBAC) | "Agent X has role Y which grants permissions Z" | Poor - requires identity registry, role management |
| **Capability-based** | "This token grants permissions Z" | Good - self-contained, delegatable |

Capability tokens are:
- Self-describing (token contains its own permissions)
- Delegatable (can be passed to sub-agents)
- Attenuatable (can be narrowed but not widened)
- Stateless (no central registry needed)

**Trade-off:** No centralized revocation in standalone mode. Mitigated by short token lifetimes and optional revocation list in distributed mode.

### 4.2 Scope Format

**Decision:** Use hierarchical colon-separated scopes: `provider:resource_type:action`

**Examples:**
```
github:repo:read        # Read any GitHub repo
github:repo:write       # Write to any GitHub repo
github:repo:*           # All repo operations
google:gmail:send       # Send Gmail
google:drive:read       # Read Google Drive
aws:s3:read             # Read S3
system:token:refresh    # Self-refresh capability
```

**Rationale:**
- Familiar pattern (OAuth scopes, AWS IAM)
- Supports wildcards for broad grants
- Hierarchical structure enables prefix matching
- Human-readable

### 4.3 Constraint Model

**Decision:** Constraints are key-value maps attached to scopes, specifying allowed resources.

**Example:**
```json
{
  "scopes": ["github:repo:read", "github:repo:write"],
  "constraints": {
    "github:repo:read": {"resources": ["myorg/*"]},
    "github:repo:write": {"resources": ["myorg/repo-a", "myorg/repo-b"]}
  }
}
```

**Rationale:**
- Scopes define *what operations* are allowed
- Constraints define *which resources* those operations apply to
- Separation allows flexible combinations
- Constraints use glob patterns for ergonomic resource matching

### 4.4 Token Signing

**Decision:** Use HMAC-SHA256 with a local secret key.

**Rationale:**

| Approach | Pros | Cons |
|----------|------|------|
| **HMAC (symmetric)** | Simple, fast, single key | Can't verify without secret |
| **RSA/EC (asymmetric)** | Public verification | More complex, larger tokens |
| **No signing** | Simplest | Tokens can be forged |

For local use:
- All verification happens on same machine (has access to secret)
- HMAC is faster and simpler
- Tokens don't need to be verified by external parties

For distributed use:
- Same HMAC key is synced to all followers
- All brokers can sign and verify tokens
- Key rotation handled by leader

### 4.5 Storage

**Decision:** Use filesystem with JSON files for configuration, auto-generated files for secrets.

**Structure (Standalone):**
```
~/.agent-credentials/
├── config.json           # Provider configurations
├── token_secret          # HMAC signing key (auto-generated, chmod 600)
├── github-app.pem        # GitHub App private key
└── cache/                # Optional credential cache
    └── credentials.json
```

**Structure (Distributed Follower):**
```
~/.agent-credentials/
├── config.json           # Local overrides (optional)
├── follower_config.json  # Leader URL, auth token
├── sync_cache/           # Synced state from leader
│   ├── signing_keys.json
│   ├── provider_configs.json
│   └── revocations.json
└── cache/
    └── credentials.json
```

**Rationale:**
- No database dependency
- Easy to inspect and debug
- Portable (copy directory to another machine)
- Clear separation of local vs. synced state

### 4.6 Token Refresh Strategy

**Decision:** Support multiple refresh strategies with "self-refresh" as default.

| Strategy | How It Works | Use Case |
|----------|--------------|----------|
| **Long-lived** | Tokens valid for days | Simple scripts |
| **Self-refresh** | Token includes `system:token:refresh` scope | Long-running agents |
| **Parent-refresh** | Child requests new token from parent | Untrusted sub-agents |
| **No refresh** | Token expires, agent terminates | Short tasks |

**Default:** Self-refresh with background thread, 5-minute refresh buffer before expiry.

### 4.7 Provider Credential Caching

**Decision:** Cache provider credentials in memory with TTL-aware expiration.

**Rationale:**
- Avoid redundant API calls (GitHub rate limits, latency)
- Cache invalidation based on token expiry minus buffer
- Memory-only (no persistence) for security
- Per-scope-and-resource cache keys

**Cache eviction:** Credential evicted `buffer` seconds before expiry (default 300s).

### 4.8 Distributed Topology

**Decision:** Use leader/follower topology with optional central authority.

**Rationale:**

| Topology | Pros | Cons |
|----------|------|------|
| **Peer-to-peer** | No single point of failure | Complex consensus, conflict resolution |
| **Leader/follower** | Simple, clear authority | Leader is SPOF (mitigated by caching) |
| **Central authority** | Enterprise integration | Adds external dependency |

Leader/follower provides:
- Clear source of truth
- Simple sync protocol
- Graceful offline operation for followers
- Optional integration with enterprise systems at leader level

### 4.9 Sync Strategy

**Decision:** Pull-based sync with optional push for critical updates.

| Data Type | Sync Method | Interval | Rationale |
|-----------|-------------|----------|-----------|
| Signing key | Pull | Startup + daily | Rarely changes |
| Provider configs | Pull | 5 minutes | Moderate change frequency |
| Revocation list | Pull + Push | 30s pull, immediate push | Security critical |
| Root tokens | Pull on demand | As needed | Large, infrequently accessed |

**Rationale:**
- Pull is simpler and more reliable
- Push only for time-critical security updates
- Followers can operate on stale data (with warnings)

### 4.10 Graceful Degradation

**Decision:** Distributed mode degrades to standalone operation when disconnected.

**Degradation levels:**

| Level | Condition | Capabilities |
|-------|-----------|--------------|
| **Full** | Connected, synced | All operations, real-time revocation |
| **Degraded** | Disconnected < 5 min | All operations, stale revocation list |
| **Limited** | Disconnected > 5 min | Existing tokens work, no new root tokens |
| **Offline** | Disconnected > 1 hr | Warn on security-sensitive operations |
| **Standalone** | No leader configured | Full local operation, no sync |

**Key principle:** A broker without leader configuration is indistinguishable from a standalone broker. The distributed extension is purely additive.

---

## 5. Architecture

### 5.1 System Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AGENT CREDENTIAL BROKER                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                              USER LAYER                                 │ │
│  │                                                                         │ │
│  │   CLI Interface              Python Library           Config Files      │ │
│  │   $ broker github ...        from broker import ...   ~/.agent-creds/   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                           AGENT RUNTIME                                 │ │
│  │                                                                         │ │
│  │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   │ │
│  │   │  Token Manager  │    │ Credential Cache│    │ Background      │   │ │
│  │   │                 │    │                 │    │ Tasks           │   │ │
│  │   │ • Current token │    │ • In-memory LRU │    │                 │   │ │
│  │   │ • Refresh logic │    │ • TTL tracking  │    │ • Token refresh │   │ │
│  │   │ • Thread-safe   │    │ • Scope+resource│    │ • Sync (if dist)│   │ │
│  │   └─────────────────┘    └─────────────────┘    └─────────────────┘   │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                            CORE SERVICES                                │ │
│  │                                                                         │ │
│  │   ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐   │ │
│  │   │ Token Service   │    │ Delegation      │    │ Credential      │   │ │
│  │   │                 │    │ Service         │    │ Service         │   │ │
│  │   │ • Create tokens │    │                 │    │                 │   │ │
│  │   │ • Sign/verify   │    │ • Validate req  │    │ • Check scope   │   │ │
│  │   │ • Refresh       │    │ • Attenuate     │    │ • Check constr  │   │ │
│  │   │                 │    │ • Issue child   │    │ • Issue cred    │   │ │
│  │   └─────────────────┘    └─────────────────┘    └─────────────────┘   │ │
│  │                                                                         │ │
│  │   ┌─────────────────┐    ┌─────────────────┐                           │ │
│  │   │ Config Service  │    │ Revocation      │  ◄── These support both  │ │
│  │   │                 │    │ Service         │      local and synced    │ │
│  │   │ • Local configs │    │                 │      data sources        │ │
│  │   │ • Synced configs│    │ • Local list    │                           │ │
│  │   │ • Merge logic   │    │ • Synced list   │                           │ │
│  │   └─────────────────┘    └─────────────────┘                           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│                                      ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          PROVIDER ADAPTERS                              │ │
│  │                                                                         │ │
│  │   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐          │ │
│  │   │  GitHub  │   │  Google  │   │   AWS    │   │ Generic  │   ...    │ │
│  │   │          │   │          │   │          │   │          │          │ │
│  │   │ App JWT  │   │ OAuth    │   │ STS      │   │ API Key  │          │ │
│  │   │ Install  │   │ Refresh  │   │ Assume   │   │ Passthru │          │ │
│  │   │ Token    │   │ Token    │   │ Role     │   │          │          │ │
│  │   └──────────┘   └──────────┘   └──────────┘   └──────────┘          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                      │                                       │
│  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐ │
│    DISTRIBUTED EXTENSION (Optional)  │                                     │ │
│  │                                   ▼                                   │ │
│     ┌─────────────────────────────────────────────────────────────────┐   │ │
│  │  │                         SYNC SERVICE                            │  │ │
│     │                                                                 │   │ │
│  │  │  ┌─────────────────┐    ┌─────────────────┐                    │  │ │
│     │  │ Sync Client     │    │ Sync Server     │                    │   │ │
│  │  │  │ (Follower)      │    │ (Leader)        │                    │  │ │
│     │  │                 │    │                 │                    │   │ │
│  │  │  │ • Pull configs  │    │ • Serve configs │                    │  │ │
│     │  │ • Pull keys     │    │ • Track followers                    │   │ │
│  │  │  │ • Pull revokes  │    │ • Push revokes  │                    │  │ │
│     │  │ • Cache locally │    │ • Rotate keys   │                    │   │ │
│  │  │  └─────────────────┘    └─────────────────┘                    │  │ │
│     └─────────────────────────────────────────────────────────────────┘   │ │
│  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘ │
│                                      │                                       │
│                                      ▼                                       │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          EXTERNAL SERVICES                              │ │
│  │                                                                         │ │
│  │        GitHub API         Google OAuth         AWS STS        etc.      │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Token Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TOKEN LIFECYCLE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. ROOT TOKEN CREATION                                                      │
│  ────────────────────────                                                    │
│                                                                              │
│     STANDALONE: User runs `$ broker create-root`                             │
│     DISTRIBUTED: Only leader can create, synced to followers                 │
│                                                                              │
│     ┌─────────────────────────────────────────────────┐                     │
│     │ ROOT TOKEN                                      │                     │
│     │ agent_id: "root"                                │                     │
│     │ scopes: ["github:repo:*", "google:gmail:send"]  │                     │
│     │ constraints: {github:repo:*: {resources: [...]}}│                     │
│     │ delegatable: true                               │                     │
│     │ max_depth: 3                                    │                     │
│     │ expires_at: +7 days                             │                     │
│     │ issuer_id: "leader" (distributed only)          │                     │
│     │ signing_key_version: 1 (distributed only)       │                     │
│     │ signature: "abc123..."                          │                     │
│     └─────────────────────────────────────────────────┘                     │
│                                      │                                       │
│                                      ▼                                       │
│  2. DELEGATION (Same in standalone and distributed)                          │
│  ──────────────────────────────────────────────────                          │
│                                                                              │
│     Parent calls: delegate(parent_token, request)                            │
│     Any broker with signing key can sign delegations                         │
│                                                                              │
│     ┌─────────────────────────────────────────────────┐                     │
│     │ CHILD TOKEN                                     │                     │
│     │ agent_id: "research-agent"                      │                     │
│     │ parent_id: "root"                               │                     │
│     │ scopes: ["github:repo:read"]        ← Narrower  │                     │
│     │ constraints: {...specific-repo...}  ← Narrower  │                     │
│     │ issuer_id: "follower-a" (distributed only)      │                     │
│     │ signature: "def456..."                          │                     │
│     └─────────────────────────────────────────────────┘                     │
│                                      │                                       │
│                                      ▼                                       │
│  3. CREDENTIAL REQUEST (Same in standalone and distributed)                  │
│  ──────────────────────────────────────────────────────────                  │
│                                                                              │
│     Agent calls: get_credential(token, "github:repo:read", "org/repo")       │
│                                                                              │
│     Broker validates:                                                        │
│       ✓ Token signature valid                                                │
│       ✓ Token not expired                                                    │
│       ✓ Token not revoked (checks local + synced revocation list)           │
│       ✓ Scope in token.scopes                                               │
│       ✓ Resource matches constraint pattern                                  │
│                                                                              │
│     Broker issues:                                                           │
│       → Provider credential (using local or synced config)                   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Multi-Agent Delegation Hierarchy

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DELEGATION HIERARCHY                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ROOT (depth=0)                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │ scopes: [github:repo:*, google:gmail:*, aws:s3:*, system:token:refresh]│ │
│  │ constraints: {github:repo:*: {resources: ["myorg/*"]}}                 │ │
│  │ delegatable: true, max_depth: 3                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│              │                                    │                          │
│              ▼                                    ▼                          │
│  ORCHESTRATOR (depth=1)                 EMAIL AGENT (depth=1)                │
│  ┌─────────────────────────────┐       ┌─────────────────────────────┐      │
│  │ scopes: [github:repo:read,  │       │ scopes: [google:gmail:send] │      │
│  │         github:repo:write,  │       │ constraints: {}             │      │
│  │         system:token:refresh│       │ delegatable: false          │      │
│  │ constraints: {              │       └─────────────────────────────┘      │
│  │   github:repo:read:         │                                            │
│  │     {resources: [myorg/*]}, │                                            │
│  │   github:repo:write:        │                                            │
│  │     {resources: [myorg/app]}│                                            │
│  │ }                           │                                            │
│  │ delegatable: true           │                                            │
│  └─────────────────────────────┘                                            │
│              │                                                               │
│              ├──────────────────────────────┐                                │
│              ▼                              ▼                                │
│  RESEARCH AGENT (depth=2)       CODE AGENT (depth=2)                         │
│  ┌──────────────────────────┐  ┌──────────────────────────┐                 │
│  │ scopes: [github:repo:read│  │ scopes: [github:repo:read│                 │
│  │ constraints: {           │  │          github:repo:write                 │
│  │   github:repo:read:      │  │ constraints: {           │                 │
│  │     {resources:          │  │   github:repo:*:         │                 │
│  │       [myorg/docs,       │  │     {resources:          │                 │
│  │        myorg/research]}  │  │       [myorg/app]}       │                 │
│  │ }                        │  │ }                        │                 │
│  │ delegatable: false       │  │ delegatable: false       │                 │
│  └──────────────────────────┘  └──────────────────────────┘                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Security Model

### 6.1 Threat Model

| Threat | Mitigation (Standalone) | Mitigation (Distributed) |
|--------|-------------------------|--------------------------|
| **Stolen agent token** | Short expiration | + Revocation list sync |
| **Token tampering** | HMAC signature | Same (shared key) |
| **Privilege escalation** | Attenuation-only delegation | Same |
| **Provider credential theft** | Short-lived, memory-only cache | Same |
| **Config file theft** | File permissions (600) | + Encrypted sync channel |
| **Signing key compromise** | Regenerate key | + Key rotation with versioning |
| **Rogue follower** | N/A | mTLS or bearer token auth |
| **Leader compromise** | N/A | Followers detect via cert/signature |

### 6.2 Security Properties

#### 6.2.1 Capability Attenuation

**Invariant:** For any child token `C` created from parent token `P`:

```
∀ scope ∈ C.scopes: scope ∈ P.scopes OR scope matches P.scopes (wildcard)
∀ (scope, constraint) ∈ C.constraints: C.constraint ⊆ P.constraint
C.expires_at ≤ P.expires_at
C.current_depth = P.current_depth + 1
```

This invariant holds regardless of which broker (leader or follower) performs the delegation.

#### 6.2.2 Token Integrity

**Invariant:** A token is valid if and only if:

```
HMAC-SHA256(token_without_signature, signing_key[token.signing_key_version]) == token.signature
```

In distributed mode, followers receive the signing key from the leader, so all brokers can verify all tokens.

#### 6.2.3 Revocation (Distributed Only)

**Invariant:** A token is considered revoked if:

```
token.signature[:16] ∈ revocation_set
```

The revocation set is synced from leader to followers. During network partition, followers use their cached revocation set (may be stale).

### 6.3 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TRUST HIERARCHY                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   STANDALONE MODE                      DISTRIBUTED MODE                      │
│   ───────────────                      ────────────────                      │
│                                                                              │
│   ┌─────────────────┐                  ┌─────────────────┐                  │
│   │  Your Machine   │                  │ Central Auth    │ (Optional)       │
│   │  (Full Trust)   │                  │ (Highest Trust) │                  │
│   │                 │                  └────────┬────────┘                  │
│   │ • Config files  │                           │                           │
│   │ • Signing key   │                           ▼                           │
│   │ • Broker process│                  ┌─────────────────┐                  │
│   └────────┬────────┘                  │     Leader      │                  │
│            │                           │   (High Trust)  │                  │
│            │                           │                 │                  │
│            │                           │ • Creates roots │                  │
│            │                           │ • Manages keys  │                  │
│            │                           │ • Syncs configs │                  │
│            │                           └────────┬────────┘                  │
│            │                                    │                           │
│            │                        ┌───────────┼───────────┐               │
│            │                        │           │           │               │
│            │                        ▼           ▼           ▼               │
│            │               ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│            │               │ Follower │ │ Follower │ │ Follower │          │
│            │               │ (Medium) │ │ (Medium) │ │ (Medium) │          │
│            │               │          │ │          │ │          │          │
│            │               │• Sign del│ │• Sign del│ │• Sign del│          │
│            │               │• Issue cr│ │• Issue cr│ │• Issue cr│          │
│            │               └────┬─────┘ └────┬─────┘ └────┬─────┘          │
│            │                    │            │            │                 │
│            ▼                    ▼            ▼            ▼                 │
│   ┌─────────────────────────────────────────────────────────────────────┐  │
│   │                         AGENT PROCESSES                              │  │
│   │                         (Limited Trust)                              │  │
│   │                                                                      │  │
│   │  • Receive capability tokens (cannot forge)                         │  │
│   │  • Request credentials (broker validates)                           │  │
│   │  • Delegate further (broker enforces attenuation)                   │  │
│   └─────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.4 Revocation

| Mode | Mechanism | Latency | Completeness |
|------|-----------|---------|--------------|
| **Standalone** | Short token TTL | Automatic at expiry | N/A |
| **Standalone + revocation list** | Manual local list | Immediate (local) | Manual |
| **Distributed** | Leader syncs revocation list | 30s poll, immediate push | High |
| **Distributed (partitioned)** | Cached revocation list | Stale (minutes-hours) | Degraded |

---

## 7. Component Specifications

### 7.1 AgentToken

The core data structure representing an agent's capabilities.

```python
@dataclass
class AgentToken:
    # Identity
    agent_id: str                          # Unique identifier for this agent
    parent_id: Optional[str] = None        # ID of parent (None for root)
    
    # Capabilities
    scopes: list[str]                      # Allowed scopes
    constraints: dict[str, dict] = field(default_factory=dict)
    
    # Delegation control
    delegatable: bool = True
    max_delegation_depth: int = 3
    current_depth: int = 0
    
    # Lifecycle
    expires_at: Optional[datetime] = None
    max_expires_at: Optional[datetime] = None  # For refresh limiting
    
    # Distributed metadata (optional, present when distributed extension enabled)
    issuer_id: Optional[str] = None            # Which broker issued this
    signing_key_version: Optional[int] = None  # Which key version signed this
    offline_grace_period: Optional[int] = None # Seconds valid offline
    requires_online_validation: bool = False   # Must check revocation online?
    
    # Integrity
    signature: Optional[str] = None
```

**Scope format:** `provider:resource_type:action`

| Pattern | Matches |
|---------|---------|
| `github:repo:read` | Exactly `github:repo:read` |
| `github:repo:*` | Any `github:repo:X` |
| `github:*` | Any `github:X:Y` |
| `*` | Everything (dangerous) |

**Constraint format:**

```json
{
  "scope": {
    "resources": ["pattern1", "pattern2"],
    "not_before": "2024-01-01T00:00:00Z",
    "not_after": "2024-12-31T23:59:59Z",
    "max_uses": 100
  }
}
```

### 7.2 Broker (Unified Interface)

The broker provides a unified interface regardless of deployment mode:

```python
class Broker:
    """
    Credential broker with optional distributed sync.
    
    When leader_url is None, operates in standalone mode.
    When leader_url is set, operates as a follower.
    When is_leader is True, operates as a leader.
    """
    
    def __init__(
        self,
        config_dir: Path = Path.home() / ".agent-credentials",
        leader_url: Optional[str] = None,      # If set, sync from leader
        leader_auth_token: Optional[str] = None,
        is_leader: bool = False,               # If True, accept follower syncs
        sync_interval: int = 60,
    ):
        self.config_dir = config_dir
        self.leader_url = leader_url
        self.is_leader = is_leader
        
        # Determine mode
        if leader_url:
            self.mode = BrokerMode.FOLLOWER
        elif is_leader:
            self.mode = BrokerMode.LEADER
        else:
            self.mode = BrokerMode.STANDALONE
        
        # Core services (always present)
        self._token_service = TokenService()
        self._delegation_service = DelegationService()
        self._credential_service = CredentialService()
        
        # Config source (local or synced)
        self._config_source = self._init_config_source()
        
        # Revocation (local list or synced)
        self._revocation_service = RevocationService(
            synced=(self.mode == BrokerMode.FOLLOWER)
        )
        
        # Sync service (only for distributed modes)
        if self.mode != BrokerMode.STANDALONE:
            self._sync_service = SyncService(...)
    
    # ─────────────────────────────────────────────────────────────────
    # PUBLIC API (Same regardless of mode)
    # ─────────────────────────────────────────────────────────────────
    
    def create_root_token(self, ...) -> AgentToken:
        """Create a root token. Only allowed in standalone/leader mode."""
        if self.mode == BrokerMode.FOLLOWER:
            raise NotAllowedError("Followers cannot create root tokens")
        ...
    
    def delegate(self, parent: AgentToken, request: DelegationRequest) -> AgentToken:
        """Delegate to create a child token. Allowed in all modes."""
        ...
    
    def get_credential(self, token: AgentToken, scope: str, resource: str) -> dict:
        """Get a provider credential. Allowed in all modes."""
        ...
    
    def verify_token(self, token: AgentToken) -> bool:
        """Verify token signature and check revocation."""
        ...
    
    def revoke_token(self, token: AgentToken, reason: str):
        """Revoke a token. In follower mode, forwards to leader."""
        ...
    
    @property
    def status(self) -> BrokerStatus:
        """Current broker status including sync state."""
        ...
```

### 7.3 Config Source

Abstracts the source of provider configurations:

```python
class ConfigSource(Protocol):
    """Source of provider configurations."""
    
    def get_provider_config(self, provider: str) -> Optional[dict]:
        """Get configuration for a provider."""
        ...
    
    def list_providers(self) -> list[str]:
        """List configured providers."""
        ...
    
    @property
    def version(self) -> int:
        """Configuration version (for sync)."""
        ...


class LocalConfigSource(ConfigSource):
    """Reads configs from local files."""
    
    def __init__(self, config_dir: Path):
        self.config_file = config_dir / "config.json"
    
    def get_provider_config(self, provider: str) -> Optional[dict]:
        configs = json.loads(self.config_file.read_text())
        return configs.get(provider)


class SyncedConfigSource(ConfigSource):
    """
    Reads configs from sync cache, with local overrides.
    
    Priority: local override > synced config
    """
    
    def __init__(self, config_dir: Path):
        self.local_file = config_dir / "config.json"
        self.synced_file = config_dir / "sync_cache" / "provider_configs.json"
    
    def get_provider_config(self, provider: str) -> Optional[dict]:
        # Check local override first
        if self.local_file.exists():
            local = json.loads(self.local_file.read_text())
            if provider in local:
                return local[provider]
        
        # Fall back to synced
        if self.synced_file.exists():
            synced = json.loads(self.synced_file.read_text())
            return synced.get("configs", {}).get(provider)
        
        return None
```

### 7.4 Revocation Service

Handles token revocation with support for both local and synced lists:

```python
class RevocationService:
    """
    Token revocation checking.
    
    Supports:
    - Local revocation list (standalone mode)
    - Synced revocation list (follower mode)
    - Combined checking (both)
    """
    
    def __init__(self, config_dir: Path, synced: bool = False):
        self.local_file = config_dir / "revocations.json"
        self.synced_file = config_dir / "sync_cache" / "revocations.json"
        self.synced = synced
        
        self._local_set: set[str] = set()
        self._synced_set: set[str] = set()
        self._synced_version: int = 0
        self._synced_at: Optional[datetime] = None
    
    def is_revoked(self, token: AgentToken) -> bool:
        """Check if token is revoked."""
        sig_prefix = token.signature[:16]
        
        # Check local list
        if sig_prefix in self._local_set:
            return True
        
        # Check synced list (if in distributed mode)
        if self.synced and sig_prefix in self._synced_set:
            return True
        
        return False
    
    def revoke_local(self, token: AgentToken):
        """Add token to local revocation list."""
        self._local_set.add(token.signature[:16])
        self._save_local()
    
    def update_synced(self, revocations: list[str], version: int):
        """Update synced revocation list (called by sync service)."""
        self._synced_set.update(revocations)
        self._synced_version = version
        self._synced_at = datetime.utcnow()
        self._save_synced()
    
    @property
    def staleness(self) -> Optional[timedelta]:
        """How stale is the synced revocation list?"""
        if not self._synced_at:
            return None
        return datetime.utcnow() - self._synced_at
```

### 7.5 Delegation Service

Handles capability delegation with attenuation validation:

```python
class DelegationService:
    """
    Creates delegated tokens with proper attenuation.
    
    Same logic for standalone and distributed modes.
    """
    
    def delegate(
        self,
        parent_token: AgentToken,
        request: DelegationRequest,
        signing_key: bytes,
        signing_key_version: Optional[int] = None,
        issuer_id: Optional[str] = None,
    ) -> AgentToken:
        """
        Create a delegated child token.
        
        Args:
            parent_token: The parent token to delegate from
            request: What the child is requesting
            signing_key: Key to sign the new token
            signing_key_version: Version of signing key (distributed only)
            issuer_id: ID of broker issuing token (distributed only)
        
        Raises:
            DelegationError: If delegation is not allowed
        """
        # Validate parent can delegate
        self._validate_parent(parent_token)
        
        # Validate requested scopes are subset of parent
        self._validate_scopes(parent_token, request.requested_scopes)
        
        # Validate constraints are narrower than parent
        merged_constraints = self._merge_constraints(
            parent_token.constraints,
            request.requested_constraints
        )
        
        # Calculate expiry
        child_expiry = self._calculate_expiry(parent_token, request.ttl_minutes)
        
        # Create child token
        child = AgentToken(
            agent_id=request.agent_id or f"agent-{uuid.uuid4().hex[:8]}",
            parent_id=parent_token.agent_id,
            scopes=request.requested_scopes,
            constraints=merged_constraints,
            delegatable=request.delegatable and parent_token.delegatable,
            max_delegation_depth=parent_token.max_delegation_depth,
            current_depth=parent_token.current_depth + 1,
            expires_at=child_expiry,
            issuer_id=issuer_id,
            signing_key_version=signing_key_version,
        )
        
        # Sign
        child.signature = self._sign(child, signing_key)
        
        return child
```

### 7.6 Provider Adapters

Each adapter implements:

```python
class ProviderAdapter(Protocol):
    """Interface for provider credential adapters."""
    
    async def issue_credential(
        self,
        config: dict,
        scope: str,
        resource: str,
    ) -> CredentialResult:
        """Issue a credential for the given scope and resource."""
        ...


@dataclass
class CredentialResult:
    credential_type: str         # "bearer_token", "aws_credentials", "api_key"
    credential: dict             # Provider-specific credential data
    expires_at: Optional[datetime]
```

See Section 11 (Appendices) for specific adapter implementations.

---

## 8. Distributed Extension

This section describes the optional distributed deployment mode, which extends the standalone broker to support leader/follower topologies.

### 8.1 Overview

The distributed extension enables:

- **Multi-location agents**: Agents running in different regions/networks
- **Centralized control**: Leader manages configurations and policies
- **Shared capabilities**: Tokens created by leader work at any follower
- **Revocation propagation**: Revoked tokens are blocked across all followers

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DISTRIBUTED TOPOLOGY                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                    ┌─────────────────────────────┐                          │
│                    │    CENTRAL AUTHORITY        │                          │
│                    │    (Optional - Vault/etc)   │                          │
│                    │                             │                          │
│                    │  • Master provider configs  │                          │
│                    │  • Policy definitions       │                          │
│                    │  • Audit aggregation        │                          │
│                    └──────────────┬──────────────┘                          │
│                                   │                                          │
│                                   ▼                                          │
│                    ┌─────────────────────────────┐                          │
│                    │      LEADER BROKER          │                          │
│                    │      (Region A / HQ)        │                          │
│                    │                             │                          │
│                    │  • Syncs from authority     │                          │
│                    │  • Issues root tokens       │                          │
│                    │  • Manages signing keys     │                          │
│                    │  • Pushes to followers      │                          │
│                    └──────────────┬──────────────┘                          │
│                                   │                                          │
│              ┌────────────────────┼────────────────────┐                    │
│              │                    │                    │                    │
│              ▼                    ▼                    ▼                    │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│   │ FOLLOWER BROKER │  │ FOLLOWER BROKER │  │ FOLLOWER BROKER │            │
│   │ (Region B)      │  │ (Region C)      │  │ (Edge Location) │            │
│   │                 │  │                 │  │                 │            │
│   │ • Local cache   │  │ • Local cache   │  │ • Offline capable│           │
│   │ • Sync from lead│  │ • Sync from lead│  │ • Issue creds   │            │
│   │ • Issue creds   │  │ • Issue creds   │  │                 │            │
│   └────────┬────────┘  └────────┬────────┘  └────────┬────────┘            │
│            │                    │                    │                      │
│            ▼                    ▼                    ▼                      │
│   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│   │  Local Agents   │  │  Local Agents   │  │  Local Agents   │            │
│   └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.2 What Gets Synced

| Data Type | Direction | Trigger | Rationale |
|-----------|-----------|---------|-----------|
| **Signing keys** | Leader → Followers | Pull on startup, push on rotation | Required for token verification |
| **Provider configs** | Leader → Followers | Pull every 5 min | Centralized config management |
| **Revocation list** | Leader → Followers | Pull every 30s, push on revoke | Security critical |
| **Root tokens** | Leader → Followers | Pull on demand | Consistency (optional) |
| **Audit logs** | Followers → Leader | Push async | Aggregation |

### 8.3 Sync Protocol

#### 8.3.1 Sync Request/Response

```python
@dataclass
class SyncRequest:
    """Request from follower to leader."""
    follower_id: str
    signing_key_version: int
    provider_configs_version: int
    revocation_list_version: int
    known_root_tokens: list[str] = field(default_factory=list)


@dataclass
class SyncResponse:
    """Response from leader to follower."""
    # Key updates
    signing_key: Optional[str] = None  # Base64-encoded, only if changed
    signing_key_version: int = 0
    
    # Config updates
    provider_configs: Optional[dict] = None  # Only if changed
    provider_configs_version: int = 0
    
    # Revocation updates (delta)
    revocation_list_delta: list[str] = field(default_factory=list)
    revocation_list_version: int = 0
    
    # Timing
    next_sync_seconds: int = 60
```

#### 8.3.2 Sync State Machine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FOLLOWER STATE MACHINE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         ┌──────────────┐                                    │
│                         │   STARTING   │                                    │
│                         └──────┬───────┘                                    │
│                                │                                             │
│                                ▼                                             │
│                    ┌───────────────────────┐                                │
│                    │   INITIAL_SYNC        │                                │
│                    │   (must complete or   │                                │
│                    │    have valid cache)  │                                │
│                    └───────────┬───────────┘                                │
│                                │                                             │
│              ┌─────────────────┼─────────────────┐                          │
│              │                 │                 │                          │
│              ▼                 ▼                 ▼                          │
│    ┌─────────────────┐ ┌─────────────┐ ┌─────────────────┐                 │
│    │    CONNECTED    │ │  DEGRADED   │ │    OFFLINE      │                 │
│    │                 │ │             │ │                 │                 │
│    │ • Full sync     │ │ • Stale     │ │ • Cached only   │                 │
│    │ • All ops OK    │ │ • Some ops  │ │ • Limited ops   │                 │
│    │ • Real-time rev │ │ • Stale rev │ │ • No revocation │                 │
│    └────────┬────────┘ └──────┬──────┘ └────────┬────────┘                 │
│             │                 │                 │                          │
│             │   ┌─────────────┴─────────────┐   │                          │
│             │   │                           │   │                          │
│             ▼   ▼                           ▼   ▼                          │
│         (transitions based on connectivity and cache age)                   │
│                                                                              │
│    CONNECTED → DEGRADED: No sync response for > 5 minutes                   │
│    DEGRADED → OFFLINE: No sync response for > 1 hour                        │
│    Any → CONNECTED: Successful sync                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.4 Signing Key Management

#### 8.4.1 Shared Key Model

All brokers share the same HMAC signing key, synced from leader:

```python
class SigningKeyManager:
    """
    Manages signing keys with versioning for distributed mode.
    """
    
    def __init__(self, config_dir: Path):
        self.config_dir = config_dir
        self._keys: dict[int, bytes] = {}  # version -> key
        self._current_version: int = 0
    
    def get_current_key(self) -> tuple[bytes, int]:
        """Get current signing key and version."""
        return self._keys[self._current_version], self._current_version
    
    def get_key(self, version: int) -> Optional[bytes]:
        """Get key by version (for verifying old tokens)."""
        return self._keys.get(version)
    
    def add_key(self, key: bytes, version: int):
        """Add a key (from sync)."""
        self._keys[version] = key
        if version > self._current_version:
            self._current_version = version
    
    def rotate(self) -> tuple[bytes, int]:
        """
        Rotate to a new key (leader only).
        
        Old keys are kept for verification.
        """
        new_key = secrets.token_bytes(32)
        new_version = self._current_version + 1
        
        self._keys[new_version] = new_key
        self._current_version = new_version
        
        self._persist()
        return new_key, new_version
```

#### 8.4.2 Key Rotation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KEY ROTATION FLOW                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TIME T=0: Normal operation                                                  │
│  ─────────────────────────                                                   │
│    Leader: key_v1                                                            │
│    Followers: key_v1                                                         │
│    Tokens signed with: v1                                                    │
│                                                                              │
│  TIME T=1: Leader rotates key                                                │
│  ────────────────────────────                                                │
│    Leader: key_v1, key_v2 (current)                                         │
│    Leader pushes key_v2 to followers                                         │
│    New tokens signed with: v2                                                │
│    Old tokens (v1) still verifiable                                          │
│                                                                              │
│  TIME T=2: Followers receive new key                                         │
│  ───────────────────────────────────                                         │
│    Followers: key_v1, key_v2 (current)                                      │
│    Followers can verify both v1 and v2 tokens                               │
│    Followers sign new delegations with v2                                    │
│                                                                              │
│  TIME T=3: Grace period expires                                              │
│  ──────────────────────────────                                              │
│    Old v1 tokens naturally expire                                            │
│    Leader can optionally drop key_v1                                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.5 Token Verification in Distributed Mode

```python
async def verify_token_distributed(
    token: AgentToken,
    broker: "Broker"
) -> VerificationResult:
    """
    Verify a token in distributed mode.
    
    Additional checks vs. standalone:
    - Signing key version
    - Revocation list (synced)
    - Offline grace period
    """
    
    # 1. Get the signing key for this token's version
    key_version = token.signing_key_version or broker.signing_key_version
    signing_key = broker.get_signing_key(key_version)
    
    if signing_key is None:
        # Unknown key version - try to sync
        if broker.mode == BrokerMode.FOLLOWER:
            await broker.sync()
            signing_key = broker.get_signing_key(key_version)
        
        if signing_key is None:
            return VerificationResult(
                valid=False,
                error=f"Unknown signing key version: {key_version}"
            )
    
    # 2. Verify signature
    if not verify_hmac(token, signing_key):
        return VerificationResult(valid=False, error="Invalid signature")
    
    # 3. Check expiration
    if token.expires_at and token.expires_at < datetime.utcnow():
        return VerificationResult(valid=False, error="Token expired")
    
    # 4. Check revocation
    if token.requires_online_validation:
        # Must check with leader
        if not broker.is_connected:
            return VerificationResult(
                valid=False,
                error="Online validation required but disconnected"
            )
        is_revoked = await broker.check_revocation_online(token)
    else:
        # Local/synced revocation list is OK
        is_revoked = broker.is_revoked(token)
    
    if is_revoked:
        return VerificationResult(valid=False, error="Token revoked")
    
    # 5. Check offline grace period
    if not broker.is_connected and token.offline_grace_period:
        offline_duration = datetime.utcnow() - broker.last_connected
        if offline_duration.total_seconds() > token.offline_grace_period:
            return VerificationResult(
                valid=False,
                error=f"Offline grace period exceeded: {offline_duration}"
            )
    
    return VerificationResult(valid=True)
```

### 8.6 Graceful Degradation

The system is designed so that distributed mode gracefully degrades to standalone operation:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DEGRADATION PATH                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  FULLY CONNECTED                                                             │
│  ────────────────                                                            │
│  • Real-time sync with leader                                               │
│  • Real-time revocation                                                      │
│  • Fresh configs                                                             │
│  • All operations allowed                                                    │
│           │                                                                  │
│           │ Leader unreachable for 5 minutes                                │
│           ▼                                                                  │
│  DEGRADED                                                                    │
│  ────────                                                                    │
│  • Using cached signing key ✓                                               │
│  • Using cached configs ✓                                                   │
│  • Revocation list may be stale (warn in logs)                              │
│  • All operations still allowed                                             │
│  • New root tokens not available (must wait for leader)                     │
│           │                                                                  │
│           │ Leader unreachable for 1 hour                                   │
│           ▼                                                                  │
│  LIMITED                                                                     │
│  ───────                                                                     │
│  • Same as DEGRADED, plus:                                                  │
│  • Tokens with requires_online_validation=true rejected                     │
│  • Tokens with offline_grace_period exceeded rejected                       │
│  • Logging indicates limited mode                                           │
│           │                                                                  │
│           │ Leader unreachable for 24 hours                                 │
│           ▼                                                                  │
│  OFFLINE                                                                     │
│  ───────                                                                     │
│  • Same as LIMITED, plus:                                                   │
│  • Explicit warnings on all operations                                      │
│  • Consider: require manual acknowledgment?                                 │
│           │                                                                  │
│           │ Remove leader_url from config                                   │
│           ▼                                                                  │
│  STANDALONE                                                                  │
│  ──────────                                                                  │
│  • No sync attempted                                                         │
│  • Local configs only                                                        │
│  • Local revocation list only                                               │
│  • Can create root tokens locally                                           │
│  • Full standalone operation                                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8.7 Leader Implementation

```python
class LeaderBroker(Broker):
    """
    Leader broker that accepts follower syncs.
    
    Extends base Broker with:
    - Sync endpoint for followers
    - Revocation push to followers
    - Key rotation
    - Optional authority sync
    """
    
    def __init__(
        self,
        config_dir: Path,
        authority_url: Optional[str] = None,
        authority_auth: Optional[str] = None,
    ):
        super().__init__(config_dir=config_dir, is_leader=True)
        self.authority_url = authority_url
        
        # Track followers
        self._followers: dict[str, FollowerInfo] = {}
        self._follower_websockets: dict[str, WebSocket] = {}
    
    # ─────────────────────────────────────────────────────────────────
    # SYNC ENDPOINT
    # ─────────────────────────────────────────────────────────────────
    
    async def handle_sync_request(self, request: SyncRequest) -> SyncResponse:
        """Handle sync request from a follower."""
        response = SyncResponse()
        
        # Signing key
        if request.signing_key_version < self._signing_key_version:
            key, version = self._signing_key_manager.get_current_key()
            response.signing_key = base64.b64encode(key).decode()
            response.signing_key_version = version
        
        # Provider configs
        if request.provider_configs_version < self._config_version:
            response.provider_configs = self._get_all_configs()
            response.provider_configs_version = self._config_version
        
        # Revocations (delta since follower's version)
        delta = self._revocation_service.get_delta_since(
            request.revocation_list_version
        )
        response.revocation_list_delta = delta
        response.revocation_list_version = self._revocation_service.version
        
        # Update follower tracking
        self._followers[request.follower_id] = FollowerInfo(
            follower_id=request.follower_id,
            last_sync=datetime.utcnow(),
            signing_key_version=response.signing_key_version,
        )
        
        return response
    
    # ─────────────────────────────────────────────────────────────────
    # REVOCATION WITH PUSH
    # ─────────────────────────────────────────────────────────────────
    
    async def revoke_token(self, token: AgentToken, reason: str):
        """Revoke a token and push to all followers."""
        # Add to local revocation list
        self._revocation_service.revoke(token)
        
        # Push to all connected followers
        message = {
            "type": "revocation",
            "signatures": [token.signature[:16]],
            "version": self._revocation_service.version,
        }
        
        await self._push_to_followers(message)
    
    async def _push_to_followers(self, message: dict):
        """Push a message to all connected followers."""
        for follower_id, ws in list(self._follower_websockets.items()):
            try:
                await ws.send_json(message)
            except Exception as e:
                logger.warning(f"Push to {follower_id} failed: {e}")
                del self._follower_websockets[follower_id]
    
    # ─────────────────────────────────────────────────────────────────
    # KEY ROTATION
    # ─────────────────────────────────────────────────────────────────
    
    async def rotate_signing_key(self):
        """Rotate the signing key and notify followers."""
        new_key, new_version = self._signing_key_manager.rotate()
        
        # Push to followers
        message = {
            "type": "key_rotation",
            "signing_key": base64.b64encode(new_key).decode(),
            "version": new_version,
        }
        
        await self._push_to_followers(message)
        
        logger.info(f"Rotated signing key to version {new_version}")
    
    # ─────────────────────────────────────────────────────────────────
    # AUTHORITY SYNC (Optional)
    # ─────────────────────────────────────────────────────────────────
    
    async def sync_from_authority(self):
        """
        Sync configurations from a central authority (e.g., Vault).
        
        This allows the leader to be managed by enterprise systems.
        """
        if not self.authority_url:
            return
        
        # Example: Fetch from Vault
        async with httpx.AsyncClient() as client:
            # Get provider configs from Vault KV
            response = await client.get(
                f"{self.authority_url}/v1/secret/data/agent-broker/providers",
                headers={"X-Vault-Token": self.authority_auth}
            )
            if response.is_success:
                data = response.json()["data"]["data"]
                self._update_configs(data)
            
            # Get policies
            response = await client.get(
                f"{self.authority_url}/v1/secret/data/agent-broker/policies",
                headers={"X-Vault-Token": self.authority_auth}
            )
            if response.is_success:
                policies = response.json()["data"]["data"]
                self._update_policies(policies)
```

### 8.8 Follower Implementation

```python
class FollowerBroker(Broker):
    """
    Follower broker that syncs from a leader.
    
    Extends base Broker with:
    - Background sync loop
    - Cached state management
    - Degraded operation
    """
    
    def __init__(
        self,
        config_dir: Path,
        leader_url: str,
        leader_auth_token: str,
        sync_interval: int = 60,
    ):
        super().__init__(
            config_dir=config_dir,
            leader_url=leader_url,
            leader_auth_token=leader_auth_token,
        )
        self.sync_interval = sync_interval
        
        # Sync state
        self._state = FollowerState.STARTING
        self._last_sync: Optional[datetime] = None
        self._last_connected: Optional[datetime] = None
        
        # Background tasks
        self._sync_task: Optional[asyncio.Task] = None
        self._websocket_task: Optional[asyncio.Task] = None
        self._shutdown = asyncio.Event()
    
    async def start(self):
        """Start the follower with initial sync."""
        # Load cached state
        await self._load_cache()
        
        # Try initial sync
        try:
            await self._do_sync()
            self._state = FollowerState.CONNECTED
        except SyncError:
            if self._has_valid_cache():
                logger.warning("Initial sync failed, using cache")
                self._state = FollowerState.DEGRADED
            else:
                raise StartupError("Cannot start: no sync and no cache")
        
        # Start background sync
        self._sync_task = asyncio.create_task(self._sync_loop())
        
        # Start WebSocket for push notifications
        self._websocket_task = asyncio.create_task(self._websocket_loop())
    
    async def stop(self):
        """Stop the follower gracefully."""
        self._shutdown.set()
        
        if self._sync_task:
            self._sync_task.cancel()
        if self._websocket_task:
            self._websocket_task.cancel()
        
        await self._save_cache()
    
    async def _sync_loop(self):
        """Background sync loop."""
        while not self._shutdown.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown.wait(),
                    timeout=self.sync_interval
                )
                break
            except asyncio.TimeoutError:
                pass
            
            try:
                await self._do_sync()
                self._state = FollowerState.CONNECTED
                self._last_connected = datetime.utcnow()
            except SyncError as e:
                logger.warning(f"Sync failed: {e}")
                self._update_degraded_state()
    
    async def _do_sync(self):
        """Perform sync with leader."""
        request = SyncRequest(
            follower_id=self.follower_id,
            signing_key_version=self._signing_key_manager.current_version,
            provider_configs_version=self._config_source.version,
            revocation_list_version=self._revocation_service.version,
        )
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.leader_url}/sync",
                json=asdict(request),
                headers={"Authorization": f"Bearer {self.leader_auth_token}"},
                timeout=10.0
            )
            response.raise_for_status()
            data = SyncResponse(**response.json())
        
        # Apply updates
        if data.signing_key:
            key = base64.b64decode(data.signing_key)
            self._signing_key_manager.add_key(key, data.signing_key_version)
        
        if data.provider_configs:
            self._config_source.update_synced(
                data.provider_configs,
                data.provider_configs_version
            )
        
        if data.revocation_list_delta:
            self._revocation_service.update_synced(
                data.revocation_list_delta,
                data.revocation_list_version
            )
        
        self._last_sync = datetime.utcnow()
    
    async def _websocket_loop(self):
        """Maintain WebSocket connection for push notifications."""
        while not self._shutdown.is_set():
            try:
                async with websockets.connect(
                    f"{self.leader_url.replace('http', 'ws')}/ws",
                    extra_headers={"Authorization": f"Bearer {self.leader_auth_token}"}
                ) as ws:
                    async for message in ws:
                        await self._handle_push(json.loads(message))
            except Exception as e:
                logger.warning(f"WebSocket error: {e}")
                await asyncio.sleep(5)  # Reconnect delay
    
    async def _handle_push(self, message: dict):
        """Handle push notification from leader."""
        if message["type"] == "revocation":
            self._revocation_service.update_synced(
                message["signatures"],
                message["version"]
            )
            logger.info(f"Received revocation push: {len(message['signatures'])} tokens")
        
        elif message["type"] == "key_rotation":
            key = base64.b64decode(message["signing_key"])
            self._signing_key_manager.add_key(key, message["version"])
            logger.info(f"Received key rotation: version {message['version']}")
    
    def _update_degraded_state(self):
        """Update state based on time since last sync."""
        if not self._last_connected:
            self._state = FollowerState.OFFLINE
            return
        
        offline_duration = datetime.utcnow() - self._last_connected
        
        if offline_duration < timedelta(minutes=5):
            self._state = FollowerState.CONNECTED  # Brief blip
        elif offline_duration < timedelta(hours=1):
            self._state = FollowerState.DEGRADED
        elif offline_duration < timedelta(hours=24):
            self._state = FollowerState.LIMITED
        else:
            self._state = FollowerState.OFFLINE
    
    @property
    def is_connected(self) -> bool:
        return self._state == FollowerState.CONNECTED
```

### 8.9 Configuration for Distributed Mode

**Leader configuration (`~/.agent-credentials/leader_config.json`):**
```json
{
  "leader_id": "leader-hq",
  "listen_address": "0.0.0.0:8443",
  "tls_cert": "/path/to/cert.pem",
  "tls_key": "/path/to/key.pem",
  "follower_auth_tokens": {
    "follower-region-b": "token-xxx",
    "follower-region-c": "token-yyy"
  },
  "authority": {
    "url": "https://vault.internal:8200",
    "auth_method": "approle",
    "role_id": "xxx",
    "secret_id": "yyy"
  }
}
```

**Follower configuration (`~/.agent-credentials/follower_config.json`):**
```json
{
  "follower_id": "follower-region-b",
  "leader_url": "https://leader.internal:8443",
  "leader_auth_token": "token-xxx",
  "sync_interval_seconds": 60,
  "offline_grace_hours": 24
}
```

**Detecting mode automatically:**
```python
def detect_broker_mode(config_dir: Path) -> BrokerMode:
    """Detect which mode to run in based on config files."""
    
    if (config_dir / "leader_config.json").exists():
        return BrokerMode.LEADER
    
    if (config_dir / "follower_config.json").exists():
        return BrokerMode.FOLLOWER
    
    return BrokerMode.STANDALONE
```

---

## 9. API Reference

### 9.1 CLI Interface

```bash
# ─────────────────────────────────────────────────────────────────
# PROVIDER SETUP (All modes)
# ─────────────────────────────────────────────────────────────────
broker init <provider>                    # Interactive setup
broker config show                        # Show current config (redacted)
broker config set <provider> <key> <val>  # Set config value

# ─────────────────────────────────────────────────────────────────
# TOKEN OPERATIONS (All modes, some restricted)
# ─────────────────────────────────────────────────────────────────
broker token create-root [options]        # Create root token (standalone/leader only)
broker token delegate [options]           # Create delegated token
broker token show <token>                 # Decode and display token
broker token verify <token>               # Verify token validity
broker token revoke <token> --reason=...  # Revoke token

# ─────────────────────────────────────────────────────────────────
# CREDENTIAL RETRIEVAL (All modes)
# ─────────────────────────────────────────────────────────────────
broker cred <scope> <resource> [--token=<token>]
broker cred github:repo:read myorg/myrepo
broker cred google:gmail:send me

# ─────────────────────────────────────────────────────────────────
# DISTRIBUTED MODE
# ─────────────────────────────────────────────────────────────────
broker status                             # Show broker status and sync state
broker sync                               # Force sync (follower only)
broker rotate-key                         # Rotate signing key (leader only)

# ─────────────────────────────────────────────────────────────────
# LEADER SERVER
# ─────────────────────────────────────────────────────────────────
broker serve                              # Start leader HTTP server
broker serve --port=8443 --tls
```

### 9.2 Python Library

```python
from agent_broker import Broker, BrokerMode, DelegationRequest

# ─────────────────────────────────────────────────────────────────
# STANDALONE MODE (Simplest)
# ─────────────────────────────────────────────────────────────────
broker = Broker()  # Auto-detects standalone

root = broker.create_root_token(
    agent_id="root",
    scopes=["github:repo:*"],
    constraints={"github:repo:*": {"resources": ["myorg/*"]}},
    ttl_days=7
)

child = broker.delegate(root, DelegationRequest(
    requested_scopes=["github:repo:read"],
    ttl_minutes=60
))

cred = broker.get_credential(child, "github:repo:read", "myorg/repo")

# ─────────────────────────────────────────────────────────────────
# DISTRIBUTED MODE (Leader)
# ─────────────────────────────────────────────────────────────────
leader = Broker(is_leader=True)
await leader.start()

root = leader.create_root_token(...)  # Only leader can create roots
await leader.revoke_token(bad_token, reason="compromised")
await leader.rotate_signing_key()

# ─────────────────────────────────────────────────────────────────
# DISTRIBUTED MODE (Follower)
# ─────────────────────────────────────────────────────────────────
follower = Broker(
    leader_url="https://leader:8443",
    leader_auth_token="xxx"
)
await follower.start()  # Syncs from leader

# These work the same as standalone
child = follower.delegate(parent, request)  # Signs locally
cred = follower.get_credential(token, scope, resource)

# Status
print(follower.status)
# {
#   "mode": "follower",
#   "state": "connected",
#   "last_sync": "2024-01-15T12:00:00Z",
#   "signing_key_version": 3,
#   "revocation_count": 42
# }
```

### 9.3 HTTP API (Leader)

```
POST /sync
  Request: SyncRequest
  Response: SyncResponse

GET /tokens/{token_id}
  Response: AgentToken

POST /tokens
  Request: CreateTokenRequest
  Response: AgentToken

DELETE /tokens/{token_id}
  Request: {"reason": "..."}
  Response: {"revoked": true}

POST /rotate-key
  Response: {"version": 4}

GET /status
  Response: {
    "mode": "leader",
    "signing_key_version": 3,
    "follower_count": 5,
    "revocation_count": 42
  }

WebSocket /ws
  Push messages: revocation, key_rotation
```

---

## 10. Implementation Roadmap

### Phase 1: Core Standalone (MVP)

**Goal:** Minimal working system for single-machine use.

**Deliverables:**
- [ ] Token data structure and signing
- [ ] GitHub provider adapter
- [ ] CLI for setup and credential retrieval
- [ ] Basic documentation

**Lines of code:** ~400
**Time estimate:** 1-2 days

### Phase 2: Delegation

**Goal:** Multi-agent support with capability delegation.

**Deliverables:**
- [ ] Delegation service with attenuation validation
- [ ] Token serialization for passing between processes
- [ ] Integration tests for delegation chains

**Lines of code:** ~150 additional
**Time estimate:** 1 day

### Phase 3: Runtime & Refresh

**Goal:** Production-ready runtime with lifecycle management.

**Deliverables:**
- [ ] AgentRuntime wrapper
- [ ] Background refresh thread
- [ ] Credential caching with TTL

**Lines of code:** ~150 additional
**Time estimate:** 1 day

### Phase 4: Additional Providers

**Goal:** Support for common providers.

**Deliverables:**
- [ ] Google OAuth adapter
- [ ] AWS STS adapter
- [ ] Generic API key adapter

**Lines of code:** ~50 per provider
**Time estimate:** 0.5 day per provider

### Phase 5: Distributed Extension

**Goal:** Leader/follower sync for multi-location deployment.

**Deliverables:**
- [ ] Sync protocol implementation
- [ ] Leader HTTP server
- [ ] Follower sync client
- [ ] Revocation push
- [ ] Key rotation

**Lines of code:** ~600 additional
**Time estimate:** 2-3 days

### Phase 6: Central Authority Integration

**Goal:** Enterprise integration with Vault/etc.

**Deliverables:**
- [ ] Vault adapter for leader
- [ ] Policy sync
- [ ] Audit log aggregation

**Lines of code:** ~200 additional
**Time estimate:** 1-2 days

### Total Estimates

| Component | Lines | Time |
|-----------|-------|------|
| Core standalone | ~400 | 2 days |
| Delegation | ~150 | 1 day |
| Runtime | ~150 | 1 day |
| Providers (3) | ~150 | 1.5 days |
| **Standalone total** | **~850** | **~5.5 days** |
| Distributed extension | ~600 | 3 days |
| Authority integration | ~200 | 2 days |
| **Full system total** | **~1650** | **~10.5 days** |

---

## 11. Appendices

### Appendix A: Comparison with Alternatives

| Feature | This System | Vault | Infisical | Akeyless |
|---------|-------------|-------|-----------|----------|
| **Standalone mode** | ✓ (~150MB) | ✓ (8GB+) | ✓ (512MB+) | ✗ |
| **Distributed mode** | ✓ (optional) | ✓ | ✓ | ✓ |
| **Multi-agent delegation** | ✓ Native | ✗ Manual | ✗ Manual | ✗ Manual |
| **Offline operation** | ✓ | ✓ | ✓ | ✗ |
| **GitHub dynamic secrets** | ✓ | Plugin | ✓ | ✓ |
| **Setup time** | 5 min | Hours | 30 min | 15 min |
| **Self-hosted** | ✓ | ✓ | ✓ | ✗ |
| **Enterprise features** | ✗ | ✓ | ✓ | ✓ |

### Appendix B: Scope Reference

```
# GitHub
github:repo:read          # Clone, fetch, read contents
github:repo:write         # Push, create branches
github:repo:admin         # Settings, webhooks
github:issues:read        # Read issues
github:issues:write       # Create/edit issues
github:actions:read       # Read workflows
github:actions:write      # Trigger workflows

# Google
google:gmail:read         # Read emails
google:gmail:send         # Send emails
google:drive:read         # Read Drive files
google:drive:write        # Create/edit files
google:calendar:read      # Read calendar
google:calendar:write     # Create/edit events

# AWS
aws:s3:read               # GetObject, ListBucket
aws:s3:write              # PutObject, DeleteObject
aws:lambda:invoke         # InvokeFunction
aws:*:*                   # All (within role)

# System
system:token:refresh      # Self-refresh capability
```

### Appendix C: Example Configurations

**Standalone (`~/.agent-credentials/config.json`):**
```json
{
  "github": {
    "app_id": "12345",
    "installation_id": "67890",
    "private_key_file": "github-app.pem"
  },
  "google": {
    "client_id": "xxx.apps.googleusercontent.com",
    "client_secret": "GOCSPX-xxx",
    "refresh_token": "1//xxx"
  }
}
```

**Follower (`~/.agent-credentials/follower_config.json`):**
```json
{
  "follower_id": "dev-laptop",
  "leader_url": "https://broker.internal:8443",
  "leader_auth_token": "follower-token-xxx",
  "sync_interval_seconds": 60,
  "local_config_override": {
    "github": {
      "private_key_file": "/local/path/to/key.pem"
    }
  }
}
```

### Appendix D: Token Examples

**Standalone token:**
```json
{
  "agent_id": "root",
  "scopes": ["github:repo:*", "google:gmail:send"],
  "constraints": {"github:repo:*": {"resources": ["myorg/*"]}},
  "delegatable": true,
  "max_delegation_depth": 3,
  "current_depth": 0,
  "expires_at": "2024-01-22T12:00:00Z",
  "signature": "a1b2c3d4..."
}
```

**Distributed token (additional fields):**
```json
{
  "agent_id": "research-agent",
  "parent_id": "root",
  "scopes": ["github:repo:read"],
  "constraints": {"github:repo:read": {"resources": ["myorg/docs"]}},
  "delegatable": false,
  "current_depth": 1,
  "expires_at": "2024-01-15T13:00:00Z",
  "issuer_id": "follower-region-b",
  "signing_key_version": 3,
  "offline_grace_period": 3600,
  "requires_online_validation": false,
  "signature": "f6e5d4c3..."
}
```

### Appendix E: Degradation Behavior Matrix

| Operation | Connected | Degraded | Limited | Offline | Standalone |
|-----------|-----------|----------|---------|---------|------------|
| Create root token | ✓ (leader) | ✗ | ✗ | ✗ | ✓ |
| Delegate token | ✓ | ✓ | ✓ | ✓ | ✓ |
| Verify token | ✓ | ✓ (warn) | ✓ (restrict) | ✓ (warn) | ✓ |
| Get credential | ✓ | ✓ | ✓ | ✓ | ✓ |
| Revoke token | ✓ (push) | ✓ (local) | ✓ (local) | ✓ (local) | ✓ (local) |
| Check revocation | ✓ (fresh) | ✓ (stale) | ✓ (stale) | ✓ (stale) | ✓ (local) |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-02 | Initial draft - standalone mode |
| 1.1 | 2025-02 | Added distributed extension (Section 8) |

---

## Glossary

| Term | Definition |
|------|------------|
| **Standalone mode** | Single-broker operation with no sync |
| **Distributed mode** | Leader/follower topology with sync |
| **Leader** | Authoritative broker that followers sync from |
| **Follower** | Broker that syncs state from leader |
| **Authority** | External system (Vault) that leader syncs from |
| **Degraded** | Follower operating with stale cache |
| **Attenuation** | Narrowing of capabilities during delegation |
| **Capability token** | Signed token specifying allowed operations |
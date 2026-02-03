# Agent Credential Broker: Design Specification

**Version:** 1.2  
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
11. [Extensibility & Migration Paths](#11-extensibility--migration-paths)
12. [Appendices](#12-appendices)

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

## 11. Extensibility & Migration Paths

This section documents the architectural seams that enable future integration with industry-standard systems, and provides migration paths for each component.

### 11.1 Design Philosophy

The system is designed with explicit adapter seams, allowing each component to be replaced independently:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADAPTER SEAM ARCHITECTURE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         CORE BROKER                                  │   │
│   │                                                                      │   │
│   │   ┌──────────────┐     ┌──────────────┐     ┌──────────────┐       │   │
│   │   │    TOKEN     │     │   POLICY     │     │  CREDENTIAL  │       │   │
│   │   │   SERVICE    │     │   SERVICE    │     │   SERVICE    │       │   │
│   │   │  (Protocol)  │     │  (Protocol)  │     │  (Protocol)  │       │   │
│   │   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘       │   │
│   │          │                    │                    │               │   │
│   │   ┌──────┴───────┐     ┌──────┴───────┐     ┌──────┴───────┐       │   │
│   │   │   ADAPTER    │     │   ADAPTER    │     │   ADAPTER    │       │   │
│   │   │    SEAM      │     │    SEAM      │     │    SEAM      │       │   │
│   │   └──────┬───────┘     └──────┬───────┘     └──────┬───────┘       │   │
│   │          │                    │                    │               │   │
│   └──────────┼────────────────────┼────────────────────┼───────────────┘   │
│              │                    │                    │                    │
│   ┌──────────┼────────────────────┼────────────────────┼───────────────┐   │
│   │          ▼                    ▼                    ▼               │   │
│   │   ┌────────────┐       ┌────────────┐       ┌────────────┐        │   │
│   │   │  Simple    │       │  Simple    │       │  Simple    │        │   │
│   │   │  (Default) │       │  (Default) │       │  (Default) │        │   │
│   │   └────────────┘       └────────────┘       └────────────┘        │   │
│   │                                                                    │   │
│   │   ┌────────────┐       ┌────────────┐       ┌────────────┐        │   │
│   │   │  Biscuit   │       │    OPA     │       │   Vault    │        │   │
│   │   │  Adapter   │       │  Adapter   │       │  Adapter   │        │   │
│   │   └────────────┘       └────────────┘       └────────────┘        │   │
│   │                                                                    │   │
│   │   ┌────────────┐       ┌────────────┐       ┌────────────┐        │   │
│   │   │   UCAN     │       │   Cedar    │       │ Infisical  │        │   │
│   │   │  Adapter   │       │  Adapter   │       │  Adapter   │        │   │
│   │   └────────────┘       └────────────┘       └────────────┘        │   │
│   │          IMPLEMENTATIONS (Swappable)                               │   │
│   └────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Similarly for: Identity, Sync, Revocation services                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key principle:** Build simple implementations first, define clean interfaces, add adapters when enterprise requirements emerge.

### 11.2 Service Interfaces

Each core service is defined as a Protocol (interface) with a simple default implementation:

#### 11.2.1 Token Service Interface

```python
class TokenService(Protocol):
    """
    Interface for token creation, verification, and attenuation.
    
    Implementations:
    - SimpleTokenService: HMAC-signed tokens (default)
    - BiscuitTokenService: Biscuit tokens with Datalog policies
    - UCANTokenService: UCAN tokens with embedded proof chains
    """
    
    def create(self, claims: TokenClaims) -> Token:
        """Create a new token with the given claims."""
        ...
    
    def verify(self, token: Token) -> VerificationResult:
        """Verify token signature and basic validity."""
        ...
    
    def attenuate(self, token: Token, restrictions: Restrictions) -> Token:
        """Create a new token with narrower permissions."""
        ...
    
    def encode(self, token: Token) -> str:
        """Encode token for transport (e.g., base64)."""
        ...
    
    def decode(self, encoded: str) -> Token:
        """Decode token from transport format."""
        ...
```

#### 11.2.2 Policy Service Interface

```python
class PolicyService(Protocol):
    """
    Interface for authorization policy evaluation.
    
    Implementations:
    - SimplePolicyService: Inline scope/constraint matching (default)
    - OPAPolicyService: Open Policy Agent with Rego policies
    - CedarPolicyService: AWS Cedar policy language
    """
    
    def check(
        self,
        token: Token,
        action: str,
        resource: str,
        context: Optional[dict] = None
    ) -> PolicyDecision:
        """
        Check if token allows action on resource.
        
        Returns:
            PolicyDecision with allowed/denied and optional explanation
        """
        ...
    
    def list_permissions(self, token: Token) -> list[Permission]:
        """List all permissions granted by token."""
        ...
```

#### 11.2.3 Credential Service Interface

```python
class CredentialService(Protocol):
    """
    Interface for provider credential issuance.
    
    Implementations:
    - SimpleCredentialService: Direct provider API calls (default)
    - VaultCredentialService: HashiCorp Vault secrets engines
    - InfisicalCredentialService: Infisical dynamic secrets
    """
    
    def issue(
        self,
        provider: str,
        scope: str,
        resource: str,
        ttl: Optional[timedelta] = None
    ) -> Credential:
        """Issue a credential for the given scope and resource."""
        ...
    
    def revoke(self, credential: Credential) -> bool:
        """Revoke a credential (if supported by provider)."""
        ...
    
    def list_providers(self) -> list[str]:
        """List configured providers."""
        ...
```

#### 11.2.4 Identity Service Interface

```python
class IdentityService(Protocol):
    """
    Interface for agent identity.
    
    Implementations:
    - SimpleIdentityService: String-based agent IDs (default)
    - SPIFFEIdentityService: SPIFFE/SPIRE workload identity
    - DIDIdentityService: Decentralized Identifiers
    """
    
    def get_identity(self) -> AgentIdentity:
        """Get identity for current agent/workload."""
        ...
    
    def verify_identity(self, identity: AgentIdentity) -> bool:
        """Verify an identity claim."""
        ...
    
    def create_identity(self, name: str, metadata: dict) -> AgentIdentity:
        """Create a new identity (if supported)."""
        ...
```

#### 11.2.5 Sync Service Interface

```python
class SyncService(Protocol):
    """
    Interface for distributed state synchronization.
    
    Implementations:
    - SimpleSyncService: HTTP-based leader/follower (default)
    - ConsulSyncService: Consul KV-based sync
    - EtcdSyncService: etcd-based sync
    """
    
    async def sync(self) -> SyncResult:
        """Pull latest state from upstream."""
        ...
    
    async def push(self, update: SyncUpdate) -> bool:
        """Push update to downstream (leader only)."""
        ...
    
    def get_state(self) -> SyncState:
        """Get current sync state."""
        ...
    
    @property
    def is_connected(self) -> bool:
        """Whether currently connected to upstream."""
        ...
```

#### 11.2.6 Revocation Service Interface

```python
class RevocationService(Protocol):
    """
    Interface for token revocation.
    
    Implementations:
    - SimpleRevocationService: Local set + synced list (default)
    - ZanzibarRevocationService: SpiceDB/Zanzibar relationship-based
    - WebhookRevocationService: External revocation check via webhook
    """
    
    def is_revoked(self, token: Token) -> bool:
        """Check if token is revoked."""
        ...
    
    def revoke(self, token: Token, reason: str) -> bool:
        """Revoke a token."""
        ...
    
    def list_revocations(self, since: Optional[datetime] = None) -> list[Revocation]:
        """List revocations, optionally since a timestamp."""
        ...
```

### 11.3 Industry Systems Comparison

#### 11.3.1 Token Format Systems

| System | Description | When to Adopt |
|--------|-------------|---------------|
| **Macaroons** | Google's capability tokens with caveats | Legacy compatibility |
| **Biscuit** | Datalog-based capability tokens with formal verification | Need complex policy logic, formal verification |
| **UCAN** | JWT-based tokens with embedded proof chains | Decentralized/Web3 environments, fully offline |
| **Our Simple Tokens** | HMAC-signed JSON tokens | Default, simple cases |

**Biscuit Migration Example:**

```python
class BiscuitTokenService(TokenService):
    """Biscuit implementation of TokenService."""
    
    def __init__(self, root_key: biscuit.PrivateKey):
        self.root_key = root_key
    
    def create(self, claims: TokenClaims) -> Token:
        builder = biscuit.BiscuitBuilder(self.root_key)
        
        # Map our claims to Biscuit facts
        for scope in claims.scopes:
            builder.add_authority_fact(f'right("{scope}")')
        
        for scope, constraint in claims.constraints.items():
            for resource in constraint.get("resources", []):
                builder.add_authority_fact(f'allowed_resource("{scope}", "{resource}")')
        
        builder.add_authority_fact(f'max_depth({claims.max_depth})')
        builder.add_authority_fact(f'expires({claims.expires_at.isoformat()})')
        
        biscuit_token = builder.build()
        
        return Token(
            format="biscuit",
            data=biscuit_token.to_base64(),
            claims=claims
        )
    
    def verify(self, token: Token) -> VerificationResult:
        try:
            biscuit_token = biscuit.Biscuit.from_base64(
                token.data, 
                self.root_key.public()
            )
            
            authorizer = biscuit.Authorizer()
            authorizer.add_token(biscuit_token)
            authorizer.add_fact(f'time({datetime.utcnow().isoformat()})')
            authorizer.add_policy("allow if true")
            authorizer.authorize()
            
            return VerificationResult(valid=True)
        except Exception as e:
            return VerificationResult(valid=False, error=str(e))
    
    def attenuate(self, token: Token, restrictions: Restrictions) -> Token:
        biscuit_token = biscuit.Biscuit.from_base64(
            token.data,
            self.root_key.public()
        )
        
        # Add attenuation block with checks
        block = biscuit.BlockBuilder()
        
        if restrictions.allowed_scopes:
            scope_check = " || ".join(f'right("{s}")' for s in restrictions.allowed_scopes)
            block.add_check(f'check if {scope_check}')
        
        if restrictions.allowed_resources:
            for scope, resources in restrictions.allowed_resources.items():
                for resource in resources:
                    block.add_check(f'check if allowed_resource("{scope}", "{resource}")')
        
        if restrictions.expires_at:
            block.add_check(f'check if time($t), $t < {restrictions.expires_at.isoformat()}')
        
        attenuated = biscuit_token.attenuate(block)
        
        return Token(
            format="biscuit",
            data=attenuated.to_base64(),
            claims=self._extract_claims(attenuated)
        )
```

#### 11.3.2 Policy Evaluation Systems

| System | Description | When to Adopt |
|--------|-------------|---------------|
| **OPA/Rego** | General-purpose policy engine | Complex dynamic policies, policy testing |
| **Cedar** | AWS's policy language | AWS integration, formal verification |
| **Zanzibar/SpiceDB** | Relationship-based access control | Complex permission hierarchies |
| **Our Simple Matcher** | Inline scope/constraint matching | Default, simple cases |

**OPA Migration Example:**

```python
class OPAPolicyService(PolicyService):
    """OPA implementation of PolicyService."""
    
    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url
    
    def check(
        self,
        token: Token,
        action: str,
        resource: str,
        context: Optional[dict] = None
    ) -> PolicyDecision:
        input_data = {
            "token": {
                "agent_id": token.claims.agent_id,
                "scopes": token.claims.scopes,
                "constraints": token.claims.constraints,
                "depth": token.claims.current_depth,
            },
            "action": action,
            "resource": resource,
            "context": context or {},
        }
        
        response = httpx.post(
            f"{self.opa_url}/v1/data/agentbroker/authz",
            json={"input": input_data}
        )
        
        result = response.json().get("result", {})
        
        return PolicyDecision(
            allowed=result.get("allow", False),
            reason=result.get("reason"),
            obligations=result.get("obligations", [])
        )
```

**OPA Policy (Rego):**

```rego
package agentbroker.authz

default allow = false

# Allow if token has matching scope and resource is permitted
allow {
    some scope in input.token.scopes
    scope_matches(scope, input.action)
    resource_permitted(input.action, input.resource)
}

# Scope matching with wildcards
scope_matches(scope, action) {
    scope == action
}

scope_matches(scope, action) {
    endswith(scope, ":*")
    prefix := trim_suffix(scope, "*")
    startswith(action, prefix)
}

# Resource constraint checking
resource_permitted(action, resource) {
    constraint := input.token.constraints[action]
    some pattern in constraint.resources
    glob.match(pattern, ["/"], resource)
}

resource_permitted(action, resource) {
    not input.token.constraints[action]  # No constraint = all allowed
}

# Provide reason for denial
reason = msg {
    not allow
    not any_scope_matches
    msg := "No matching scope in token"
}

reason = msg {
    not allow
    any_scope_matches
    msg := "Resource not permitted by constraints"
}

any_scope_matches {
    some scope in input.token.scopes
    scope_matches(scope, input.action)
}
```

#### 11.3.3 Credential Issuance Systems

| System | Description | When to Adopt |
|--------|-------------|---------------|
| **HashiCorp Vault** | Enterprise secrets management | Enterprise deployment, audit requirements |
| **Infisical** | Open-source secrets management | Team deployment, lighter weight than Vault |
| **Cloud KMS** | AWS/GCP/Azure native | Cloud-native deployment |
| **Our Simple Adapters** | Direct provider API calls | Default, simple cases |

**Vault Migration Example:**

```python
class VaultCredentialService(CredentialService):
    """Vault implementation of CredentialService."""
    
    def __init__(self, vault_url: str, vault_token: str):
        self.client = hvac.Client(url=vault_url, token=vault_token)
    
    def issue(
        self,
        provider: str,
        scope: str,
        resource: str,
        ttl: Optional[timedelta] = None
    ) -> Credential:
        if provider == "github":
            return self._issue_github(scope, resource, ttl)
        elif provider == "aws":
            return self._issue_aws(scope, resource, ttl)
        elif provider == "google":
            return self._issue_google(scope, resource, ttl)
        else:
            return self._issue_kv(provider, scope, resource)
    
    def _issue_github(self, scope: str, resource: str, ttl: Optional[timedelta]) -> Credential:
        # Use Vault's GitHub secrets engine
        permissions = self._scope_to_github_permissions(scope)
        
        response = self.client.secrets.github.generate_token(
            mount_point="github",
            installation_id=self._get_installation_id(resource),
            repository_ids=[self._get_repo_id(resource)],
            permissions=permissions
        )
        
        return Credential(
            provider="github",
            credential_type="bearer_token",
            data={"token": response["data"]["token"]},
            expires_at=datetime.fromisoformat(response["data"]["expires_at"])
        )
    
    def _issue_aws(self, scope: str, resource: str, ttl: Optional[timedelta]) -> Credential:
        # Use Vault's AWS secrets engine
        response = self.client.secrets.aws.generate_credentials(
            name="agent-role",
            role_arn=self._get_role_arn(resource),
            ttl=str(int(ttl.total_seconds())) + "s" if ttl else None
        )
        
        return Credential(
            provider="aws",
            credential_type="aws_credentials",
            data={
                "access_key_id": response["data"]["access_key"],
                "secret_access_key": response["data"]["secret_key"],
                "session_token": response["data"]["security_token"]
            },
            expires_at=datetime.utcnow() + timedelta(seconds=response["lease_duration"])
        )
```

#### 11.3.4 Identity Systems

| System | Description | When to Adopt |
|--------|-------------|---------------|
| **SPIFFE/SPIRE** | Workload identity | Need workload attestation, zero-trust |
| **DIDs** | Decentralized identifiers | Decentralized environments |
| **Our Simple IDs** | String-based agent IDs | Default, simple cases |

**SPIFFE Migration Example:**

```python
class SPIFFEIdentityService(IdentityService):
    """SPIFFE/SPIRE implementation of IdentityService."""
    
    def __init__(self, workload_api_addr: str = "unix:///tmp/spire-agent/public/api.sock"):
        self.workload_api = workload_api_addr
        self._source = None
    
    def _get_source(self):
        if not self._source:
            self._source = spiffe.WorkloadApiSource(self.workload_api)
        return self._source
    
    def get_identity(self) -> AgentIdentity:
        source = self._get_source()
        svid = source.get_x509_svid()
        
        return AgentIdentity(
            id=str(svid.spiffe_id),  # e.g., "spiffe://example.com/agent/research"
            type="spiffe",
            certificate=svid.cert_chain_pem,
            metadata={
                "trust_domain": svid.spiffe_id.trust_domain,
                "path": svid.spiffe_id.path,
            }
        )
    
    def verify_identity(self, identity: AgentIdentity) -> bool:
        if identity.type != "spiffe":
            return False
        
        source = self._get_source()
        bundle = source.get_bundle()
        
        # Verify the certificate chain against the trust bundle
        try:
            spiffe.verify_x509_svid(
                identity.certificate,
                bundle,
                expected_spiffe_id=identity.id
            )
            return True
        except spiffe.VerificationError:
            return False
```

### 11.4 Migration Risk Assessment

| Component | Current | Replace With | Effort | Risk | Offline Impact |
|-----------|---------|--------------|--------|------|----------------|
| Token format | SimpleToken | Biscuit | 2 days | Low | None |
| Token format | SimpleToken | UCAN | 2 days | Low | Improved |
| Policy eval | SimpleMatcher | OPA | 1 day | Low | Degraded* |
| Policy eval | SimpleMatcher | Cedar | 1 day | Low | Degraded* |
| Credentials | SimpleAdapters | Vault | 1-2 days | Low | Broken** |
| Credentials | SimpleAdapters | Infisical | 1 day | Low | Broken** |
| Identity | StringIDs | SPIFFE | 1 day | Low | Degraded* |
| Sync | SimpleSync | Consul | 2 days | Medium | Same |
| Revocation | SimpleList | Zanzibar | 1 day | Low | Broken** |

*Can fall back to cached/simple mode
**Requires connectivity to external system

### 11.5 What's Unique to Our Design

These aspects are **not available in existing systems** and represent our core value:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    UNIQUE VALUE PROPOSITION                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. AGENT-SPECIFIC DELEGATION SEMANTICS                                     │
│  ───────────────────────────────────────                                    │
│                                                                              │
│     "Create a sub-agent that can only read these 3 repos for 30 minutes"   │
│                                                                              │
│     No existing system has first-class support for:                         │
│     • Parent-to-child capability delegation                                 │
│     • Automatic scope attenuation                                           │
│     • Depth-limited delegation chains                                       │
│     • Per-delegation TTL constraints                                        │
│                                                                              │
│     Vault: Would require creating new policy + identity (heavyweight)       │
│     OPA: Would require custom policy logic and external state              │
│     SPIFFE: Doesn't handle authorization at all                            │
│                                                                              │
│  2. GRACEFUL DEGRADATION                                                    │
│  ────────────────────────                                                   │
│                                                                              │
│     "Leader is down but I have cached state from 10 minutes ago.           │
│      Continue operating with stale revocation list, warn in logs."          │
│                                                                              │
│     Vault: Fails closed (no Vault = no secrets)                             │
│     OPA: Usually fails closed                                               │
│     SPIFFE: Fails closed                                                    │
│                                                                              │
│     Our design explicitly supports:                                         │
│     • Connected → Degraded → Limited → Offline state machine               │
│     • Per-token offline grace periods                                       │
│     • Cached state persistence across restarts                             │
│     • Clear degradation behavior matrix                                     │
│                                                                              │
│  3. INTEGRATED CREDENTIAL ISSUANCE                                          │
│  ─────────────────────────────────                                          │
│                                                                              │
│     "I have this token → I get a GitHub credential scoped to match"         │
│                                                                              │
│     Most systems separate authorization from credential issuance:           │
│     • OPA/Zanzibar: "Are you allowed?" (doesn't issue credentials)          │
│     • Vault: Issues credentials (but identity-based, not capability-based)  │
│     • SPIFFE: Issues identity (doesn't do authorization or credentials)     │
│                                                                              │
│     Our design unifies:                                                      │
│     • Capability verification                                                │
│     • Scope-matched credential issuance                                     │
│     • Credential caching with TTL alignment                                 │
│                                                                              │
│  4. SUBPROCESS TOKEN PASSING                                                │
│  ───────────────────────────                                                │
│                                                                              │
│     "Spawn a subprocess with AGENT_TOKEN env var containing narrowed token" │
│                                                                              │
│     Agent-specific pattern not addressed by enterprise systems:             │
│     • Environment-based token injection                                     │
│     • Automatic delegation on subprocess spawn                              │
│     • Token refresh across process boundaries                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.6 Phased Adoption Strategy

#### Phase 1: Simple Implementation (Current)

Build with clean interfaces, simple implementations:

```python
# Configuration-driven service selection
def create_broker(config: BrokerConfig) -> Broker:
    return Broker(
        token_service=SimpleTokenService(config.signing_secret),
        policy_service=SimplePolicyService(),
        credential_service=SimpleCredentialService(config.providers),
        identity_service=SimpleIdentityService(),
        sync_service=SimpleSyncService(config.leader_url) if config.leader_url else None,
        revocation_service=SimpleRevocationService(),
    )
```

**Deliverable:** Working system with ~1200 lines, no external dependencies beyond provider SDKs.

#### Phase 2: Enterprise Credential Backend

When you need audit logging, lease management, or more providers:

```python
# Swap credential service to Vault
def create_broker(config: BrokerConfig) -> Broker:
    if config.credential_backend == "vault":
        credential_service = VaultCredentialService(
            vault_url=config.vault_url,
            vault_token=config.vault_token
        )
    else:
        credential_service = SimpleCredentialService(config.providers)
    
    return Broker(
        token_service=SimpleTokenService(config.signing_secret),
        policy_service=SimplePolicyService(),
        credential_service=credential_service,  # Swapped
        # ... rest unchanged
    )
```

**Trigger:** Team deployment, audit requirements, >5 providers
**Effort:** 1-2 days

#### Phase 3: Complex Policy Requirements

When you need dynamic policies, policy testing, or complex authorization logic:

```python
# Add OPA for policy evaluation
def create_broker(config: BrokerConfig) -> Broker:
    if config.policy_backend == "opa":
        policy_service = OPAPolicyService(config.opa_url)
    else:
        policy_service = SimplePolicyService()
    
    return Broker(
        # ... 
        policy_service=policy_service,  # Swapped
        # ...
    )
```

**Trigger:** Complex policy requirements, need for policy simulation/testing
**Effort:** 1 day + policy writing

#### Phase 4: Formal Verification / Advanced Tokens

When you need cryptographic proof chains or formal policy verification:

```python
# Upgrade token format to Biscuit
def create_broker(config: BrokerConfig) -> Broker:
    if config.token_format == "biscuit":
        token_service = BiscuitTokenService(config.biscuit_root_key)
    elif config.token_format == "ucan":
        token_service = UCANTokenService(config.did_key)
    else:
        token_service = SimpleTokenService(config.signing_secret)
    
    return Broker(
        token_service=token_service,  # Swapped
        # ...
    )
```

**Trigger:** Formal verification requirements, decentralized deployment, third-party caveats
**Effort:** 2 days

#### Phase 5: Workload Attestation

When you need to verify agent/workload identity cryptographically:

```python
# Add SPIFFE identity verification
def create_broker(config: BrokerConfig) -> Broker:
    if config.identity_backend == "spiffe":
        identity_service = SPIFFEIdentityService(config.spire_socket)
    else:
        identity_service = SimpleIdentityService()
    
    return Broker(
        # ...
        identity_service=identity_service,  # Swapped
        # ...
    )
```

**Trigger:** Zero-trust requirements, need to verify where agents are running
**Effort:** 1 day + SPIRE deployment

### 11.7 Hybrid Configurations

For gradual migration, components can be mixed:

```python
# Example: Vault for credentials, OPA for complex policies, simple tokens
broker = Broker(
    token_service=SimpleTokenService(secret),           # Simple HMAC tokens
    policy_service=HybridPolicyService(                 # Simple + OPA fallback
        simple=SimplePolicyService(),
        opa=OPAPolicyService(opa_url),
        use_opa_for=["complex:*"]                       # Only some scopes use OPA
    ),
    credential_service=VaultCredentialService(vault),   # Vault for credentials
    identity_service=SimpleIdentityService(),           # Simple string IDs
    revocation_service=SimpleRevocationService(),       # Simple list
)
```

**Hybrid Policy Example:**

```python
class HybridPolicyService(PolicyService):
    """Use simple matching for basic cases, OPA for complex ones."""
    
    def __init__(
        self,
        simple: SimplePolicyService,
        opa: OPAPolicyService,
        use_opa_for: list[str]
    ):
        self.simple = simple
        self.opa = opa
        self.opa_patterns = use_opa_for
    
    def check(self, token: Token, action: str, resource: str, context: dict = None) -> PolicyDecision:
        # Determine which service to use
        use_opa = any(
            fnmatch.fnmatch(action, pattern) 
            for pattern in self.opa_patterns
        )
        
        if use_opa and self.opa.is_available():
            return self.opa.check(token, action, resource, context)
        else:
            return self.simple.check(token, action, resource, context)
```

### 11.8 Lock-in Assessment Summary

| Concern | Risk Level | Mitigation |
|---------|------------|------------|
| Token format lock-in | **Low** | Clean TokenService interface, format field in tokens |
| Policy logic lock-in | **Low** | PolicyService interface, simple default always available |
| Credential backend lock-in | **Low** | CredentialService interface, provider adapter pattern |
| Sync protocol lock-in | **Medium** | More integrated, but can swap SyncService implementation |
| Core orchestration lock-in | **Owned** | This is our value-add (delegation, degradation, agent UX) |

**Bottom line:** The architecture is designed for component-level replacement. The main "lock-in" is to our orchestration logic, which is also where our unique value lies.

---

## 12. Appendices

### 12.1 Appendix A: Comparison with Alternatives

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

### 12.2 Appendix B: Scope Reference

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

### 12.3 Appendix C: Example Configurations

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

### 12.4 Appendix D: Token Examples

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

### 12.5 Appendix E: Degradation Behavior Matrix

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
| 1.2 | 2025-02 | Added extensibility & migration paths (Section 11) |

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
| **Adapter seam** | Interface boundary allowing component replacement |
| **Service protocol** | Abstract interface defining component contract |
| **Biscuit** | Datalog-based capability token format with formal verification |
| **UCAN** | User Controlled Authorization Networks - JWT-based capability tokens |
| **OPA** | Open Policy Agent - general-purpose policy engine |
| **SPIFFE** | Secure Production Identity Framework for Everyone - workload identity standard |
| **Zanzibar** | Google's relationship-based access control system |
# Agent IAM — Feature Roadmap

**Status:** Active
**Last Updated:** 2026-04-27 (W1 revised with MCP threat-landscape research)

This document tracks in-flight feature workstreams. Each section captures the
design we've agreed on, the scope, the planned API surface, and open questions.
Use the **Status** field at the top of each workstream to track progress:
`Proposed` → `In Design` → `In Progress` → `Shipped`.

For background on the existing system, see `docs/design.md` and
`docs/persistent-identity-design.md`.

---

## Table of Contents

1. [Workstream 1 — MCP Tool Access Control](#workstream-1--mcp-tool-access-control)
2. [Workstream 2 — Just-In-Time Elevation](#workstream-2--just-in-time-elevation)
3. [Workstream 3 — Human On-Behalf-Of (OBO)](#workstream-3--human-on-behalf-of-obo)
4. [Explicitly Out of Scope](#explicitly-out-of-scope)
5. [Sequencing](#sequencing)

---

## Workstream 1 — MCP Tool Access Control

**Status:** Shipped (v1, 2026-04-29)
**Owner:** _unassigned_
**Depends on:** none
**Sequence:** ship first

**Shipped on branch `claude/agent-iam-access-research-n38yi`:**

| Step | Module | Tests | Commit |
|---|---|---|---|
| 1. Tool-schema TOFU | `src/mcp/schema-pin.ts` | 31 | `f913b32` |
| 2. Allow/deny scope policy | `src/mcp/policy.ts` | 22 | `1ca0d82` |
| 3. RFC 8707 audience binding | `src/mcp/credential.ts` | 17 | `8f04e6e` |
| 4. Annotation primitives | `src/mcp/annotations.ts` | 17 | `585eb41` |
| 5. Server identity verification | `src/mcp/server-trust.ts`, `server-schema.ts` | 27 | `c145cae` |
| 6. CLI + reference harness + docs | `src/cli.ts` (mcp commands), `examples/mcp-harness/`, `docs/mcp-policy.md` | (manual) | (this commit) |

**Deferred:** picomatch swap (no real bug class to fix); broker integration for
`Broker.issueForMCPServer()` (pure functions ship; broker plumbing is follow-up
work that doesn't change the contract); vendoring the dated official
`server.json` schema for full conformance (current structural check is
sufficient for v1).

### v1 Limitations / known deployment gaps

W1 nailed the **policy and verification primitives** but the **distribution and
operations layer** has known gaps. As a security toolkit for a single trusted
harness on a workstation, W1 is feature-complete. As a deployable system for an
org running many agents, the items below need filling in.

| # | Gap | Severity for ops | Status |
|---|---|---|---|
| G1 | **Broker-config storage for `mcpDenyPolicy`** — currently an `CheckMCPCallOptions` field the harness must plumb. No CLI to manage; no propagation through distributed mode. | High | Closed (`c2a5e75`) — single-broker complete; distributed-mode propagation deferred |
| G2 | **No fine-grained revocation** — only whole-token revocation exists. Can't withdraw a single MCP scope from a still-valid token. | Medium | Open |
| G3 | **No structured audit pipeline** — `formatDecision` produces a string for local logs only. No event schema, no pluggable sink, no broker-side aggregation. Critical for incident response. | High | Closed (`9b62607`) |
| G4 | **Hook-based integrations don't get the full `MCPTool`** — Claude Code's `PreToolUse` and similar pass tool name + args, not the definition. So TOFU and annotation primitives can't run from a hook context. Library or harness must re-fetch the tool def. | Medium | Open |
| G5 | **No JWKS endpoint / broker public key distribution** — `verifyMCPCredential` works in principle but the receiving server has no built-in way to fetch the broker's public key. Currently bring-your-own-distribution. | High | Closed (`af608b8`) — CLI-served JWKS; HTTP endpoint via LeaderServer deferred |
| G6 | **No shared TOFU registry for ephemeral / containerized agents** — `FileSchemaPinRegistry` writes to disk (lost on container restart); `MemorySchemaPinRegistry` loses state every run. Many ephemeral agents need a shared registry to detect rug-pulls reliably. | High | Closed (client) (`(this commit)`) — `HttpSchemaPinRegistry` ships against a documented HTTP contract; agent-iam doesn't ship the server (operator chooses Postgres/Redis/S3/etc.) |
| G7 | **No async-approval contract for `ask` decisions** — the `Decision.kind === "ask"` branch returns a reason; the harness has to invent its own queue/UI. No standard `AsyncApprovalProvider` interface. | Medium | Open |
| G8 | **No `Broker.issueForMCPServer()` integration** — `issueMCPCredential` is a pure function callers wire themselves. Means key management, audit, and CLI ergonomics are caller-side. | Medium | Closed (`af608b8`) |

Filling order (post-W1 follow-ups, in priority):

1. **G1, G3** — broker config plumbing for `mcpDenyPolicy` and structured
   audit events. Without these, real deployments can't roll out policy or
   investigate denials. Both are small; ship together.
2. **G5, G8** — broker signing-key management and `Broker.issueForMCPServer()`
   wrapping. Prerequisite for anyone actually using the RFC 8707 work.
3. **G6** — shared/broker-hosted pin registry. Required for non-trivial
   production deployments. Larger; depends on existing distributed-mode HTTP
   infrastructure.
4. **G2, G4, G7** — fine-grained revocation, hook-payload helpers, async
   approval contract. Useful but second-order; can wait for real demand.

Track each gap as it lands by appending its closing commit hash to the row.

### Motivation

Agents that use MCP servers can invoke arbitrary tools exposed by those servers.
Today agent-iam has no vocabulary for restricting which MCP tools an agent may
call. The primary threat model is **prompt injection / jailbreak of the LLM**:
the harness around the model is trusted, but the model's tool-call decisions
are not.

The April 2026 research surfaced two threats not in the original framing:

- **Tool rug-pulls** (CVE-2025-54136 and the broader pattern). Servers ship
  benign tools at first connection then silently swap to malicious payloads.
  The MCP spec's `tools/list_changed` notification is optional and doesn't
  mandate re-consent. Defenders converged on SHA-256 pinning of canonical tool
  definitions (mcp-scan, mcp-guardian).
- **Token replay across servers.** OAuth tokens without an `aud` claim can be
  replayed by any MCP server that receives them. The MCP authorization spec
  (2025-11-25) **MUSTs** RFC 8707 audience binding. Without it, a compromised
  filesystem server can reuse our credentials against any other resource.

W1 ships a coherent defense: signed allow/deny policy + tool-schema TOFU pinning
+ optional server identity verification + RFC 8707 audience binding on
broker-issued credentials destined for MCP servers.

### Design summary

#### Enforcement model

- **Enforcement seam: the agent harness**, not agent-iam, not the MCP server.
  Agent-iam distributes signed policy and verification helpers; the harness
  enforces inline before dispatching tool calls. Matches Claude Code's own
  permission model.
- **No MCP proxy in v1.** Out-of-process gating is the wrong layer for a
  credential broker. Revisit if we ever serve untrusted agent code.

#### Allow / deny scopes

- **New scope namespace:** `mcp:<server>:<tool>` (3 segments, matching the
  existing `provider:resource:action` grammar). Tool name is the leaf —
  MCP tools are atomic by protocol design, no `:invoke` suffix needed.
- **No `denyScopes` field on tokens in v1.** Per-token deny breaks pure
  attenuation and the realistic use cases ("grant `*` minus shell") are
  better served by org-wide policy. Use enumerated allow lists per token.
- **Broker-level deny policy** (passed as `CheckMCPCallOptions.brokerDenyPolicy`
  from the harness) — the SCP analog. Cannot be widened by any token.
  Clean separation: per-token allow says "what this agent may do," broker
  deny says "what nobody may ever do." (v1 ships the API surface; storing
  the policy in `Broker` config and a CLI to manage it is follow-up work.)
- **Three-state `Decision`** — `allow | deny | ask`, matching Claude Code's
  `deny → ask → allow` precedence (the de facto industry standard).
  `ask` lets harnesses surface human-in-the-loop prompts. v1 broker doesn't
  emit tokens that produce `ask`, but defining it now is free.
- **Default-deny once opted in.** Tokens with no `mcp:*` scopes get all MCP
  calls denied. Migration is manual: re-mint tokens with `mcp:*` (the
  canonical "all MCP" pattern — note `mcp:*:*` does *not* work, see
  scope-namespace gotcha in `docs/mcp-policy.md`).

#### Tool-schema TOFU (rug-pull defense)

Mirrors the existing TOFU pattern in `src/identity/standalone-verifier.ts` —
verifier records `(identifier, hash-of-canonical-data)` on first contact,
compares on subsequent contacts.

| Identity TOFU (today) | MCP tool-schema TOFU (new) |
|---|---|
| identifier = `did:key:...` | identifier = `(server-name, tool-name)` |
| canonical data = public key | canonical data = full `Tool` object |
| canonicalization = `src/identity/jcs.ts` | canonicalization = same `jcs.ts` |
| storage = remote service's choice | storage = harness's choice |
| trust progression = authority endorsement | trust progression = MCP Registry / sigstore endorsement |

On schema mismatch the helper returns `ask` (or `deny` in strict mode). The
storage layer is harness-owned by default; broker can offer a shared registry
for multi-agent setups but is not the source of truth.

#### Server identity (optional, opt-in)

MCP servers are **not principals in agent-iam's identity graph** — they're
external services we need to recognize. The right abstraction is the
trusted-party pattern (mirror of `trustedAuthorities` in
`standalone-verifier.ts:79-80`), not a new `IdentityProvider`.

Three stackable verification paths, each optional:

1. **Hash-pin** — `sha256` of the server tarball/binary; cheapest.
2. **Registry-anchored** — fetch `server.json` from the official MCP Registry
   (Sep 2025), validate against vendored schema with `ajv`, compare canonical
   URI.
3. **Sigstore-attested** — verify provenance bundle with `@sigstore/verify`,
   check builder identity matches expected publisher.

Tokens carry `mcpServerBindings: Record<string, MCPServerBinding>`. Default
is empty = trust local config (current behavior). Hardened deployments
populate the field.

#### RFC 8707 audience binding

When `Broker.issueFromProvider()` produces a credential destined for an MCP
server, the resulting token includes `aud = <canonical server URI>`. Resource
servers reject tokens whose `aud` doesn't match. Three attacks this prevents:

1. **Token-passing / confused deputy** — server A can't replay a token at
   server B.
2. **Compromised-server exfil** — credentials leaked from a compromised MCP
   server are useless against other servers.
3. **Cross-tenant token reuse** — multi-tenant brokers can't accidentally
   issue cross-tenant-replayable tokens.

Implementation: `jose.SignJWT().setAudience(uri)` on issuance,
`jose.jwtVerify(t, k, { audience })` on verification. Cost: ~one line each.
The canonical URI comes from the server-identity binding above — these
features compose into one defense.

#### Annotation-aware policy primitives

Tool annotations (`destructiveHint`, `openWorldHint`, `readOnlyHint`,
`idempotentHint`) are **advisory only** — untrusted servers can lie. But they
work as policy *inputs* for trusted servers. v1 ships:

- `requireApprovalIf("destructiveHint")` — return `ask` for destructive tools.
- `denyIf("openWorldHint")` — block open-world tools entirely (lethal-trifecta
  primitive).

Session-state policy ("block open-world after sensitive read") is v2 — it
introduces session state we don't have today.

### API surface (planned)

```ts
// src/types.ts
interface MCPServerBinding {
  canonicalURI: string;            // for RFC 8707 aud claim
  registry?: string;               // MCP Registry name, e.g. "io.github.org/server"
  sha256?: string;                 // tarball/binary hash
  sigstoreBundle?: string;         // base64 sigstore bundle
}

interface AgentToken {
  // ...existing fields
  mcpServerBindings?: Record<string, MCPServerBinding>;
}

// src/mcp/policy.ts (new)
type Decision =
  | { kind: "allow"; matchedScope: string }
  | { kind: "deny"; reason: string; matchedScope?: string }
  | { kind: "ask"; reason: string };

function checkMCPCall(
  token: AgentToken,
  server: string,
  tool: string,
  args?: unknown,                  // unused in v1; reserved for v2
  context?: { brokerDenyPolicy?: string[]; toolAnnotations?: ToolAnnotations },
): Decision;

// src/mcp/schema-pin.ts (new)
function canonicalToolHash(tool: Tool): string;

interface SchemaPinRegistry {
  get(server: string, tool: string): Promise<string | undefined>;
  set(server: string, tool: string, hash: string): Promise<void>;
}

class FileSchemaPinRegistry implements SchemaPinRegistry {
  constructor(dir?: string);       // defaults to ~/.agent-credentials/mcp-pins/
}

function verifyToolSchema(
  server: string,
  tool: Tool,
  registry: SchemaPinRegistry,
): Promise<{ valid: boolean; drift?: { knownHash: string; currentHash: string } }>;

// src/mcp/server-trust.ts (new)
function verifyServerIdentity(
  binding: MCPServerBinding,
  observedManifest: { uri: string; sha256?: string; bundle?: string },
): Promise<{ valid: boolean; error?: string }>;
```

### Type / code changes (as shipped)

- `src/token.ts:36-57` — `scopeMatches` fixed for the mid-wildcard
  short-circuit bug discovered in post-W1 review (`*` is now a
  single-segment wildcard with segment-count enforcement).
- `src/mcp/types.ts` (new) — local `MCPTool`, `MCPToolAnnotations` (we
  defer adding `@modelcontextprotocol/sdk` until we depend on more than
  the type surface; swap is a one-import change).
- `src/mcp/policy.ts` (new) — `checkMCPCall()`, three-state `Decision`,
  default-deny semantics, broker-deny override (broker policy passed via
  `CheckMCPCallOptions.brokerDenyPolicy` rather than stored in `Broker`
  config).
- `src/mcp/credential.ts` (new) — `issueMCPCredential` /
  `verifyMCPCredential` pure functions for RFC 8707 audience-bound JWTs.
  `Broker.issueForMCPServer()` integration is deferred follow-up work.
- `src/mcp/schema-pin.ts` (new) — `canonicalToolHash()` (uses existing
  `src/identity/jcs.ts`), `SchemaPinRegistry` interface,
  `FileSchemaPinRegistry`, `MemorySchemaPinRegistry`, `verifyToolSchema()`.
- `src/mcp/server-trust.ts` (new) — `MCPServerBinding`,
  `verifyServerIdentity()`, three optional verification paths
  (hash-pin, registry-anchored via vendored minimal `server-schema.ts`,
  and an injected `SigstoreVerifier` interface).
- `src/mcp/annotations.ts` (new) — `requireApprovalIf`, `denyIf` primitives.
- `src/mcp/index.ts` (new) — public exports.
- `src/cli.ts` — `agent-iam mcp test <server> <tool> --token <t> [--broker-deny <pat...>]`,
  `agent-iam mcp pin-list [--server <name>]`,
  `agent-iam mcp pin-clear <server> [tool]`.
- `examples/mcp-harness/` — reference dispatch wrapper, demo, README.
- `docs/mcp-policy.md` — integrator contract.

Vendoring a dated official `server.json` schema for stronger
conformance is deferred — `src/mcp/server-schema.ts` ships a permissive
structural check that's sufficient for v1.
- Tests: `src/mcp/*.test.ts` per module; `src/token.test.ts` extensions for
  picomatch parity.
- `docs/mcp-policy.md` — contract for harness integrators, server-identity
  caveat, migration path.
- `examples/mcp-harness/` — minimal reference harness wiring
  `checkMCPCall` + schema TOFU + RFC 8707 verification.

### Libraries (decided)

New runtime dependencies, all MIT or Apache-2.0, all from authoritative sources:

| Library | Use | Source |
|---|---|---|
| `@modelcontextprotocol/sdk` (v1.x) | `Tool`, `ToolAnnotations`, JSON-RPC types — types-only subpath import; transports excluded | Anthropic / MCP org |
| `picomatch` | Replace hand-rolled regex matcher in `src/token.ts` | micromatch org |
| `jose` | JWT issue/verify with `aud` (RFC 8707) | panva |
| `oauth4webapi` | RFC 9728 PRM discovery (lazy — only if we integrate external authz servers) | panva |
| `@sigstore/verify` | Verify provenance bundles for server identity | Sigstore community |
| `ajv` (with `Ajv2020`) + `ajv-formats` | Validate `server.json` against vendored 2020-12 schema | ajv-validator |

**Skipped (have working in-tree equivalents):**

- `canonicalize` (RFC 8785 JCS) — `src/identity/jcs.ts` already implements
  the ASCII-safe subset we need. Validate against published RFC 8785 test
  vectors before relying further.
- `openid-client` — too much surface; `oauth4webapi` covers what we need.

**Build ourselves:**

- `server.json` schema loader (~30 LOC, vendor + ajv).
- Tool-schema TOFU lockfile (~150 LOC; closest prior art `mcptrust` is Go and
  pins names not definitions, leaving the rug-pull window open).

### Build order

1. **Tool-schema TOFU** (`src/mcp/schema-pin.ts`) — highest leverage; reuses
   `jcs.ts`; storage layer is well-understood from existing identity TOFU.
2. **Scope namespace + `checkMCPCall`** (`src/mcp/policy.ts`) — wire up
   default-deny, broker-deny override, three-state Decision.
3. **RFC 8707 audience binding** — adds `jose`; minimal `Broker.issueForMCPServer`.
4. **Annotation primitives** (`src/mcp/annotations.ts`) — small surface.
5. **Optional server-identity bindings** (`src/mcp/server-trust.ts`) — adds
   `@sigstore/verify`, `ajv`, vendored schema.
6. **CLI surface, reference harness, docs.**

**Deferred: picomatch swap.** Earlier sketch listed this as "step 0, fixes a
latent bug class." On inspection the current matcher is sound: `scopeMatches`
in `src/token.ts:37-57` is pure segment-based string ops with no regex, and
`resourceMatches` at `src/token.ts:60-71` properly escapes metachars before
glob substitution. The current `resourceMatches` also lets `*` span `/`
(see `token.test.ts:80`); picomatch's default semantics would break that.
Revisit only if a real need emerges (brace expansion, negation patterns).

### Open questions

- **Schema migration timing.** Tokens without `mcp:*` scopes are now
  default-denied for MCP calls. v1 documents this as a manual re-mint
  rather than shipping an automated helper. Worth revisiting if real
  deployments accumulate stale tokens.
- **Sigstore trust roots.** High-level `sigstore` package fetches TUF roots
  over the network; offline path uses `@sigstore/verify` with pre-fetched
  root. Pick before coding the server-trust module.
- **`server.json` schema versioning.** Pin to a single dated snapshot or
  support multiple? V1: pin one, document upgrade path.
- **Cross-server policy** (e.g., "this agent may use server A *or* server B
  in a session, not both") — not handled anywhere in the ecosystem.
  Genuine design freedom but defer to v2.
- **`tools/list_changed` re-consent.** The MCP spec doesn't mandate
  re-prompting on tool list changes. Our schema TOFU detects the drift;
  what should the harness do? Document `ask` as the recommended response.

### Out of scope (v1)

- MCP proxy / out-of-process gate.
- Per-token `denyScopes` (use broker-level deny + enumerated allow instead).
- Argument-level policy (extension point reserved in `checkMCPCall` signature).
- Session-state policy / lethal-trifecta tripwires.
- Cross-server combination policy.
- SEP-990 Cross App Access integration (overlaps with W3).
- Async task lifecycle / elicitation handling.
- MCP server-side token verification (servers can already use
  `standalone-verifier.ts`; not required).

---

## Workstream 2 — Just-In-Time Elevation

**Status:** Proposed
**Owner:** _unassigned_
**Depends on:** none
**Sequence:** ship second

### Motivation

Agents should default to least privilege but occasionally need a transient
expansion (e.g., to perform a write after holding read-only by default). Today
the only way to get more scope is to mint a new root token, which is heavy and
defeats the audit chain. We want **transient elevation** — short-lived, audited,
auto-expiring scope expansion.

We explicitly **rejected runtime "tiers" as a first-class concept** because they
calcify, hide actual grants, and devolve into role explosion (see AWS managed
policies as the cautionary tale). What's valuable underneath the tier idea is
just-in-time elevation; that's what this workstream delivers.

### Design summary

- **No runtime tier abstraction.** Tokens carry scopes, not tier references.
- **Issuance-time scope bundles** as pure CLI/UX sugar: `agent-iam issue
  --template reader` expands a named scope list at mint time. The token is
  unchanged. Bundles live in broker config.
- **Step-up via `Broker.elevate()`.** Inspired by Azure PIM. Issues a new
  short-lived child token with additional scopes, gated by a meta-scope on
  the parent (`system:scope:elevate:<scope-pattern>`). Auto-expires; cannot
  itself be re-elevated beyond `maxExpiresAt`.
- **Justification field** captured on the elevated token for audit.

### API surface (planned)

```ts
// src/types.ts
interface ElevationRequest {
  parentToken: AgentToken;
  additionalScopes: string[];
  ttlMinutes: number;        // bounded by broker policy
  justification: string;     // free-text, audit only
}

interface AgentToken {
  // ...existing fields
  elevation?: {
    parentTokenId: string;
    justification: string;
    grantedAt: string;       // ISO 8601
  };
}

// src/broker.ts
class Broker {
  elevate(req: ElevationRequest): AgentToken;
}
```

### Type / code changes

- `src/types.ts` — add `ElevationRequest`, `elevation?` field on `AgentToken`.
- `src/broker.ts` — `elevate()` method. Validates: parent holds
  `system:scope:elevate:<each-additional-scope>`; ttlMinutes ≤ broker max;
  resulting expiry ≤ parent's `maxExpiresAt`.
- `src/cli.ts` — `agent-iam elevate --scopes ... --ttl ... --reason ...`.
- Optional: `src/templates/` — scope bundle definitions consumed by CLI only.
- Tests: `src/broker.test.ts` — elevation success, denial without
  meta-scope, auto-expiry, no double-elevation past `maxExpiresAt`.

### Open questions

- **Meta-scope shape.** `system:scope:elevate:<scope>` per-scope, or a
  single `system:elevation:request` plus a separate allowlist field?
  Per-scope keeps the model uniform but inflates scope counts.
- **Approval flow.** v1 is self-service (parent token authorizes its own
  elevation). Do we ever need a human-in-the-loop approver? Probably yes
  eventually, but defer.
- **Revocation.** Elevations should appear in revocation lists distinctly
  from delegations so emergency revoke-all-elevations is one operation.

### Out of scope

- Runtime tier abstraction (rejected as antipattern).
- Approval workflows / multi-party elevation (defer).
- Persistent "elevated" mode — elevation is always transient.

---

## Workstream 3 — Human On-Behalf-Of (OBO)

**Status:** In Design (needs separate design doc before code)
**Owner:** _unassigned_
**Depends on:** none, but largest scope of the three
**Sequence:** ship last

### Motivation

Agents increasingly act on behalf of human users (read the user's email,
commit to the user's repos). Agent-iam currently only models agent identities
backed by Ed25519 keypairs or platform UUIDs — it has no notion of a human
principal, no consent mechanism, and no audit chain that says "agent A acted
as user U at time T because of consent C."

This is the well-trodden **OAuth on-behalf-of** pattern, not agent-to-agent
impersonation. The references are Microsoft OBO flow, RFC 8693 Token Exchange,
and Google Workspace domain-wide delegation.

The central risk is the **confused deputy problem** — the agent must not be
trickable into using its OBO grant for things the user didn't actually consent
to. Consent must be explicit, scoped, and time-bounded.

### Design summary

- **New identity provider: `FederatedIdentityProvider`.** Trusts an external
  IdP (OIDC primarily, optionally SAML). Users are represented as
  `user:<idp>:<sub>`. agent-iam does not authenticate users itself —
  it verifies signed assertions from the IdP.
- **New primitive: consent grants.** A signed record where a user authorizes
  `agent A` to act as them for `scopes S` until `expiresAt`. Stored
  separately from tokens so they can be revoked independently.
- **Token exchange (RFC 8693-shaped):** `Broker.exchangeForUserToken()`
  takes an agent token + a user OIDC assertion + a consent grant and mints
  a token with `persistentIdentity = user`, `act = [agent]`,
  `scopes ⊆ (consent ∩ agent's scopes)`. Triple intersection.
- **Defer consent UX to the IdP.** Reinventing consent screens is a tarpit.
  We accept the OIDC `id_token` and the IdP's consent decision as canonical.
- **Audit chain.** Every actor in the `act` chain is recorded. Revocation
  cascades: revoke the consent grant → all derived tokens invalid.

### API surface (sketch only — full design doc needed)

```ts
// src/identity/federated-provider.ts (new)
class FederatedIdentityProvider implements IdentityProvider {
  verify(assertion: OIDCAssertion): UserPrincipal;
}

// src/types.ts
interface ConsentGrant {
  grantId: string;
  userId: string;             // user:<idp>:<sub>
  agentId: string;            // the agent authorized to act as user
  scopes: string[];
  expiresAt: string;
  signature: string;          // signed by user's IdP or by broker after IdP verify
}

interface AgentToken {
  // ...existing fields
  act?: string[];             // chain of actors; original principal first
}

// src/broker.ts
class Broker {
  exchangeForUserToken(req: {
    agentToken: AgentToken;
    userAssertion: OIDCAssertion;
    consentGrantId: string;
    requestedScopes: string[];
  }): AgentToken;
}
```

### Open questions (the doc must answer)

- **Where does consent live?** Broker-stored signed records, or always
  re-derived from the IdP's `id_token` claims? Probably broker-stored for
  scope flexibility, IdP-anchored for principal auth.
- **OIDC IdP integration.** Which IdPs do we support out of the box?
  Generic OIDC discovery is the right answer; ship with examples for
  Google, GitHub, Okta.
- **Scope mapping.** A user's actual permissions in downstream systems
  (Drive files they can see) are not knowable to agent-iam. We rely on
  the downstream provider to enforce. Document this clearly.
- **Revocation propagation.** When a consent grant is revoked, derived
  tokens must stop working. Ties into the existing revocation list system
  in `src/distributed/`.
- **Multi-actor chains.** Can agent A (acting as user U) further delegate
  to agent B? If so, B's `act` chain is `[U, A]`. Need to formalize this.

### Out of scope

- agent-iam acting as a primary user authenticator (we federate, not
  authenticate humans).
- Building consent UI in agent-iam.
- Cross-IdP identity linking (one user across multiple IdPs).

### Required next step

Spin out `docs/human-obo-design.md` with:

1. Threat model (confused deputy, token theft, IdP compromise).
2. Detailed consent grant lifecycle (issue, store, present, revoke).
3. Concrete OIDC integration shape.
4. Audit format spec.
5. Migration plan for existing keypair-only deployments.

---

## Explicitly Out of Scope

These were considered and rejected — recorded so we don't relitigate.

- **Runtime access tiers.** Named tiers as a first-class token field.
  Rejected as antipattern: calcifies, hides grants, role-explosion-prone.
  Replaced by issuance-time templates (CLI sugar) + JIT elevation.
- **Agent-iam-hosted MCP proxy.** Wrong layer for a credential broker.
  Revisit only if we need org-wide gating across untrusted agents.
- **Agent-to-agent impersonation.** The original "act as another agent"
  framing. Real need was human OBO — see Workstream 3.
- **Argument-level MCP policy.** Tool name gating only in v1; the `args`
  parameter is reserved on `checkMCPCall` for v2.
- **Per-token MCP `denyScopes`.** Earlier sketch had this; replaced by
  broker-level deny policy + enumerated allow lists. Revisit only if a real
  use case appears.
- **MCP session-state policy** (lethal-trifecta tripwires). v2; requires
  session state we don't have.
- **Broker-hosted human authentication.** We federate to OIDC IdPs, never
  authenticate users directly.

---

## Sequencing

```
W1 (MCP)  ─────────►  ship
                          │
                          ▼
W2 (JIT elevation)  ─────► ship
                                │
                                ▼
W3 (Human OBO)  design doc ─► ship
```

**W1 first** because it's the most concrete user need and its decisions set
patterns the other workstreams reuse: the picomatch swap, the scope
vocabulary, RFC 8707 audience binding (referenced by W3), and the schema-TOFU
pattern (mirroring identity TOFU).

**W2 second** because elevation reuses the scope vocabulary expanded in W1
and is largely self-contained.

**W3 last** because it introduces the most new surface area (federated
identity, consent grants, token exchange) and benefits from the lessons
of W1 and W2 about how the audit chain and revocation model evolve.

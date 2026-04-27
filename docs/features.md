# Agent IAM — Feature Roadmap

**Status:** Active
**Last Updated:** 2026-04-27

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

**Status:** Proposed
**Owner:** _unassigned_
**Depends on:** none
**Sequence:** ship first

### Motivation

Agents that use MCP servers can invoke arbitrary tools exposed by those servers.
Today agent-iam has no vocabulary for restricting which MCP tools an agent may
call. The threat model is **prompt injection / jailbreak of the LLM**: the
harness around the model is trusted, but the model's tool-call decisions are
not. We need a signed, attenuatable policy that the harness can consult before
dispatching each tool call.

### Design summary

- **Enforcement seam: the agent harness, not agent-iam, not the MCP server.**
  Agent-iam distributes signed policy; the harness enforces inline before
  dispatching tool calls. This matches how Claude Code's own permission system
  works.
- **No MCP proxy.** Building protocol-aware infrastructure inside the broker
  is the wrong layer. Defer until/unless we have multi-tenant / untrusted-agent
  scenarios.
- **New scope namespace:** `mcp:<server>:<tool>:invoke`. Reuses the existing
  scope + glob-constraint machinery, so allow-listing comes for free.
- **New `denyScopes` field on `AgentToken`.** Deny always wins; the deny set
  grows monotonically down the delegation chain (union, not intersection).
  This deliberately breaks pure attenuation — we accept the tradeoff because
  org-wide "never allow shell tools" requires it.
- **Reference helper:** `checkMCPCall(token, server, tool, args) → Decision`,
  a pure function harnesses call before dispatching.

### API surface (planned)

```ts
// src/types.ts
interface AgentToken {
  // ...existing fields
  denyScopes?: string[];  // NEW: deny patterns, win over allow
}

// src/mcp/policy.ts (new)
type Decision =
  | { allow: true }
  | { allow: false; reason: string };

function checkMCPCall(
  token: AgentToken,
  server: string,
  tool: string,
  args?: unknown,
): Decision;
```

### Type / code changes

- `src/types.ts` — add `denyScopes?: string[]` to `AgentToken`.
- `src/token.ts` — `checkPermission()` evaluates deny-scopes first; deny
  matches return `false` regardless of allow matches. `mergeScopes()` /
  delegation logic unions deny lists, intersects allow lists.
- `src/mcp/policy.ts` (new) — `checkMCPCall()` helper.
- `src/mcp/index.ts` (new) — public exports.
- `src/cli.ts` — `agent-iam mcp allow|deny <pattern>` for ergonomic policy edit.
- Tests: `src/mcp/policy.test.ts`, plus extensions to `src/token.test.ts` for
  deny-precedence and deny-union-on-delegation.

### Open questions

- **Wildcard semantics on deny.** Does `mcp:*:write:*` match a tool literally
  named `write` only, or any tool whose name contains `write`? Lean toward
  strict segment matching (current scope behavior).
- **Server identity.** How does the harness know which "server" string to
  pass to `checkMCPCall`? Probably the MCP server name from the harness's
  config, but we should document this contract clearly.
- **Tool argument inspection.** Should `args` factor into decisions
  (e.g., deny `filesystem:read` for paths outside `/workspace`)? V2;
  start with name-based gating only.
- **Reference harness.** Ship one as an example, or just document the
  contract? Lean toward a minimal example in `examples/mcp-harness/`.

### Out of scope

- MCP proxy / out-of-process gate.
- Argument-level policy (defer to v2).
- MCP server-side token verification (servers can already use
  `standalone-verifier.ts` if they want; not required).

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
- **Argument-level MCP policy.** Tool name gating only in v1.
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

**W1 first** because it's the smallest, has the most concrete user need,
and its `denyScopes` decision sets a precedent the other workstreams reuse.

**W2 second** because elevation reuses the scope vocabulary expanded in W1
and is largely self-contained.

**W3 last** because it introduces the most new surface area (federated
identity, consent grants, token exchange) and benefits from the lessons
of W1 and W2 about how the audit chain and revocation model evolve.

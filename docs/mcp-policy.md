# MCP Policy Integration Guide

This is the contract for integrating agent-iam's MCP access-control
primitives into an agent harness. It covers what to call, in what order,
and what to do with the results.

For the design rationale and threat model, see W1 in `docs/features.md`.

---

## TL;DR

An agent harness — the trusted code around an LLM that dispatches tool
calls — is responsible for **enforcement**. agent-iam ships **policy** as
signed scopes plus a small set of pure-function helpers. The harness
calls these helpers before every MCP tool invocation.

```ts
import {
  checkMCPCall,
  verifyToolSchema,
  requireApprovalIf,
  denyIf,
  formatDecision,
  FileSchemaPinRegistry,
} from "agent-iam";

const registry = new FileSchemaPinRegistry();

async function dispatchToolCall(
  token: AgentToken,
  serverName: string,
  toolDef: MCPTool,
  args: unknown,
) {
  // 1. Schema TOFU: detect rug-pulls.
  const pinResult = await verifyToolSchema(serverName, toolDef, registry);
  if (!pinResult.valid) {
    return askUser(`Tool schema for ${serverName}/${toolDef.name} has changed.`);
  }

  // 2. Allow/deny scope check.
  let decision = checkMCPCall(token, serverName, toolDef.name, args, {
    brokerDenyPolicy: BROKER_DENY,
  });

  // 3. Annotation-aware escalation (only for trusted servers).
  if (TRUSTED_SERVERS.has(serverName)) {
    decision = requireApprovalIf(decision, toolDef.annotations, "destructiveHint");
    decision = denyIf(decision, toolDef.annotations, "openWorldHint");
  }

  // 4. Act on the decision.
  log.info(`tool=${serverName}/${toolDef.name} ${formatDecision(decision)}`);
  if (decision.kind === "deny") throw new PermissionError(decision.reason);
  if (decision.kind === "ask") await promptHuman(decision.reason);
  // decision.kind === "allow" — proceed
  return invokeTool(serverName, toolDef.name, args);
}
```

A complete runnable example lives in `examples/mcp-harness/`.

---

## The enforcement model

agent-iam takes a clear position on where enforcement lives:

- **Trusted: the agent harness.** Code you wrote, deployed, control.
- **Untrusted: the LLM's tool-call decisions.** Prompt injection, jailbreaks,
  hallucinated arguments — the model is a semi-adversarial component
  *inside* the trust boundary.

Therefore enforcement happens **inline in the harness's tool dispatch
layer**, before the call goes out. agent-iam does not ship an MCP proxy or
out-of-process gate — the harness has to call *something*, and an in-process
check is just as strong as a network hop.

If you ever run *untrusted* agent code (third-party agents, multi-tenant),
you'll need an out-of-process gate. That's not a v1 problem.

---

## Scope namespace

MCP scopes use the existing `provider:resource:action` grammar:

| Pattern | Matches |
|---|---|
| `mcp:filesystem:read_file` | exactly that one tool |
| `mcp:filesystem:read_*` | tool names beginning with `read_` on `filesystem` (segment match) |
| `mcp:filesystem:*` | any tool on `filesystem` (recursive prefix) |
| `mcp:*` | any MCP tool on any server (recursive prefix — canonical "all MCP") |
| `*` | any scope, MCP or otherwise |

**Gotcha:** `mcp:*:*` does **not** behave as you'd expect. The matcher's
trailing-`:*` short-circuit treats it as a prefix match for literal
`mcp:*:`, which no real scope produces. Use `mcp:*` instead.

### Default-deny

Tokens with no matching `mcp:*` scope have all MCP calls denied. To opt a
token in to "any MCP tool":

```bash
agent-iam token create-root --scopes 'mcp:*'
```

For backwards compatibility with tokens issued before W1, mint a new token
with `mcp:*` (effectively the migration step).

---

## The four call sites

In dispatch order:

### 1. `verifyToolSchema(server, tool, registry, options?)` — TOFU pinning

Detects tool rug-pulls (CVE-2025-54136 class). On first contact pins the
canonical SHA-256 of the tool definition; on subsequent contacts compares.

- **Default:** TOFU on (`{ tofu: true }`). Auto-pin on first sight, accept.
- **Strict:** `{ tofu: false }`. Reject any tool not already pinned.
- **Drift:** returns `{ valid: false, drift: { knownHash, currentHash } }`.
  Recommended response is `ask` (treat as suspicious but human-resolvable).

Storage default: `~/.agent-credentials/mcp-pins/{encodeURIComponent(server)}.json`.
Pass a different directory to `new FileSchemaPinRegistry(dir)` for tests.
For tests / ephemeral processes use `MemorySchemaPinRegistry`.

For **multi-replica or containerized agents** that can't rely on a local
file (a container restart loses the pin state, defeating rug-pull
detection), use `HttpSchemaPinRegistry` against a registry server you
operate. agent-iam ships the *client* but not the server — pin storage is
a database concern (Postgres, Redis, S3, k8s ConfigMap, etc.) and
operators have strong opinions. Implement the documented contract:

```
GET    /pins                       → 200 [{server,tool,hash,pinnedAt}, ...]
GET    /pins?server=NAME           → 200 (filtered)
GET    /pins/:server/:tool         → 200 {hash, pinnedAt} | 404
PUT    /pins/:server/:tool         → 200 (body {hash}) | 409 conflict
DELETE /pins/:server/:tool         → 200 | 404 (idempotent)
```

`server` and `tool` path components are URL-encoded by the client.
Authentication is a bearer token sent in `Authorization`. The client
sets `redirect: "error"` to refuse 3xx responses (defense against a
compromised registry redirecting bearer tokens to an attacker URL).
Body parsing is bounded by the same timeout as the request.

**409 Conflict on PUT** indicates that a different hash is already pinned
for the same `(server, tool)` pair. The client surfaces this as a typed
`PinConflictError` (carrying `server`, `tool`, and the response body)
so callers can distinguish "concurrent first-pin race" from "actual
schema drift" without parsing error strings. Server implementations
should return 409 only on hash conflict; idempotent re-pin of the same
hash should return 200.

Network failures and non-2xx responses (other than `get`'s 404 and the
PUT 409 above) propagate as generic thrown errors — the TOFU model
assumes registry availability.

### 2. `checkMCPCall(token, server, tool, args?, options?)` — scope check

Pure function. Three-state `Decision` (`allow | deny | ask`).
Evaluation order:

1. **Broker-level deny policy** (`options.brokerDenyPolicy`) wins over
   everything. The SCP analog — org admin says "no shell tools, period."
2. **Token allow list.** First matching scope grants.
3. **Default deny.**

The `args` parameter is reserved for v2 argument-level policy. Pass them
now to forward-compat the call site.

### 3. Annotation primitives — `requireApprovalIf` / `denyIf`

Compose with the decision from step 2. Both return the input unchanged
unless the named hint is `true` on the server-supplied annotations.

| Function | Effect when hint is true |
|---|---|
| `requireApprovalIf(d, ann, hint)` | `allow → ask`; `ask`/`deny` unchanged |
| `denyIf(d, ann, hint)` | `allow|ask → deny`; `deny` unchanged |

**Annotations are advisory only.** Per the official MCP blog (March 2026),
untrusted servers can lie about them. Apply these only to servers you
trust to be honest.

Decision severity is monotonic (`allow < ask < deny`). Transformers can
escalate but never relax — a `deny` from the policy layer is sticky.

### 4. `verifyServerIdentity(binding, observed, options?)` — optional

Run **once per server, at connection time** (not per tool call). Three
stackable opt-in checks:

In evaluation order:

- **URI match** (always-on) — observed URI must match `binding.canonicalURI`.
  Mismatch short-circuits all other checks.
- **Registry-anchored** — observed `server.json` validates and its `name`
  matches `binding.registry`.
- **Hash-pin** — observed `artifactSha256` must match `binding.sha256`
  (length-checked before the timing-safe compare).
- **Sigstore** — provenance bundle verified by an injected
  `SigstoreVerifier`. Wire `@sigstore/verify` yourself.

Default behavior with an empty binding is "trust local config" —
unchanged from agent-iam's pre-W1 behavior.

---

## RFC 8707: audience-bound credentials

When an agent calls an MCP server that uses OAuth-style auth, the broker
issues a per-server JWT with `aud = <canonical server URI>`. This
prevents token replay across MCP servers — the MCP authorization spec
**MUSTs** this.

The broker manages its own EdDSA signing keypair and exposes it via
`Broker.issueForMCPServer()` (recommended) or the lower-level pure
`issueMCPCredential` for callers who hold the key themselves.

```ts
import { Broker, MemoryAuditSink } from "agent-iam";

const broker = new Broker();
const auditSink = new MemoryAuditSink(); // or FileAuditSink, etc.

// Broker side:
const cred = await broker.issueForMCPServer({
  agentToken: token,
  serverURI: "https://filesystem.example.com",
  scopes: ["mcp:filesystem:read_file"],
  ttlSeconds: 300,
  auditSink,                                // optional: emits mcp.credential.issued
});

// Server side:
import { verifyMCPCredential } from "agent-iam";
const v = await verifyMCPCredential(cred.jwt, {
  publicKey: brokerPublicKeyPem,            // see "Distributing the public key" below
  expectedAudience: "https://filesystem.example.com",
});
if (!v.valid) reject(v.error);
```

### Distributing the public key

MCP servers verifying credentials need the broker's public key. agent-iam
publishes it as a JWKS document (RFC 7517) via the CLI:

```
agent-iam mcp jwks
```

Mount that output at any URL (e.g. `https://broker.example.com/.well-known/jwks.json`)
and have your MCP servers fetch it. The keypair lives at
`{configDir}/mcp-signing.{key,pub}` (private mode 0o600), generated lazily
on first use.

Key rotation is not yet automated — replacing the keypair is a manual
file swap that invalidates outstanding credentials.

---

## What's *not* in v1

- **Per-token deny scopes.** Use `brokerDenyPolicy` + enumerated allow lists.
- **Argument-level policy.** Hook seam reserved (`args` parameter); v2.
- **Session-state policy** (lethal-trifecta tripwires). v2.
- **Cross-server combination policy** ("A or B in a session, not both").
- **MCP proxy / out-of-process gate.** Out of scope for the broker.
- **Async task / elicitation lifecycle.**
- **Automated signing-key rotation** and JWKS endpoint served from the
  leader server. Today rotation is a manual file swap and JWKS is served
  via `agent-iam mcp jwks` (mounted manually wherever).
- **MCP audit-event emission for `verifyMCPCredential` / `verifyServerIdentity`.**
  Those are pure functions; harness can hand-emit equivalent events.
- **Distributed-mode propagation of `mcpDenyPolicy`.** Single broker only.

---

## Logging

The `formatDecision(d)` helper produces a one-line log-friendly string.
Recommended schema:

```
{timestamp} agentId={agentId} server={server} tool={tool} {formatDecision(d)}
```

`Decision` always carries enough context to log meaningfully: `allow`
includes `matchedScope`; `deny` includes `reason` and (when applicable)
the matched deny pattern; `ask` includes `reason`.

---

## CLI

```
# Policy
agent-iam mcp test --token <serialized> [--broker-deny <pattern>...] <server> <tool>
agent-iam mcp deny list
agent-iam mcp deny add <pattern>
agent-iam mcp deny remove <pattern>

# Schema pins
agent-iam mcp pin-list [--server <name>]
agent-iam mcp pin-clear <server> [tool]

# Credentials & key distribution
agent-iam mcp jwks
agent-iam mcp issue-cred <serverURI> --token <T> --scopes <S...> [--ttl <secs>] [--issuer <iss>]
```

`mcp test` exit codes encode the decision:
- `0` — allow
- `1` — deny
- `2` — ask

`mcp deny add` rejects patterns that aren't `*` or `mcp:*` shapes.
`mcp issue-cred` writes an `mcp.credential.issued` audit event to
`{configDir}/mcp-audit.jsonl` so operator-mints leave a trail. The
command is intended for debugging, not production-scale issuance — for
that, call `Broker.issueForMCPServer()` programmatically and supply
your own audit sink.

---

## Testing your integration

Three things every harness should test:

1. **Default-deny** — a token with no `mcp:*` scopes denies any MCP call.
2. **Broker-deny override** — a broker deny pattern blocks even when the
   token allows.
3. **Schema drift detection** — feed `verifyToolSchema` two tools with the
   same name but different descriptions; second call should report drift.

The `MemorySchemaPinRegistry` is the right choice for harness tests.

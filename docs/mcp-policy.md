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
For ephemeral agents use `MemorySchemaPinRegistry`.

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

```ts
import { issueMCPCredential, verifyMCPCredential } from "agent-iam";

// Broker side (or library wrapper):
const cred = await issueMCPCredential({
  agentToken: token,
  serverURI: "https://filesystem.example.com",
  scopes: ["mcp:filesystem:read_file"],
  signingKey: brokerSigningKeyPem,
  issuer: "broker.example.com",
  ttlSeconds: 300,
});

// Server side:
const v = await verifyMCPCredential(cred.jwt, {
  publicKey: brokerPublicKeyPem,
  expectedAudience: "https://filesystem.example.com",
});
if (!v.valid) reject(v.error);
```

The signing/verification keys are EdDSA (Ed25519), reusing the same
keypair format as agent-iam's identity stack. Broker-side key management
(generation, rotation, JWKS distribution) is not yet wired into the
`Broker` class — for now `issueMCPCredential` is a pure function the
caller invokes directly with the signing key.

---

## What's *not* in v1

- **Per-token deny scopes.** Use `brokerDenyPolicy` + enumerated allow lists.
- **Argument-level policy.** Hook seam reserved (`args` parameter); v2.
- **Session-state policy** (lethal-trifecta tripwires). v2.
- **Cross-server combination policy** ("A or B in a session, not both").
- **MCP proxy / out-of-process gate.** Out of scope for the broker.
- **Async task / elicitation lifecycle.**
- **`Broker.issueForMCPServer()` method.** Pure functions only in v1.

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

For local debugging:

```
agent-iam mcp test --token <serialized> [--broker-deny <pattern>...] <server> <tool>
agent-iam mcp pin-list [--server <name>]
agent-iam mcp pin-clear <server> [tool]
```

`mcp test` exit codes encode the decision:
- `0` — allow
- `1` — deny
- `2` — ask

---

## Testing your integration

Three things every harness should test:

1. **Default-deny** — a token with no `mcp:*` scopes denies any MCP call.
2. **Broker-deny override** — a broker deny pattern blocks even when the
   token allows.
3. **Schema drift detection** — feed `verifyToolSchema` two tools with the
   same name but different descriptions; second call should report drift.

The `MemorySchemaPinRegistry` is the right choice for harness tests.

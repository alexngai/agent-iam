/**
 * MCP Tool Allow/Deny Policy
 *
 * Pure-function policy check the harness calls before dispatching each
 * MCP tool invocation. Three-state decision (allow / deny / ask) matching
 * the Claude Code precedence model: deny → ask → allow.
 *
 * Design (from docs/features.md W1):
 *   - New scope namespace: `mcp:<server>:<tool>` (3 segments, matching the
 *     existing `provider:resource:action` grammar).
 *   - Default-deny: tokens with no matching `mcp:*` scope have MCP calls
 *     denied. Migration helper adds `mcp:*` to existing tokens for
 *     backwards compatibility.
 *   - Broker-level deny policy (the SCP analog) wins over any token allow.
 *     There is no per-token `denyScopes` in v1.
 *   - Three-state Decision: `ask` lets harnesses surface human-in-the-loop
 *     prompts. v1 broker doesn't emit tokens that produce `ask` directly,
 *     but defining it now keeps the contract stable.
 */

import { scopeMatches } from "../token.js";
import type { AgentToken } from "../types.js";
import type { MCPToolAnnotations } from "./types.js";

/** Outcome of a single MCP tool-call policy check */
export type Decision =
  | { kind: "allow"; matchedScope: string }
  | { kind: "deny"; reason: string; matchedScope?: string }
  | { kind: "ask"; reason: string };

/** Optional context the harness can supply to `checkMCPCall`. */
export interface CheckMCPCallOptions {
  /**
   * Org-wide deny patterns (e.g. `mcp:shell:*`). Evaluated before token
   * allow lists; any match returns `deny` regardless of token scopes.
   * Cannot be widened by tokens — this is the SCP analog.
   */
  brokerDenyPolicy?: string[];

  /**
   * Tool annotations from the server. Reserved for v1 annotation-aware
   * policy primitives (see W1 step 4). Currently unused; harnesses may
   * pass them now to forward-compat the call site.
   */
  toolAnnotations?: MCPToolAnnotations;
}

/**
 * Check whether a token may invoke a given MCP tool.
 *
 * Order of evaluation:
 *   1. Broker-level deny policy (org-wide, wins over everything).
 *   2. Token allow list (any matching scope grants the call).
 *   3. Default deny.
 *
 * @param token   The agent's capability token.
 * @param server  MCP server name as known to the harness (e.g. `"filesystem"`).
 * @param tool    Tool name as exposed by the server (e.g. `"read_file"`).
 * @param args    Tool call arguments. Reserved for v2 argument-level policy;
 *                ignored in v1 but kept in the signature so harnesses don't
 *                need to change later.
 * @param options Broker policy and (forward-compat) tool annotations.
 */
export function checkMCPCall(
  token: AgentToken,
  server: string,
  tool: string,
  args?: unknown,
  options?: CheckMCPCallOptions
): Decision {
  const target = `mcp:${server}:${tool}`;

  if (options?.brokerDenyPolicy) {
    for (const pattern of options.brokerDenyPolicy) {
      if (scopeMatches(pattern, target)) {
        return {
          kind: "deny",
          reason: `Broker policy denies ${target}`,
          matchedScope: pattern,
        };
      }
    }
  }

  for (const pattern of token.scopes) {
    if (scopeMatches(pattern, target)) {
      return { kind: "allow", matchedScope: pattern };
    }
  }

  return {
    kind: "deny",
    reason: `No matching scope for ${target}`,
  };
}

/**
 * Format a Decision as a single log-friendly line. Recommended schema for
 * harness audit logs alongside (timestamp, agentId, server, tool).
 */
export function formatDecision(d: Decision): string {
  switch (d.kind) {
    case "allow":
      return `allow (matched ${d.matchedScope})`;
    case "ask":
      return `ask (${d.reason})`;
    case "deny":
      return d.matchedScope
        ? `deny (${d.reason}; matched ${d.matchedScope})`
        : `deny (${d.reason})`;
  }
}

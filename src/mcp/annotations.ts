/**
 * MCP Tool Annotation-Aware Policy Primitives
 *
 * Composable transformers that escalate a `Decision` based on the tool's
 * declared annotations (`destructiveHint`, `openWorldHint`, etc.).
 *
 * Annotations are **advisory only** per the MCP spec (and explicitly
 * called out in the official MCP blog, March 2026): untrusted servers
 * can lie about them. Use these primitives only with servers you trust
 * to be honest about their tools' behavior.
 *
 * Typical usage in a harness:
 *
 *   let d = checkMCPCall(token, server, tool, args, { brokerDenyPolicy });
 *   d = requireApprovalIf(d, tool.annotations, "destructiveHint");
 *   d = denyIf(d, tool.annotations, "openWorldHint");
 *   // act on d
 *
 * Decision severity is monotonic: `allow < ask < deny`. Transformers can
 * escalate but never relax — a `deny` from the policy layer can never be
 * downgraded by an annotation predicate.
 */

import type { Decision } from "./policy.js";
import type { MCPToolAnnotations } from "./types.js";

/** Boolean annotation hints defined by the MCP spec. */
export type AnnotationHint =
  | "readOnlyHint"
  | "destructiveHint"
  | "idempotentHint"
  | "openWorldHint";

/**
 * Escalate `decision` to `ask` if the named annotation hint is `true`.
 *
 * - `deny` is sticky (already denied stays denied).
 * - `ask` is unchanged (already requires approval).
 * - `allow` becomes `ask` when the hint is true.
 * - Missing annotations or `hint !== true` are a no-op.
 */
export function requireApprovalIf(
  decision: Decision,
  annotations: MCPToolAnnotations | undefined,
  hint: AnnotationHint
): Decision {
  if (decision.kind === "deny" || decision.kind === "ask") return decision;
  if (annotations?.[hint] !== true) return decision;
  return {
    kind: "ask",
    reason: `Tool annotation ${hint}=true requires approval`,
  };
}

/**
 * Escalate `decision` to `deny` if the named annotation hint is `true`.
 *
 * - `deny` is sticky.
 * - `ask` and `allow` both become `deny` when the hint is true.
 * - Missing annotations or `hint !== true` are a no-op.
 *
 * Useful for blanket policies like "no open-world tools" — a building
 * block for lethal-trifecta defenses.
 */
export function denyIf(
  decision: Decision,
  annotations: MCPToolAnnotations | undefined,
  hint: AnnotationHint
): Decision {
  if (decision.kind === "deny") return decision;
  if (annotations?.[hint] !== true) return decision;
  return {
    kind: "deny",
    reason: `Tool annotation ${hint}=true is denied by policy`,
  };
}

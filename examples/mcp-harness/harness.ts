/**
 * Reference MCP harness integration.
 *
 * Wraps a single tool dispatch with all four agent-iam checks in order:
 *   1. Tool-schema TOFU pinning  — detect rug-pulls.
 *   2. Allow/deny scope check   — token + broker-level deny.
 *   3. Annotation escalation    — destructive/open-world hints.
 *   4. Server identity check    — once at connection time, not per call
 *      (illustrated separately, not in this dispatch path).
 *
 * Replace the `invokeTool` and `promptHuman` stubs with your real MCP
 * client and human-approval mechanism.
 */

import {
  checkMCPCall,
  verifyToolSchema,
  requireApprovalIf,
  denyIf,
  formatDecision,
  type AgentToken,
  type MCPTool,
  type SchemaPinRegistry,
  type Decision,
} from "../../dist/index.js";

export interface HarnessConfig {
  /** Optional org-wide deny patterns (e.g. ["mcp:shell:*"]). */
  brokerDenyPolicy?: string[];
  /** Server names whose annotations the harness will trust as policy input. */
  trustedServersForAnnotations?: Set<string>;
  /** Schema-pin storage backend. */
  pinRegistry: SchemaPinRegistry;
  /**
   * If true (default), unrecognized tools are auto-pinned on first sight
   * (TOFU). If false, only previously-pinned tools are accepted.
   */
  tofu?: boolean;
  /** Stub for the actual MCP tool invocation. */
  invokeTool: (server: string, tool: string, args: unknown) => Promise<unknown>;
  /** Stub for surfacing an `ask` decision to a human. Returns true if approved. */
  promptHuman: (reason: string) => Promise<boolean>;
  /** Audit-log sink. */
  log?: (line: string) => void;
}

export class PermissionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

export class SchemaDriftError extends Error {
  constructor(message: string, public knownHash: string, public currentHash: string) {
    super(message);
    this.name = "SchemaDriftError";
  }
}

export async function dispatchToolCall(
  cfg: HarnessConfig,
  token: AgentToken,
  serverName: string,
  toolDef: MCPTool,
  args: unknown
): Promise<unknown> {
  const log = cfg.log ?? (() => {});
  const target = `${serverName}/${toolDef.name}`;

  // 1. Schema TOFU.
  const tofu = cfg.tofu ?? true;
  const pin = await verifyToolSchema(serverName, toolDef, cfg.pinRegistry, { tofu });
  if (!pin.valid) {
    if (pin.drift) {
      log(`tool=${target} schema-drift known=${pin.drift.knownHash.slice(0, 8)} current=${pin.drift.currentHash.slice(0, 8)}`);
      const approved = await cfg.promptHuman(
        `Tool ${target} schema has changed since first use. Continue?`
      );
      if (!approved) {
        throw new SchemaDriftError(
          `User rejected drifted tool ${target}`,
          pin.drift.knownHash,
          pin.drift.currentHash
        );
      }
      // User-approved drift: re-pin to the new hash.
      await cfg.pinRegistry.set(serverName, toolDef.name, pin.drift.currentHash);
      log(`tool=${target} schema-repinned current=${pin.drift.currentHash.slice(0, 8)}`);
    } else {
      // Strict mode (cfg.tofu === false) and the tool was never pinned.
      throw new SchemaDriftError(
        `Tool ${target} not pinned (strict mode)`,
        "",
        ""
      );
    }
  }

  // 2. Scope policy.
  let decision: Decision = checkMCPCall(token, serverName, toolDef.name, args, {
    brokerDenyPolicy: cfg.brokerDenyPolicy,
  });

  // 3. Annotation escalation (only for trusted servers).
  if (cfg.trustedServersForAnnotations?.has(serverName)) {
    decision = requireApprovalIf(decision, toolDef.annotations, "destructiveHint");
    decision = denyIf(decision, toolDef.annotations, "openWorldHint");
  }

  log(`tool=${target} ${formatDecision(decision)}`);

  switch (decision.kind) {
    case "deny":
      throw new PermissionError(decision.reason);
    case "ask": {
      const approved = await cfg.promptHuman(decision.reason);
      if (!approved) {
        throw new PermissionError(`User rejected ${target}: ${decision.reason}`);
      }
      return cfg.invokeTool(serverName, toolDef.name, args);
    }
    case "allow":
      return cfg.invokeTool(serverName, toolDef.name, args);
  }
}

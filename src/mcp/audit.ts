/**
 * MCP Audit Event Schema and Sinks
 *
 * Structured audit events for every MCP policy decision the harness runs.
 * Critical for incident response — `formatDecision` produces a string for
 * human-readable logs, but for "agent X tried to call mcp:shell:exec 47
 * times today" you need structured events that can ship to a SIEM, OTel
 * collector, or local JSONL file.
 *
 * Three pieces:
 *   - `MCPAuditEvent` — the canonical event shape.
 *   - `MCPAuditSink` interface — pluggable backends.
 *   - Built-in sinks: `ConsoleAuditSink`, `FileAuditSink` (JSONL), and
 *     `MemoryAuditSink` (tests).
 *
 * Harness usage:
 *   const sink = new FileAuditSink("/var/log/agent-iam/audit.jsonl");
 *   const decision = checkMCPCall(...);
 *   await sink.record(buildAuditEvent({ agentId, server, tool, decision }));
 */

import * as fs from "fs";
import * as path from "path";
import type { Decision } from "./policy.js";

/** Structured audit event for a single MCP policy decision or pin operation. */
export interface MCPAuditEvent {
  /** Event timestamp (ISO 8601). */
  timestamp: string;
  /**
   * Event kind. Only the kinds with active emitters in this library are
   * declared; harnesses extending the audit pipeline can pass arbitrary
   * additional strings here at runtime via type-coercion if they want to
   * record their own kinds.
   */
  kind:
    | "mcp.tool.decision"
    | "mcp.schema.pin"
    | "mcp.schema.drift"
    | "mcp.schema.repin"
    | "mcp.credential.issued";
  /** Agent the event is about, when applicable. */
  agentId?: string;
  /** MCP server identifier, when applicable. */
  server?: string;
  /** Tool name, when applicable. */
  tool?: string;
  /** Decision outcome, when applicable (mirrors Decision.kind). */
  decision?: "allow" | "deny" | "ask";
  /** Free-text reason carried from the underlying decision/operation. */
  reason?: string;
  /** Scope pattern matched, when applicable. */
  matchedScope?: string;
  /** Tool-schema hash relevant to the event (e.g., on pin or drift). */
  hash?: string;
  /** Prior hash, on drift / repin events. */
  priorHash?: string;
  /** RFC 8707 audience (the canonical server URI), on credential events. */
  audience?: string;
  /** Free-form additional context the harness wants to record. */
  context?: Record<string, unknown>;
}

/** Args for buildAuditEvent's most common usage (decision events). */
export interface BuildDecisionEventArgs {
  agentId?: string;
  server: string;
  tool: string;
  decision: Decision;
  context?: Record<string, unknown>;
}

/**
 * Build an `MCPAuditEvent` from a `Decision`. Captures matchedScope/reason
 * automatically and stamps the timestamp. Caller adds the event to a sink.
 */
export function buildDecisionEvent(args: BuildDecisionEventArgs): MCPAuditEvent {
  return {
    timestamp: new Date().toISOString(),
    kind: "mcp.tool.decision",
    agentId: args.agentId,
    server: args.server,
    tool: args.tool,
    decision: args.decision.kind,
    reason: args.decision.kind === "allow" ? undefined : args.decision.reason,
    matchedScope:
      args.decision.kind === "allow"
        ? args.decision.matchedScope
        : args.decision.kind === "deny"
        ? args.decision.matchedScope
        : undefined,
    context: args.context,
  };
}

/** Pluggable audit-event sink. Harnesses pick (or write) one. */
export interface MCPAuditSink {
  record(event: MCPAuditEvent): Promise<void>;
}

/** Drops events on the floor. Useful as a default for tests / no-op harnesses. */
export class NullAuditSink implements MCPAuditSink {
  async record(_event: MCPAuditEvent): Promise<void> {
    // no-op
  }
}

/** Logs events to console.log as one JSON line each. */
export class ConsoleAuditSink implements MCPAuditSink {
  async record(event: MCPAuditEvent): Promise<void> {
    console.log(JSON.stringify(event));
  }
}

/** Captures events in memory; useful for assertion in tests. */
export class MemoryAuditSink implements MCPAuditSink {
  readonly events: MCPAuditEvent[] = [];
  async record(event: MCPAuditEvent): Promise<void> {
    this.events.push(event);
  }
  clear(): void {
    this.events.length = 0;
  }
}

/**
 * Appends events to a file as JSONL (one JSON object per line). Creates the
 * file with mode 0o600 if it doesn't exist; ensures the parent directory
 * exists with mode 0o700.
 *
 * Not concurrency-safe across processes; for that use an external collector
 * (rsyslog, otel, etc.).
 */
export class FileAuditSink implements MCPAuditSink {
  private readonly path: string;
  private initialized = false;

  constructor(filePath: string) {
    this.path = filePath;
  }

  async record(event: MCPAuditEvent): Promise<void> {
    this.ensureInitialized();
    fs.appendFileSync(this.path, JSON.stringify(event) + "\n");
  }

  private ensureInitialized(): void {
    if (this.initialized) return;
    const dir = path.dirname(this.path);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    // Open with O_APPEND | O_CREAT (no O_TRUNC) so concurrent writers
    // don't truncate each other's records. `writeFileSync(path, "")` would
    // race with another process's appendFileSync and clobber events.
    const fd = fs.openSync(this.path, "a", 0o600);
    fs.closeSync(fd);
    this.initialized = true;
  }
}

/**
 * Multiplex events to multiple sinks. Each is awaited in order; if one
 * throws, later sinks still run, and the error from the first failure is
 * re-thrown after all have been attempted.
 */
export class CompositeAuditSink implements MCPAuditSink {
  constructor(private readonly sinks: MCPAuditSink[]) {}

  async record(event: MCPAuditEvent): Promise<void> {
    let firstError: unknown;
    for (const s of this.sinks) {
      try {
        await s.record(event);
      } catch (err) {
        if (firstError === undefined) firstError = err;
      }
    }
    if (firstError !== undefined) throw firstError;
  }
}

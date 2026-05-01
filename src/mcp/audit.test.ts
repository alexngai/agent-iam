/**
 * Tests for MCP audit event schema and sinks.
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  buildDecisionEvent,
  ConsoleAuditSink,
  CompositeAuditSink,
  FileAuditSink,
  MemoryAuditSink,
  NullAuditSink,
} from "./audit.js";
import type { Decision } from "./policy.js";

describe("buildDecisionEvent", () => {
  test("captures allow with matched scope", () => {
    const d: Decision = { kind: "allow", matchedScope: "mcp:fs:*" };
    const e = buildDecisionEvent({ agentId: "a", server: "fs", tool: "read", decision: d });
    assert.strictEqual(e.kind, "mcp.tool.decision");
    assert.strictEqual(e.decision, "allow");
    assert.strictEqual(e.matchedScope, "mcp:fs:*");
    assert.strictEqual(e.reason, undefined);
    assert.match(e.timestamp, /\d{4}-\d{2}-\d{2}T/);
  });

  test("captures deny with reason and matched scope", () => {
    const d: Decision = {
      kind: "deny",
      reason: "Broker policy denies mcp:shell:exec",
      matchedScope: "mcp:shell:*",
    };
    const e = buildDecisionEvent({ server: "shell", tool: "exec", decision: d });
    assert.strictEqual(e.decision, "deny");
    assert.match(e.reason ?? "", /Broker policy/);
    assert.strictEqual(e.matchedScope, "mcp:shell:*");
  });

  test("captures ask with reason", () => {
    const d: Decision = { kind: "ask", reason: "destructiveHint=true" };
    const e = buildDecisionEvent({ server: "fs", tool: "rm", decision: d });
    assert.strictEqual(e.decision, "ask");
    assert.strictEqual(e.matchedScope, undefined);
    assert.match(e.reason ?? "", /destructiveHint/);
  });

  test("forwards arbitrary context", () => {
    const d: Decision = { kind: "allow", matchedScope: "*" };
    const e = buildDecisionEvent({
      server: "fs",
      tool: "read",
      decision: d,
      context: { sessionId: "abc-123" },
    });
    assert.deepStrictEqual(e.context, { sessionId: "abc-123" });
  });
});

describe("MemoryAuditSink", () => {
  test("captures events in order", async () => {
    const sink = new MemoryAuditSink();
    await sink.record({ timestamp: "t1", kind: "mcp.tool.decision", server: "a", tool: "x" });
    await sink.record({ timestamp: "t2", kind: "mcp.tool.decision", server: "b", tool: "y" });
    assert.strictEqual(sink.events.length, 2);
    assert.strictEqual(sink.events[0].server, "a");
    assert.strictEqual(sink.events[1].server, "b");
  });

  test("clear empties the buffer", async () => {
    const sink = new MemoryAuditSink();
    await sink.record({ timestamp: "t", kind: "mcp.tool.decision" });
    sink.clear();
    assert.strictEqual(sink.events.length, 0);
  });
});

describe("NullAuditSink", () => {
  test("accepts any event without throwing", async () => {
    const sink = new NullAuditSink();
    await sink.record({ timestamp: "t", kind: "mcp.tool.decision" });
  });
});

describe("FileAuditSink", () => {
  let tmpDir: string;
  let logPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-audit-test-"));
    logPath = path.join(tmpDir, "subdir", "audit.jsonl");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("creates parent directory and file on first write", async () => {
    const sink = new FileAuditSink(logPath);
    await sink.record({ timestamp: "t", kind: "mcp.tool.decision", server: "a", tool: "x" });
    assert.ok(fs.existsSync(logPath));
  });

  test("writes one JSON object per line", async () => {
    const sink = new FileAuditSink(logPath);
    await sink.record({ timestamp: "t1", kind: "mcp.tool.decision", server: "a", tool: "x" });
    await sink.record({ timestamp: "t2", kind: "mcp.tool.decision", server: "b", tool: "y" });
    const contents = fs.readFileSync(logPath, "utf8");
    const lines = contents.trim().split("\n");
    assert.strictEqual(lines.length, 2);
    assert.deepStrictEqual(JSON.parse(lines[0]), {
      timestamp: "t1",
      kind: "mcp.tool.decision",
      server: "a",
      tool: "x",
    });
  });

  test("appends to existing file", async () => {
    const sink1 = new FileAuditSink(logPath);
    await sink1.record({ timestamp: "t1", kind: "mcp.tool.decision" });

    const sink2 = new FileAuditSink(logPath);
    await sink2.record({ timestamp: "t2", kind: "mcp.tool.decision" });

    const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
    assert.strictEqual(lines.length, 2);
  });

  test("audit file is created with mode 0o600", async () => {
    const sink = new FileAuditSink(logPath);
    await sink.record({ timestamp: "t", kind: "mcp.tool.decision" });
    const mode = fs.statSync(logPath).mode & 0o777;
    assert.strictEqual(mode, 0o600);
  });
});

describe("CompositeAuditSink", () => {
  test("forwards to all sinks", async () => {
    const a = new MemoryAuditSink();
    const b = new MemoryAuditSink();
    const composite = new CompositeAuditSink([a, b]);
    await composite.record({ timestamp: "t", kind: "mcp.tool.decision" });
    assert.strictEqual(a.events.length, 1);
    assert.strictEqual(b.events.length, 1);
  });

  test("continues to remaining sinks if one throws", async () => {
    const broken: { record: (e: any) => Promise<void> } = {
      record: async () => {
        throw new Error("sink down");
      },
    };
    const ok = new MemoryAuditSink();
    const composite = new CompositeAuditSink([broken, ok]);
    await assert.rejects(
      () => composite.record({ timestamp: "t", kind: "mcp.tool.decision" }),
      /sink down/
    );
    // The healthy sink still received the event despite the failing one.
    assert.strictEqual(ok.events.length, 1);
  });
});

describe("ConsoleAuditSink", () => {
  test("emits to stdout (smoke test)", async () => {
    // We don't intercept stdout — just assert no throw.
    const sink = new ConsoleAuditSink();
    const original = console.log;
    let captured = "";
    console.log = (msg: string) => {
      captured = msg;
    };
    try {
      await sink.record({
        timestamp: "t",
        kind: "mcp.tool.decision",
        server: "fs",
        tool: "read",
      });
    } finally {
      console.log = original;
    }
    assert.match(captured, /"kind":"mcp\.tool\.decision"/);
    assert.match(captured, /"server":"fs"/);
  });
});

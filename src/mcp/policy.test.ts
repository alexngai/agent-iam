/**
 * Tests for MCP allow/deny policy.
 */

import { test, describe } from "node:test";
import * as assert from "node:assert";
import { checkMCPCall, formatDecision } from "./policy.js";
import type { AgentToken } from "../types.js";

/** Build a minimal AgentToken stub with the given scopes. */
function tokenWith(scopes: string[]): AgentToken {
  return {
    agentId: "test-agent",
    scopes,
    constraints: {},
    delegatable: false,
    maxDelegationDepth: 0,
    currentDepth: 0,
  };
}

describe("checkMCPCall — token allow list", () => {
  test("allows on exact scope match", () => {
    const token = tokenWith(["mcp:filesystem:read_file"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "allow");
    if (d.kind === "allow") {
      assert.strictEqual(d.matchedScope, "mcp:filesystem:read_file");
    }
  });

  test("allows on tool wildcard (mcp:filesystem:*)", () => {
    const token = tokenWith(["mcp:filesystem:*"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "allow");
    if (d.kind === "allow") {
      assert.strictEqual(d.matchedScope, "mcp:filesystem:*");
    }
  });

  test("allows on namespace wildcard (mcp:*) — opt-in to all MCP", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "allow");
  });

  test("allows on universal wildcard (*)", () => {
    const token = tokenWith(["*"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "allow");
  });

  test("returns the actual matched scope, not the request", () => {
    const token = tokenWith(["mcp:filesystem:*"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    if (d.kind === "allow") {
      assert.strictEqual(d.matchedScope, "mcp:filesystem:*");
    } else {
      assert.fail("expected allow");
    }
  });

  test("first matching scope wins", () => {
    const token = tokenWith(["mcp:filesystem:read_file", "mcp:filesystem:*"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    if (d.kind === "allow") {
      assert.strictEqual(d.matchedScope, "mcp:filesystem:read_file");
    } else {
      assert.fail("expected allow");
    }
  });
});

describe("checkMCPCall — default deny", () => {
  test("denies when token has no MCP scopes (default-deny once shipped)", () => {
    const token = tokenWith(["github:repo:read"]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") {
      assert.match(d.reason, /No matching scope/);
    }
  });

  test("denies when token has empty scope list", () => {
    const token = tokenWith([]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    assert.strictEqual(d.kind, "deny");
  });

  test("denies on different server (mcp:filesystem:* does not grant net)", () => {
    const token = tokenWith(["mcp:filesystem:*"]);
    const d = checkMCPCall(token, "net", "fetch");
    assert.strictEqual(d.kind, "deny");
  });

  test("denies on different tool (mcp:filesystem:read_file does not grant write_file)", () => {
    const token = tokenWith(["mcp:filesystem:read_file"]);
    const d = checkMCPCall(token, "filesystem", "write_file");
    assert.strictEqual(d.kind, "deny");
  });

  test("default-deny includes the target in the reason for audit", () => {
    const token = tokenWith([]);
    const d = checkMCPCall(token, "filesystem", "read_file");
    if (d.kind === "deny") {
      assert.match(d.reason, /mcp:filesystem:read_file/);
    } else {
      assert.fail("expected deny");
    }
  });
});

describe("checkMCPCall — broker-level deny policy", () => {
  test("broker deny overrides token allow", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "shell", "exec", undefined, {
      brokerDenyPolicy: ["mcp:shell:*"],
    });
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") {
      assert.strictEqual(d.matchedScope, "mcp:shell:*");
      assert.match(d.reason, /Broker policy/);
    }
  });

  test("broker deny on exact tool wins over token's exact allow", () => {
    const token = tokenWith(["mcp:shell:exec"]);
    const d = checkMCPCall(token, "shell", "exec", undefined, {
      brokerDenyPolicy: ["mcp:shell:exec"],
    });
    assert.strictEqual(d.kind, "deny");
  });

  test("broker deny only fires when the pattern matches the target", () => {
    const token = tokenWith(["mcp:filesystem:read_file"]);
    const d = checkMCPCall(token, "filesystem", "read_file", undefined, {
      brokerDenyPolicy: ["mcp:shell:*"],
    });
    assert.strictEqual(d.kind, "allow");
  });

  test("empty broker deny policy is a no-op", () => {
    const token = tokenWith(["mcp:filesystem:*"]);
    const d = checkMCPCall(token, "filesystem", "read_file", undefined, {
      brokerDenyPolicy: [],
    });
    assert.strictEqual(d.kind, "allow");
  });

  test("first matching broker deny pattern wins", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "shell", "exec", undefined, {
      brokerDenyPolicy: ["mcp:shell:*", "mcp:*"],
    });
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") {
      assert.strictEqual(d.matchedScope, "mcp:shell:*");
    }
  });

  test("broker deny without any token allow still denies (deny first, then default-deny)", () => {
    const token = tokenWith(["github:repo:read"]);
    const d = checkMCPCall(token, "shell", "exec", undefined, {
      brokerDenyPolicy: ["mcp:shell:*"],
    });
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") {
      assert.match(d.reason, /Broker policy/);
    }
  });
});

describe("checkMCPCall — server/tool name validation", () => {
  // Regression for review finding C2: with a colon in server or tool, the
  // built target has >3 segments and interacts unsafely with wildcard match.
  test("rejects server name containing `:`", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "fs:evil", "tool");
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") assert.match(d.reason, /Invalid MCP server name/);
  });

  test("rejects tool name containing `:`", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "fs", "evil:tool");
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") assert.match(d.reason, /Invalid MCP tool name/);
  });

  test("rejects empty server name", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "", "tool");
    assert.strictEqual(d.kind, "deny");
  });

  test("rejects empty tool name", () => {
    const token = tokenWith(["mcp:*"]);
    const d = checkMCPCall(token, "fs", "");
    assert.strictEqual(d.kind, "deny");
  });
});

describe("checkMCPCall — args reserved", () => {
  test("v1 ignores args; identical decision regardless", () => {
    const token = tokenWith(["mcp:filesystem:read_file"]);
    const a = checkMCPCall(token, "filesystem", "read_file");
    const b = checkMCPCall(token, "filesystem", "read_file", { path: "/etc/passwd" });
    assert.strictEqual(a.kind, b.kind);
  });
});

describe("formatDecision", () => {
  test("formats allow with matched scope", () => {
    const s = formatDecision({ kind: "allow", matchedScope: "mcp:fs:*" });
    assert.match(s, /^allow/);
    assert.match(s, /mcp:fs:\*/);
  });

  test("formats deny with reason and matched scope", () => {
    const s = formatDecision({
      kind: "deny",
      reason: "Broker policy denies mcp:shell:exec",
      matchedScope: "mcp:shell:*",
    });
    assert.match(s, /^deny/);
    assert.match(s, /Broker policy/);
    assert.match(s, /mcp:shell:\*/);
  });

  test("formats deny without matched scope", () => {
    const s = formatDecision({
      kind: "deny",
      reason: "No matching scope for mcp:net:fetch",
    });
    assert.match(s, /^deny/);
    assert.match(s, /No matching scope/);
  });

  test("formats ask with reason", () => {
    const s = formatDecision({ kind: "ask", reason: "Destructive tool" });
    assert.match(s, /^ask/);
    assert.match(s, /Destructive tool/);
  });
});

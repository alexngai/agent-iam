/**
 * Tests for annotation-aware policy primitives.
 */

import { test, describe } from "node:test";
import * as assert from "node:assert";
import { requireApprovalIf, denyIf } from "./annotations.js";
import type { Decision } from "./policy.js";

const ALLOW: Decision = { kind: "allow", matchedScope: "mcp:fs:*" };
const ASK: Decision = { kind: "ask", reason: "prior ask" };
const DENY: Decision = { kind: "deny", reason: "prior deny" };

describe("requireApprovalIf", () => {
  test("escalates allow → ask when hint is true", () => {
    const d = requireApprovalIf(ALLOW, { destructiveHint: true }, "destructiveHint");
    assert.strictEqual(d.kind, "ask");
    if (d.kind === "ask") {
      assert.match(d.reason, /destructiveHint=true/);
    }
  });

  test("no-op when hint is missing from annotations", () => {
    const d = requireApprovalIf(ALLOW, {}, "destructiveHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("no-op when hint is explicitly false", () => {
    const d = requireApprovalIf(ALLOW, { destructiveHint: false }, "destructiveHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("no-op when annotations object is undefined", () => {
    const d = requireApprovalIf(ALLOW, undefined, "destructiveHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("sticky on prior ask (no double-prompt)", () => {
    const d = requireApprovalIf(ASK, { destructiveHint: true }, "destructiveHint");
    assert.deepStrictEqual(d, ASK);
  });

  test("sticky on prior deny (cannot relax to ask)", () => {
    const d = requireApprovalIf(DENY, { destructiveHint: true }, "destructiveHint");
    assert.deepStrictEqual(d, DENY);
  });

  test("works with each spec'd hint", () => {
    for (const hint of ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const) {
      const d = requireApprovalIf(ALLOW, { [hint]: true }, hint);
      assert.strictEqual(d.kind, "ask", `hint=${hint}`);
    }
  });
});

describe("denyIf", () => {
  test("escalates allow → deny when hint is true", () => {
    const d = denyIf(ALLOW, { openWorldHint: true }, "openWorldHint");
    assert.strictEqual(d.kind, "deny");
    if (d.kind === "deny") {
      assert.match(d.reason, /openWorldHint=true/);
    }
  });

  test("escalates ask → deny when hint is true", () => {
    const d = denyIf(ASK, { openWorldHint: true }, "openWorldHint");
    assert.strictEqual(d.kind, "deny");
  });

  test("no-op when hint is missing", () => {
    const d = denyIf(ALLOW, {}, "openWorldHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("no-op when hint is explicitly false", () => {
    const d = denyIf(ALLOW, { openWorldHint: false }, "openWorldHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("no-op when annotations object is undefined", () => {
    const d = denyIf(ALLOW, undefined, "openWorldHint");
    assert.deepStrictEqual(d, ALLOW);
  });

  test("sticky on prior deny (preserves original reason)", () => {
    const d = denyIf(DENY, { openWorldHint: true }, "openWorldHint");
    assert.deepStrictEqual(d, DENY);
  });
});

describe("composition (typical harness chain)", () => {
  test("allow → require-approval-if-destructive → deny-if-openWorld: stops at ask", () => {
    let d: Decision = ALLOW;
    d = requireApprovalIf(d, { destructiveHint: true }, "destructiveHint");
    d = denyIf(d, { destructiveHint: true }, "openWorldHint"); // openWorld absent
    assert.strictEqual(d.kind, "ask");
  });

  test("allow → require-approval → deny escalates to deny when both hints fire", () => {
    let d: Decision = ALLOW;
    const annotations = { destructiveHint: true, openWorldHint: true };
    d = requireApprovalIf(d, annotations, "destructiveHint");
    d = denyIf(d, annotations, "openWorldHint");
    assert.strictEqual(d.kind, "deny");
  });

  test("allow with no flagged annotations stays allow through the chain", () => {
    let d: Decision = ALLOW;
    const annotations = { readOnlyHint: true };
    d = requireApprovalIf(d, annotations, "destructiveHint");
    d = denyIf(d, annotations, "openWorldHint");
    assert.strictEqual(d.kind, "allow");
  });

  test("deny from policy is not relaxed by annotations chain", () => {
    let d: Decision = DENY;
    const annotations = { readOnlyHint: true };
    d = requireApprovalIf(d, annotations, "destructiveHint");
    d = denyIf(d, annotations, "openWorldHint");
    assert.deepStrictEqual(d, DENY);
  });
});

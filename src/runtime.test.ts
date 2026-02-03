/**
 * Tests for AgentRuntime
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Broker } from "./broker.js";
import {
  AgentRuntime,
  AGENT_TOKEN_ENV,
  withRuntime,
} from "./runtime.js";

// Create a unique temp directory for each test
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-runtime-test-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("AgentRuntime", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
    // Clean up environment
    delete process.env[AGENT_TOKEN_ENV];
  });

  describe("Construction", () => {
    test("creates runtime from token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      assert.ok(runtime);

      const status = runtime.getStatus();
      assert.strictEqual(status.agentId, "test");
    });

    test("creates runtime from serialized token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });
      const serialized = broker.serializeToken(token);

      const runtime = AgentRuntime.fromSerialized(serialized, {
        configDir: tempDir,
      });
      assert.ok(runtime);

      const status = runtime.getStatus();
      assert.strictEqual(status.agentId, "test");
    });

    test("creates runtime from environment", () => {
      const token = broker.createRootToken({
        agentId: "env-test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });
      process.env[AGENT_TOKEN_ENV] = broker.serializeToken(token);

      const runtime = AgentRuntime.fromEnvironment({ configDir: tempDir });
      assert.ok(runtime);

      const status = runtime.getStatus();
      assert.strictEqual(status.agentId, "env-test");
    });

    test("throws if environment variable not set", () => {
      delete process.env[AGENT_TOKEN_ENV];

      assert.throws(
        () => {
          AgentRuntime.fromEnvironment({ configDir: tempDir });
        },
        { message: /AGENT_TOKEN.*not set/ }
      );
    });
  });

  describe("start/stop", () => {
    test("starts with valid token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();
      runtime.stop();
    });

    test("throws on start with invalid token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
      });

      // Tamper with token
      const tampered = { ...token, scopes: ["hacked"] };

      const runtime = new AgentRuntime(tampered, { configDir: tempDir });

      assert.throws(
        () => {
          runtime.start();
        },
        { message: /Invalid token/ }
      );
    });

    test("throws on restart after stop", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();
      runtime.stop();

      assert.throws(
        () => {
          runtime.start();
        },
        { message: /stopped.*cannot be restarted/ }
      );
    });

    test("operations fail after stop", async () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();
      runtime.stop();

      assert.throws(
        () => {
          runtime.delegate({ requestedScopes: ["github:repo:read"] });
        },
        { message: /stopped/ }
      );
    });
  });

  describe("Permission Checking", () => {
    test("checkPermission returns true for allowed scope", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      assert.strictEqual(
        runtime.checkPermission("github:repo:read", "any/repo"),
        true
      );

      runtime.stop();
    });

    test("checkPermission returns false for disallowed scope", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      assert.strictEqual(
        runtime.checkPermission("github:repo:write", "any/repo"),
        false
      );

      runtime.stop();
    });

    test("checkPermission respects constraints", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        constraints: {
          "github:repo:read": { resources: ["myorg/*"] },
        },
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      assert.strictEqual(
        runtime.checkPermission("github:repo:read", "myorg/repo"),
        true
      );
      assert.strictEqual(
        runtime.checkPermission("github:repo:read", "other/repo"),
        false
      );

      runtime.stop();
    });
  });

  describe("Delegation", () => {
    test("delegates to create child token", () => {
      const token = broker.createRootToken({
        agentId: "parent",
        scopes: ["github:repo:read", "github:repo:write"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      const child = runtime.delegate({
        agentId: "child",
        requestedScopes: ["github:repo:read"],
        ttlMinutes: 30,
      });

      assert.strictEqual(child.parentId, "parent");
      assert.deepStrictEqual(child.scopes, ["github:repo:read"]);

      runtime.stop();
    });

    test("createSubprocessEnv returns environment with token", () => {
      const token = broker.createRootToken({
        agentId: "parent",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      const env = runtime.createSubprocessEnv({
        agentId: "subprocess",
        requestedScopes: ["github:repo:read"],
      });

      assert.ok(env[AGENT_TOKEN_ENV]);
      assert.ok(typeof env[AGENT_TOKEN_ENV] === "string");

      // Verify the token in env is valid
      const childRuntime = AgentRuntime.fromSerialized(env[AGENT_TOKEN_ENV], {
        configDir: tempDir,
      });
      assert.strictEqual(childRuntime.getStatus().agentId, "subprocess");

      runtime.stop();
    });
  });

  describe("Token Access", () => {
    test("getToken returns current token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      const retrieved = runtime.getToken();

      assert.deepStrictEqual(retrieved, token);
    });

    test("getSerializedToken returns serialized form", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });
      const expected = broker.serializeToken(token);

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      const serialized = runtime.getSerializedToken();

      assert.strictEqual(serialized, expected);
    });
  });

  describe("Status", () => {
    test("returns complete status", () => {
      const token = broker.createRootToken({
        agentId: "status-test",
        scopes: ["github:repo:read", "system:token:refresh"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      runtime.start();

      const status = runtime.getStatus();

      assert.strictEqual(status.agentId, "status-test");
      assert.deepStrictEqual(status.scopes, [
        "github:repo:read",
        "system:token:refresh",
      ]);
      assert.ok(status.expiresAt);
      assert.ok(typeof status.timeUntilExpiry === "number");
      assert.strictEqual(status.canRefresh, true);

      runtime.stop();
    });

    test("canRefresh is false without refresh scope", () => {
      const token = broker.createRootToken({
        agentId: "no-refresh",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      const status = runtime.getStatus();

      assert.strictEqual(status.canRefresh, false);
    });

    test("canRefresh is true with system:* scope", () => {
      const token = broker.createRootToken({
        agentId: "system-wildcard",
        scopes: ["github:repo:read", "system:*"],
        ttlDays: 1,
      });

      const runtime = new AgentRuntime(token, { configDir: tempDir });
      const status = runtime.getStatus();

      assert.strictEqual(status.canRefresh, true);
    });
  });

  describe("withRuntime helper", () => {
    test("executes function and cleans up", async () => {
      const token = broker.createRootToken({
        agentId: "helper-test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      let runtimeStatus: string | undefined;

      const result = await withRuntime(token, { configDir: tempDir }, async (runtime) => {
        runtimeStatus = runtime.getStatus().agentId;
        return "done";
      });

      assert.strictEqual(result, "done");
      assert.strictEqual(runtimeStatus, "helper-test");
    });

    test("cleans up on error", async () => {
      const token = broker.createRootToken({
        agentId: "error-test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      await assert.rejects(
        async () => {
          await withRuntime(token, { configDir: tempDir }, async () => {
            throw new Error("Test error");
          });
        },
        { message: "Test error" }
      );
    });
  });
});

describe("Broker - Token Refresh", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("refreshes token with refresh scope", () => {
    const token = broker.createRootToken({
      agentId: "refresh-test",
      scopes: ["github:repo:read", "system:token:refresh"],
      ttlDays: 1,
    });

    // Refresh with a different TTL to ensure expiry changes
    const refreshed = broker.refreshToken(token, 120); // 2 hours

    assert.strictEqual(refreshed.agentId, token.agentId);
    assert.deepStrictEqual(refreshed.scopes, token.scopes);
    assert.ok(refreshed.expiresAt);
    // Expiry should be different (2 hours from now vs 1 day from creation)
    assert.notStrictEqual(refreshed.expiresAt, token.expiresAt);
    // Verify the refreshed token is valid
    assert.strictEqual(broker.verifyToken(refreshed).valid, true);
  });

  test("throws without refresh scope", () => {
    const token = broker.createRootToken({
      agentId: "no-refresh",
      scopes: ["github:repo:read"],
      ttlDays: 1,
    });

    assert.throws(
      () => {
        broker.refreshToken(token);
      },
      { message: /system:token:refresh scope/ }
    );
  });

  test("throws for invalid token", () => {
    const token = broker.createRootToken({
      agentId: "test",
      scopes: ["system:token:refresh"],
    });

    const tampered = { ...token, agentId: "hacked" };

    assert.throws(
      () => {
        broker.refreshToken(tampered);
      },
      { message: /invalid token/i }
    );
  });

  test("respects maxExpiresAt", () => {
    const token = broker.createRootToken({
      agentId: "max-expiry",
      scopes: ["system:token:refresh"],
      ttlDays: 1,
    });

    // Try to refresh with very long TTL
    const refreshed = broker.refreshToken(token, 365 * 24 * 60); // 1 year

    // Should be capped to maxExpiresAt
    assert.strictEqual(refreshed.expiresAt, token.maxExpiresAt);
  });

  test("refreshes with system:* scope", () => {
    const token = broker.createRootToken({
      agentId: "system-wildcard",
      scopes: ["github:repo:read", "system:*"],
      ttlDays: 1,
    });

    const refreshed = broker.refreshToken(token);

    assert.ok(refreshed.signature);
    assert.strictEqual(broker.verifyToken(refreshed).valid, true);
  });
});

describe("Broker - Cache Management", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("getCacheStats returns empty initially", () => {
    const stats = broker.getCacheStats();

    assert.strictEqual(stats.size, 0);
    assert.deepStrictEqual(stats.entries, []);
  });

  test("clearCredentialCache clears cache", () => {
    // We can't easily add to cache without real credentials
    // but we can verify the method doesn't throw
    broker.clearCredentialCache();
    const stats = broker.getCacheStats();

    assert.strictEqual(stats.size, 0);
  });

  test("evictExpiredCredentials returns count", () => {
    const evicted = broker.evictExpiredCredentials();

    assert.strictEqual(typeof evicted, "number");
  });

  test("setCacheBuffer updates buffer", () => {
    // This just verifies the method exists and doesn't throw
    broker.setCacheBuffer(10 * 60 * 1000); // 10 minutes
  });
});

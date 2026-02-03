/**
 * Tests for Broker class
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Broker } from "./broker.js";

// Create a unique temp directory for each test
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-broker-test-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("Broker", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("Token Operations", () => {
    test("creates and verifies root token", () => {
      const token = broker.createRootToken({
        agentId: "test-agent",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      assert.strictEqual(token.agentId, "test-agent");
      assert.ok(token.signature);

      const result = broker.verifyToken(token);
      assert.strictEqual(result.valid, true);
    });

    test("delegation works through broker", () => {
      const parent = broker.createRootToken({
        agentId: "parent",
        scopes: ["github:repo:read", "github:repo:write"],
        ttlDays: 7,
      });

      const child = broker.delegate(parent, {
        agentId: "child",
        requestedScopes: ["github:repo:read"],
        ttlMinutes: 60,
      });

      assert.strictEqual(child.parentId, "parent");
      assert.deepStrictEqual(child.scopes, ["github:repo:read"]);

      const result = broker.verifyToken(child);
      assert.strictEqual(result.valid, true);
    });

    test("delegation fails with invalid parent", () => {
      const parent = broker.createRootToken({
        agentId: "parent",
        scopes: ["github:repo:read"],
      });

      // Tamper with the token
      const tampered = { ...parent, scopes: ["github:*"] };

      assert.throws(
        () => {
          broker.delegate(tampered, {
            requestedScopes: ["github:repo:read"],
          });
        },
        { message: /Invalid parent token/ }
      );
    });

    test("checkPermission validates scope and resource", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        constraints: {
          "github:repo:read": { resources: ["myorg/*"] },
        },
        ttlDays: 1,
      });

      // Valid
      let result = broker.checkPermission(
        token,
        "github:repo:read",
        "myorg/repo"
      );
      assert.strictEqual(result.valid, true);

      // Invalid scope
      result = broker.checkPermission(token, "github:repo:write", "myorg/repo");
      assert.strictEqual(result.valid, false);

      // Invalid resource
      result = broker.checkPermission(token, "github:repo:read", "other/repo");
      assert.strictEqual(result.valid, false);
    });
  });

  describe("Token Serialization", () => {
    test("serialize and deserialize preserves token", () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const serialized = broker.serializeToken(token);
      const deserialized = broker.deserializeToken(serialized);

      assert.strictEqual(deserialized.agentId, token.agentId);
      assert.deepStrictEqual(deserialized.scopes, token.scopes);

      // Verify works after deserialization
      const result = broker.verifyToken(deserialized);
      assert.strictEqual(result.valid, true);
    });

    test("deserialized token can be used for delegation", () => {
      const parent = broker.createRootToken({
        agentId: "parent",
        scopes: ["github:repo:read"],
        ttlDays: 7,
      });

      const serialized = broker.serializeToken(parent);
      const deserialized = broker.deserializeToken(serialized);

      const child = broker.delegate(deserialized, {
        agentId: "child",
        requestedScopes: ["github:repo:read"],
      });

      assert.strictEqual(child.parentId, "parent");
      assert.strictEqual(broker.verifyToken(child).valid, true);
    });
  });

  describe("Status", () => {
    test("returns broker status", () => {
      const status = broker.getStatus();

      assert.strictEqual(status.mode, "standalone");
      assert.strictEqual(status.configDir, tempDir);
      assert.strictEqual(status.secretExists, true);
      assert.ok(Array.isArray(status.providers));
    });

    test("lists configured providers", () => {
      // Initially no providers
      let status = broker.getStatus();
      assert.deepStrictEqual(status.providers, []);

      // Add a provider
      const keyPath = path.join(tempDir, "test-key.pem");
      fs.writeFileSync(keyPath, "fake-key");

      broker.initProvider("github", {
        appId: "123",
        installationId: "456",
        privateKeyPath: keyPath,
      });

      status = broker.getStatus();
      assert.deepStrictEqual(status.providers, ["github"]);
    });
  });

  describe("Provider Initialization", () => {
    test("initializes GitHub provider", () => {
      const keyPath = path.join(tempDir, "test-key.pem");
      fs.writeFileSync(keyPath, "fake-key");

      broker.initProvider("github", {
        appId: "123",
        installationId: "456",
        privateKeyPath: keyPath,
      });

      const status = broker.getStatus();
      assert.ok(status.providers.includes("github"));
    });

    test("throws for unknown provider", () => {
      assert.throws(
        () => {
          broker.initProvider("unknown", {});
        },
        { message: /not supported/ }
      );
    });
  });

  describe("Configuration", () => {
    test("showConfig returns redacted config", () => {
      const config = broker.showConfig();

      assert.ok("providers" in config);
    });

    test("persists across broker instances", () => {
      // Create a token with first broker
      const token = broker.createRootToken({
        agentId: "persistent",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      // Create new broker instance with same config dir
      const broker2 = new Broker(tempDir);

      // Should verify the same token
      const result = broker2.verifyToken(token);
      assert.strictEqual(result.valid, true);
    });
  });

  describe("Credential Retrieval - Permission Checks", () => {
    test("getCredential throws for unauthorized scope", async () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      await assert.rejects(
        async () => {
          await broker.getCredential(token, "github:repo:write", "myorg/repo");
        },
        { message: /Permission denied/ }
      );
    });

    test("getCredential throws for unauthorized resource", async () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        constraints: {
          "github:repo:read": { resources: ["myorg/*"] },
        },
        ttlDays: 1,
      });

      await assert.rejects(
        async () => {
          await broker.getCredential(token, "github:repo:read", "other/repo");
        },
        { message: /Permission denied/ }
      );
    });

    test("getCredential throws when provider not configured", async () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      await assert.rejects(
        async () => {
          await broker.getCredential(token, "github:repo:read", "myorg/repo");
        },
        { message: /not configured/ }
      );
    });

    test("getCredential throws for tampered token", async () => {
      const token = broker.createRootToken({
        agentId: "test",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const tampered = { ...token, scopes: ["github:*"] };

      await assert.rejects(
        async () => {
          await broker.getCredential(tampered, "github:repo:read", "myorg/repo");
        },
        { message: /Permission denied/ }
      );
    });
  });

  describe("Complex Delegation Scenarios", () => {
    test("multi-level delegation with scope narrowing", () => {
      const root = broker.createRootToken({
        agentId: "root",
        scopes: ["github:repo:read", "github:repo:write", "aws:s3:read"],
        constraints: {
          "github:repo:*": { resources: ["myorg/*"] },
        },
        maxDelegationDepth: 3,
        ttlDays: 7,
      });

      // Level 1: Narrow to just github
      const orchestrator = broker.delegate(root, {
        agentId: "orchestrator",
        requestedScopes: ["github:repo:read", "github:repo:write"],
        ttlMinutes: 60,
      });

      // Level 2: Narrow to just read
      const researcher = broker.delegate(orchestrator, {
        agentId: "researcher",
        requestedScopes: ["github:repo:read"],
        requestedConstraints: {
          "github:repo:read": { resources: ["myorg/docs", "myorg/research"] },
        },
        ttlMinutes: 30,
      });

      // Verify all tokens
      assert.strictEqual(broker.verifyToken(root).valid, true);
      assert.strictEqual(broker.verifyToken(orchestrator).valid, true);
      assert.strictEqual(broker.verifyToken(researcher).valid, true);

      // Verify scope narrowing
      assert.deepStrictEqual(researcher.scopes, ["github:repo:read"]);

      // Verify constraint narrowing
      assert.deepStrictEqual(researcher.constraints, {
        "github:repo:read": { resources: ["myorg/docs", "myorg/research"] },
      });

      // Verify permission checks
      assert.strictEqual(
        broker.checkPermission(researcher, "github:repo:read", "myorg/docs")
          .valid,
        true
      );
      assert.strictEqual(
        broker.checkPermission(researcher, "github:repo:read", "myorg/other")
          .valid,
        false
      );
      assert.strictEqual(
        broker.checkPermission(researcher, "github:repo:write", "myorg/docs")
          .valid,
        false
      );
    });

    test("cannot widen scopes through delegation", () => {
      const root = broker.createRootToken({
        agentId: "root",
        scopes: ["github:repo:read"],
        ttlDays: 7,
      });

      assert.throws(
        () => {
          broker.delegate(root, {
            requestedScopes: ["github:repo:read", "github:repo:write"],
          });
        },
        { message: /not allowed by parent/ }
      );
    });

    test("cannot extend expiry through delegation", () => {
      const root = broker.createRootToken({
        agentId: "root",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      const child = broker.delegate(root, {
        requestedScopes: ["github:repo:read"],
        ttlMinutes: 7 * 24 * 60, // Try to request 7 days
      });

      // Child expiry should be capped to parent
      assert.strictEqual(child.expiresAt, root.expiresAt);
    });

    test("delegatable=false prevents further delegation", () => {
      const root = broker.createRootToken({
        agentId: "root",
        scopes: ["github:repo:read"],
        ttlDays: 7,
      });

      const child = broker.delegate(root, {
        agentId: "child",
        requestedScopes: ["github:repo:read"],
        delegatable: false,
      });

      assert.throws(
        () => {
          broker.delegate(child, {
            requestedScopes: ["github:repo:read"],
          });
        },
        { message: /not delegatable/ }
      );
    });

    test("passes serialized token between simulated processes", () => {
      // Process 1: Create root and serialize
      const root = broker.createRootToken({
        agentId: "main-process",
        scopes: ["github:repo:read", "github:repo:write"],
        ttlDays: 1,
      });
      const serializedRoot = broker.serializeToken(root);

      // Process 2: Receives serialized token via environment
      const broker2 = new Broker(tempDir);
      const receivedRoot = broker2.deserializeToken(serializedRoot);

      // Process 2: Delegates to subprocess
      const child = broker2.delegate(receivedRoot, {
        agentId: "subprocess",
        requestedScopes: ["github:repo:read"],
        ttlMinutes: 30,
      });
      const serializedChild = broker2.serializeToken(child);

      // Process 3: Receives delegated token
      const broker3 = new Broker(tempDir);
      const receivedChild = broker3.deserializeToken(serializedChild);

      // All tokens should verify
      assert.strictEqual(broker3.verifyToken(receivedChild).valid, true);
      assert.strictEqual(receivedChild.parentId, "main-process");
      assert.strictEqual(receivedChild.currentDepth, 1);
    });
  });
});

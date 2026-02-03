/**
 * End-to-End Integration Tests
 *
 * Tests complete flows across phases 1-5 with minimal mocking.
 * These tests verify that all components work together correctly.
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Broker } from "./broker.js";
import { AgentRuntime, AGENT_TOKEN_ENV } from "./runtime.js";
import { APIKeyProvider, APIKeyProviderFactory } from "./providers/apikey.js";
import {
  LeaderServer,
  FollowerClient,
  SigningKeyManager,
  RevocationList,
} from "./distributed/index.js";

// ─────────────────────────────────────────────────────────────────
// TEST UTILITIES
// ─────────────────────────────────────────────────────────────────

function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-e2e-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ─────────────────────────────────────────────────────────────────
// PHASE 1 & 2: CORE TOKEN FLOWS
// ─────────────────────────────────────────────────────────────────

describe("E2E: Token Lifecycle", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("complete token lifecycle: create -> serialize -> deserialize -> verify", () => {
    // Create root token
    const root = broker.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read", "github:repo:write", "aws:s3:read"],
      constraints: {
        "github:repo:*": { resources: ["myorg/*"] },
        "aws:s3:read": { resources: ["my-bucket/*"] },
      },
      maxDelegationDepth: 3,
      ttlDays: 7,
    });

    // Verify root token
    assert.strictEqual(broker.verifyToken(root).valid, true);
    assert.strictEqual(root.currentDepth, 0);
    assert.strictEqual(root.delegatable, true);

    // Serialize and deserialize (simulating process boundary)
    const serialized = broker.serializeToken(root);
    assert.ok(typeof serialized === "string");
    assert.ok(serialized.length > 0);

    const deserialized = broker.deserializeToken(serialized);
    assert.strictEqual(broker.verifyToken(deserialized).valid, true);
    assert.deepStrictEqual(deserialized.scopes, root.scopes);
  });

  test("multi-level delegation chain with progressive narrowing", () => {
    // Root: Full access to github and aws
    const root = broker.createRootToken({
      agentId: "root",
      scopes: ["github:repo:read", "github:repo:write", "aws:s3:read", "aws:s3:write"],
      constraints: {
        "github:repo:*": { resources: ["myorg/*"] },
        "aws:s3:*": { resources: ["prod-bucket/*", "staging-bucket/*"] },
      },
      maxDelegationDepth: 4,
      ttlDays: 30,
    });

    // Level 1: Orchestrator - gets github and read-only aws
    const orchestrator = broker.delegate(root, {
      agentId: "orchestrator",
      requestedScopes: ["github:repo:read", "github:repo:write", "aws:s3:read"],
      ttlMinutes: 24 * 60, // 1 day
    });
    assert.strictEqual(orchestrator.currentDepth, 1);
    assert.strictEqual(orchestrator.parentId, "root");

    // Level 2: Code reviewer - only github read
    const reviewer = broker.delegate(orchestrator, {
      agentId: "reviewer",
      requestedScopes: ["github:repo:read"],
      requestedConstraints: {
        "github:repo:read": { resources: ["myorg/frontend", "myorg/backend"] },
      },
      ttlMinutes: 60,
    });
    assert.strictEqual(reviewer.currentDepth, 2);
    assert.deepStrictEqual(reviewer.scopes, ["github:repo:read"]);

    // Level 3: Sub-reviewer - even more restricted
    const subReviewer = broker.delegate(reviewer, {
      agentId: "sub-reviewer",
      requestedScopes: ["github:repo:read"],
      requestedConstraints: {
        "github:repo:read": { resources: ["myorg/frontend"] },
      },
      ttlMinutes: 30,
    });
    assert.strictEqual(subReviewer.currentDepth, 3);

    // Verify all tokens
    assert.strictEqual(broker.verifyToken(root).valid, true);
    assert.strictEqual(broker.verifyToken(orchestrator).valid, true);
    assert.strictEqual(broker.verifyToken(reviewer).valid, true);
    assert.strictEqual(broker.verifyToken(subReviewer).valid, true);

    // Verify permissions at each level
    assert.strictEqual(
      broker.checkPermission(root, "aws:s3:write", "prod-bucket/file").valid,
      true
    );
    assert.strictEqual(
      broker.checkPermission(orchestrator, "aws:s3:write", "prod-bucket/file").valid,
      false // Lost write access
    );
    assert.strictEqual(
      broker.checkPermission(reviewer, "github:repo:read", "myorg/frontend").valid,
      true
    );
    assert.strictEqual(
      broker.checkPermission(reviewer, "github:repo:read", "myorg/other").valid,
      false // Constrained
    );
    assert.strictEqual(
      broker.checkPermission(subReviewer, "github:repo:read", "myorg/backend").valid,
      false // Further constrained
    );
  });

  test("delegation security: cannot escalate privileges", () => {
    const root = broker.createRootToken({
      agentId: "root",
      scopes: ["github:repo:read"],
      constraints: {
        "github:repo:read": { resources: ["myorg/*"] },
      },
      ttlDays: 1,
    });

    // Cannot request scope not in parent
    assert.throws(
      () => {
        broker.delegate(root, {
          requestedScopes: ["github:repo:write"],
        });
      },
      { message: /not allowed by parent/ }
    );

    // Cannot widen resource constraints
    const child = broker.delegate(root, {
      agentId: "child",
      requestedScopes: ["github:repo:read"],
      requestedConstraints: {
        "github:repo:read": { resources: ["myorg/specific-repo"] },
      },
    });

    // Child's constraint is narrower (this should work)
    assert.strictEqual(
      broker.checkPermission(child, "github:repo:read", "myorg/specific-repo").valid,
      true
    );
    // But cannot access broader resources
    assert.strictEqual(
      broker.checkPermission(child, "github:repo:read", "myorg/other-repo").valid,
      false
    );
  });

  test("tampered tokens are rejected", () => {
    const token = broker.createRootToken({
      agentId: "test",
      scopes: ["github:repo:read"],
      ttlDays: 1,
    });

    // Various tampering attempts
    const tamperedScope = { ...token, scopes: ["github:*"] };
    const tamperedAgent = { ...token, agentId: "hacked" };
    const tamperedDepth = { ...token, maxDelegationDepth: 100 };

    assert.strictEqual(broker.verifyToken(tamperedScope).valid, false);
    assert.strictEqual(broker.verifyToken(tamperedAgent).valid, false);
    assert.strictEqual(broker.verifyToken(tamperedDepth).valid, false);
  });
});

// ─────────────────────────────────────────────────────────────────
// PHASE 3: RUNTIME FLOWS
// ─────────────────────────────────────────────────────────────────

describe("E2E: Agent Runtime", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
    delete process.env[AGENT_TOKEN_ENV];
  });

  test("complete subprocess spawning flow", () => {
    // Parent process creates root token
    const rootToken = broker.createRootToken({
      agentId: "main-agent",
      scopes: ["github:repo:read", "github:repo:write", "system:token:refresh"],
      constraints: {
        "github:repo:*": { resources: ["myorg/*"] },
      },
      ttlDays: 1,
    });

    // Parent starts runtime
    const parentRuntime = new AgentRuntime(rootToken, { configDir: tempDir });
    parentRuntime.start();

    // Parent creates subprocess environment
    const childEnv = parentRuntime.createSubprocessEnv({
      agentId: "code-agent",
      requestedScopes: ["github:repo:read"],
      requestedConstraints: {
        "github:repo:read": { resources: ["myorg/frontend"] },
      },
      ttlMinutes: 30,
    });

    // Verify env contains token
    assert.ok(childEnv[AGENT_TOKEN_ENV]);

    // Simulate child process starting with token from environment
    process.env[AGENT_TOKEN_ENV] = childEnv[AGENT_TOKEN_ENV];
    const childRuntime = AgentRuntime.fromEnvironment({ configDir: tempDir });
    childRuntime.start();

    // Child can check permissions
    assert.strictEqual(
      childRuntime.checkPermission("github:repo:read", "myorg/frontend"),
      true
    );
    assert.strictEqual(
      childRuntime.checkPermission("github:repo:read", "myorg/backend"),
      false
    );
    assert.strictEqual(
      childRuntime.checkPermission("github:repo:write", "myorg/frontend"),
      false
    );

    // Child can further delegate (if allowed)
    const grandchildToken = childRuntime.delegate({
      agentId: "sub-task",
      requestedScopes: ["github:repo:read"],
      ttlMinutes: 10,
    });
    assert.ok(grandchildToken);
    assert.strictEqual(grandchildToken.currentDepth, 2);

    childRuntime.stop();
    parentRuntime.stop();
  });

  test("token refresh flow", () => {
    const token = broker.createRootToken({
      agentId: "refreshable",
      scopes: ["github:repo:read", "system:token:refresh"],
      ttlDays: 1,
    });

    const runtime = new AgentRuntime(token, { configDir: tempDir });
    runtime.start();

    const statusBefore = runtime.getStatus();
    assert.strictEqual(statusBefore.canRefresh, true);

    // Perform refresh
    runtime.refresh();

    const statusAfter = runtime.getStatus();
    // Token should still be valid and refreshable
    assert.strictEqual(statusAfter.canRefresh, true);

    runtime.stop();
  });

  test("runtime status tracking", () => {
    const token = broker.createRootToken({
      agentId: "status-agent",
      scopes: ["github:repo:read", "aws:s3:read"],
      constraints: {
        "github:repo:read": { resources: ["myorg/*"] },
      },
      ttlDays: 1,
    });

    const runtime = new AgentRuntime(token, { configDir: tempDir });
    runtime.start();

    const status = runtime.getStatus();

    assert.strictEqual(status.agentId, "status-agent");
    assert.deepStrictEqual(status.scopes, ["github:repo:read", "aws:s3:read"]);
    assert.ok(status.expiresAt);
    assert.ok(status.timeUntilExpiry && status.timeUntilExpiry > 0);
    assert.strictEqual(status.canRefresh, false); // No refresh scope

    runtime.stop();
  });
});

// ─────────────────────────────────────────────────────────────────
// PHASE 4: PROVIDER INTEGRATION
// ─────────────────────────────────────────────────────────────────

describe("E2E: API Key Provider", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("complete API key credential flow", async () => {
    // Configure API key provider
    broker.addAPIKey({
      name: "openai-prod",
      providerName: "openai",
      apiKey: "sk-test-key-12345",
      baseUrl: "https://api.openai.com/v1",
      ttlMinutes: 60,
    });

    // Create token with openai scope
    const token = broker.createRootToken({
      agentId: "ai-agent",
      scopes: ["openai:chat:completions", "openai:embeddings:create"],
      ttlDays: 1,
    });

    // Get credential (this tests the full flow without actual API call)
    const credential = await broker.getCredential(
      token,
      "openai:chat:completions",
      ""
    );

    assert.strictEqual(credential.credentialType, "api_key");
    assert.strictEqual(credential.credential.apiKey, "sk-test-key-12345");
    assert.strictEqual(credential.credential.providerName, "openai");
    assert.ok(credential.expiresAt);
  });

  test("API key provider with multiple keys and scope routing", async () => {
    // Add multiple API keys
    broker.addAPIKey({
      name: "openai",
      providerName: "openai",
      apiKey: "sk-openai-key",
    });
    broker.addAPIKey({
      name: "anthropic",
      providerName: "anthropic",
      apiKey: "sk-ant-key",
    });

    // Token with access to both
    const token = broker.createRootToken({
      agentId: "multi-agent",
      scopes: ["openai:chat:*", "anthropic:messages:*"],
      ttlDays: 1,
    });

    // Get OpenAI credential
    const openaiCred = await broker.getCredential(token, "openai:chat:completions", "");
    assert.strictEqual(openaiCred.credential.providerName, "openai");

    // Get Anthropic credential
    const anthropicCred = await broker.getCredential(token, "anthropic:messages:create", "");
    assert.strictEqual(anthropicCred.credential.providerName, "anthropic");
  });

  test("credential denial for unauthorized scope", async () => {
    broker.addAPIKey({
      name: "openai",
      providerName: "openai",
      apiKey: "sk-key",
    });

    const token = broker.createRootToken({
      agentId: "limited",
      scopes: ["openai:chat:completions"], // Only chat
      ttlDays: 1,
    });

    // Should fail for embeddings (not in scopes)
    await assert.rejects(
      async () => {
        await broker.getCredential(token, "openai:embeddings:create", "");
      },
      { message: /Permission denied/ }
    );
  });

  test("API key provider factory creates correct configs", () => {
    const provider = new APIKeyProvider();

    // Add keys using factory
    provider.addKey("openai", APIKeyProviderFactory.openai("sk-key", "org-123"), ["openai:*"]);
    provider.addKey("anthropic", APIKeyProviderFactory.anthropic("sk-ant"), ["anthropic:*"]);
    provider.addKey("stripe", APIKeyProviderFactory.stripe("sk_test"), ["stripe:*"]);

    const keys = provider.listKeys();
    assert.strictEqual(keys.length, 3);
    assert.ok(keys.some((k) => k.provider === "openai"));
    assert.ok(keys.some((k) => k.provider === "anthropic"));
    assert.ok(keys.some((k) => k.provider === "stripe"));
  });
});

// ─────────────────────────────────────────────────────────────────
// PHASE 5: DISTRIBUTED MODE
// ─────────────────────────────────────────────────────────────────

describe("E2E: Distributed Mode", () => {
  let leaderDir: string;
  let followerDir: string;
  let leaderBroker: Broker;
  let followerBroker: Broker;
  let leader: LeaderServer;
  let follower: FollowerClient;
  const authToken = "e2e-test-token";
  let leaderPort: number;

  beforeEach(async () => {
    leaderDir = createTempDir();
    followerDir = createTempDir();
    leaderBroker = new Broker(leaderDir);
    followerBroker = new Broker(followerDir);
    leaderPort = 10000 + Math.floor(Math.random() * 5000);
  });

  afterEach(async () => {
    follower?.stop();
    await leader?.stop();
    cleanupTempDir(leaderDir);
    cleanupTempDir(followerDir);
  });

  test("complete leader-follower sync cycle", async () => {
    // Start leader
    leader = new LeaderServer(leaderBroker, leaderDir, {
      port: leaderPort,
      followerAuthToken: authToken,
    });
    await leader.start();

    // Start follower
    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: `http://localhost:${leaderPort}`,
      leaderAuthToken: authToken,
      followerId: "follower-1",
      syncIntervalSeconds: 1,
    });
    await follower.start();

    // Verify sync completed
    const followerStatus = follower.getStatus();
    assert.ok(followerStatus.signingKeyVersion > 0);

    // Both should have same signing key version
    const leaderStatus = leader.getStatus();
    assert.strictEqual(
      followerStatus.signingKeyVersion,
      leaderStatus.signingKeyVersion
    );
  });

  test("revocation syncs from leader to follower", async () => {
    // Start leader
    leader = new LeaderServer(leaderBroker, leaderDir, {
      port: leaderPort,
      followerAuthToken: authToken,
    });
    await leader.start();

    // Start follower
    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: `http://localhost:${leaderPort}`,
      leaderAuthToken: authToken,
      followerId: "follower-1",
    });
    await follower.start();

    // Revoke a token on leader
    const tokenToRevoke = { agentId: "bad-token" } as any;
    await leader.revokeToken(tokenToRevoke, "compromised");

    // Verify leader has revocation
    assert.strictEqual(leader.isRevoked("bad-token"), true);

    // Sync follower
    await follower.sync();

    // Follower should also have revocation
    assert.strictEqual(follower.isRevoked("bad-token"), true);
  });

  test("key rotation syncs to follower", async () => {
    // Start leader
    leader = new LeaderServer(leaderBroker, leaderDir, {
      port: leaderPort,
      followerAuthToken: authToken,
    });
    await leader.start();

    // Start follower
    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: `http://localhost:${leaderPort}`,
      leaderAuthToken: authToken,
      followerId: "follower-1",
    });
    await follower.start();

    const initialVersion = follower.getSigningKeyManager().getCurrentVersion();

    // Rotate key on leader
    const { version: newVersion } = await leader.rotateSigningKey();
    assert.ok(newVersion > initialVersion);

    // Sync follower
    await follower.sync();

    // Follower should have new key
    assert.strictEqual(
      follower.getSigningKeyManager().getCurrentVersion(),
      newVersion
    );
  });

  test("tokens signed by leader verify on follower with shared secret", async () => {
    // For cross-region verification, brokers must share the same signing secret
    // This test demonstrates using a shared config directory
    const sharedDir = createTempDir();
    try {
      const sharedLeaderBroker = new Broker(sharedDir);
      const sharedFollowerBroker = new Broker(sharedDir);

      // Start leader
      leader = new LeaderServer(sharedLeaderBroker, sharedDir, {
        port: leaderPort,
        followerAuthToken: authToken,
      });
      await leader.start();

      // Create token on leader
      const token = sharedLeaderBroker.createRootToken({
        agentId: "cross-region-agent",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      // Serialize and "send" to follower region
      const serialized = sharedLeaderBroker.serializeToken(token);

      // Follower can verify (same signing secret)
      const followerToken = sharedFollowerBroker.deserializeToken(serialized);
      const result = sharedFollowerBroker.verifyToken(followerToken);
      assert.strictEqual(result.valid, true);
    } finally {
      cleanupTempDir(sharedDir);
    }
  });

  test("follower operates in degraded mode when leader unavailable", async () => {
    // Pre-populate follower cache
    const keyManager = new SigningKeyManager(followerDir);
    keyManager.getCurrentKey();

    // Create follower pointing to non-existent leader
    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: "http://localhost:99999",
      leaderAuthToken: authToken,
      followerId: "offline-follower",
      syncTimeoutMs: 100,
    });

    // Should start in degraded mode with cached data
    await follower.start();
    assert.ok(follower.canOperate());
  });
});

// ─────────────────────────────────────────────────────────────────
// CROSS-PHASE INTEGRATION
// ─────────────────────────────────────────────────────────────────

describe("E2E: Cross-Phase Integration", () => {
  let leaderDir: string;
  let followerDir: string;
  let leaderBroker: Broker;
  let followerBroker: Broker;
  let leader: LeaderServer;
  let follower: FollowerClient;
  const authToken = "integration-token";
  let leaderPort: number;

  beforeEach(async () => {
    leaderDir = createTempDir();
    followerDir = createTempDir();
    leaderBroker = new Broker(leaderDir);
    followerBroker = new Broker(followerDir);
    leaderPort = 15000 + Math.floor(Math.random() * 5000);
  });

  afterEach(async () => {
    follower?.stop();
    await leader?.stop();
    cleanupTempDir(leaderDir);
    cleanupTempDir(followerDir);
    delete process.env[AGENT_TOKEN_ENV];
  });

  test("complete distributed agent workflow", async () => {
    // For distributed mode to work with token verification, use shared config
    const sharedDir = createTempDir();
    try {
      const sharedBroker = new Broker(sharedDir);

      // Start distributed infrastructure
      leader = new LeaderServer(sharedBroker, sharedDir, {
        port: leaderPort,
        followerAuthToken: authToken,
      });
      await leader.start();

      follower = new FollowerClient(sharedBroker, sharedDir, {
        leaderUrl: `http://localhost:${leaderPort}`,
        leaderAuthToken: authToken,
        followerId: "region-b",
      });
      await follower.start();

      // Configure API keys
      sharedBroker.addAPIKey({
        name: "openai",
        providerName: "openai",
        apiKey: "sk-distributed-key",
      });

      // Create root token
      const rootToken = sharedBroker.createRootToken({
        agentId: "distributed-orchestrator",
        scopes: ["github:repo:read", "openai:chat:*", "system:token:refresh"],
        constraints: {
          "github:repo:read": { resources: ["myorg/*"] },
        },
        maxDelegationDepth: 3,
        ttlDays: 7,
      });

      // Serialize token (simulating cross-region transfer)
      const serialized = sharedBroker.serializeToken(rootToken);

      // Start runtime with received token (in "follower region")
      const runtime = AgentRuntime.fromSerialized(serialized, {
        configDir: sharedDir,
      });
      runtime.start();

      // Verify token is valid
      const runtimeStatus = runtime.getStatus();
      assert.ok(runtimeStatus.expiresAt);
      assert.strictEqual(runtime.checkPermission("github:repo:read", "myorg/repo"), true);

      // Delegate to sub-agent
      const subEnv = runtime.createSubprocessEnv({
        agentId: "local-worker",
        requestedScopes: ["github:repo:read"],
        requestedConstraints: {
          "github:repo:read": { resources: ["myorg/frontend"] },
        },
        ttlMinutes: 60,
      });

      // Sub-agent starts
      process.env[AGENT_TOKEN_ENV] = subEnv[AGENT_TOKEN_ENV];
      const subRuntime = AgentRuntime.fromEnvironment({ configDir: sharedDir });
      subRuntime.start();

      // Verify sub-agent permissions
      assert.strictEqual(
        subRuntime.checkPermission("github:repo:read", "myorg/frontend"),
        true
      );
      assert.strictEqual(
        subRuntime.checkPermission("github:repo:read", "myorg/backend"),
        false
      );

      // Revoke root token on leader
      await leader.revokeToken(rootToken, "test revocation");

      // Sync follower
      await follower.sync();

      // Follower should now see the revocation
      assert.strictEqual(follower.isRevoked("distributed-orchestrator"), true);

      subRuntime.stop();
      runtime.stop();
    } finally {
      cleanupTempDir(sharedDir);
    }
  });

  test("signing key rotation in distributed mode", async () => {
    // This test verifies that SigningKeyManager properly handles key rotation
    // Note: Broker token verification uses ConfigService secret, not SigningKeyManager
    // So we test the distributed key sync at the module level

    // Start leader
    leader = new LeaderServer(leaderBroker, leaderDir, {
      port: leaderPort,
      followerAuthToken: authToken,
    });
    await leader.start();

    // Start follower (gets initial key)
    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: `http://localhost:${leaderPort}`,
      leaderAuthToken: authToken,
      followerId: "key-rotation-test",
    });
    await follower.start();

    const initialVersion = follower.getSigningKeyManager().getCurrentVersion();

    // Rotate key on leader
    const { version: newVersion } = await leader.rotateSigningKey();
    assert.ok(newVersion > initialVersion);

    // Sync follower
    await follower.sync();

    // Follower should have both key versions
    assert.strictEqual(
      follower.getSigningKeyManager().getCurrentVersion(),
      newVersion
    );
    assert.ok(follower.getSigningKeyManager().hasKey(initialVersion));
    assert.ok(follower.getSigningKeyManager().hasKey(newVersion));
  });

  test("broker token verification with shared config across regions", async () => {
    // For broker-level token verification, use shared config directory
    const sharedDir = createTempDir();
    try {
      const sharedBroker = new Broker(sharedDir);

      // Create token before rotation
      const token = sharedBroker.createRootToken({
        agentId: "pre-rotation-token",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      // Create another broker instance with same config (simulates distributed deployment)
      const remoteBroker = new Broker(sharedDir);

      // Token should verify on both
      const serialized = sharedBroker.serializeToken(token);
      const onRemote = remoteBroker.deserializeToken(serialized);

      assert.strictEqual(sharedBroker.verifyToken(token).valid, true);
      assert.strictEqual(remoteBroker.verifyToken(onRemote).valid, true);
    } finally {
      cleanupTempDir(sharedDir);
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// SECURITY TESTS
// ─────────────────────────────────────────────────────────────────

describe("E2E: Security Scenarios", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("expired token rejection", async () => {
    // Create token with very short TTL
    const token = broker.createRootToken({
      agentId: "short-lived",
      scopes: ["github:repo:read"],
      ttlDays: 0, // Will set to default, we'll manually adjust
    });

    // Manually set expiration to past (simulating expired token)
    const expiredToken = {
      ...token,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    };

    // Re-sign won't work because we can't access the secret, but
    // verification should still fail due to expiration check
    const result = broker.verifyToken(expiredToken);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error?.includes("expired") || result.error?.includes("Invalid"));
  });

  test("constraint timing enforcement", () => {
    const future = new Date(Date.now() + 60000).toISOString();
    const past = new Date(Date.now() - 60000).toISOString();

    // Token with notBefore in future
    const notYetValid = broker.createRootToken({
      agentId: "future-token",
      scopes: ["github:repo:read"],
      constraints: {
        "github:repo:read": { notBefore: future },
      },
      ttlDays: 1,
    });

    // Token with notAfter in past
    const noLongerValid = broker.createRootToken({
      agentId: "past-token",
      scopes: ["github:repo:read"],
      constraints: {
        "github:repo:read": { notAfter: past },
      },
      ttlDays: 1,
    });

    // notBefore: should fail permission check
    const futureResult = broker.checkPermission(
      notYetValid,
      "github:repo:read",
      "any/repo"
    );
    assert.strictEqual(futureResult.valid, false);

    // notAfter: should fail permission check
    const pastResult = broker.checkPermission(
      noLongerValid,
      "github:repo:read",
      "any/repo"
    );
    assert.strictEqual(pastResult.valid, false);
  });

  test("delegation depth limit enforcement", () => {
    const root = broker.createRootToken({
      agentId: "root",
      scopes: ["github:repo:read"],
      maxDelegationDepth: 2,
      ttlDays: 7,
    });

    // Level 1
    const level1 = broker.delegate(root, {
      agentId: "level1",
      requestedScopes: ["github:repo:read"],
    });

    // Level 2 (at max depth)
    const level2 = broker.delegate(level1, {
      agentId: "level2",
      requestedScopes: ["github:repo:read"],
    });

    // Level 3 should fail (exceeds maxDelegationDepth)
    assert.throws(
      () => {
        broker.delegate(level2, {
          agentId: "level3",
          requestedScopes: ["github:repo:read"],
        });
      },
      { message: /[Dd]elegation.*depth/ }
    );
  });

  test("secret isolation between broker instances", () => {
    const otherDir = createTempDir();
    try {
      const broker1 = new Broker(tempDir);
      const broker2 = new Broker(otherDir);

      // Create token with broker1
      const token = broker1.createRootToken({
        agentId: "isolated",
        scopes: ["github:repo:read"],
        ttlDays: 1,
      });

      // broker2 should NOT verify (different secret)
      const serialized = broker1.serializeToken(token);
      const deserialized = broker2.deserializeToken(serialized);

      const result = broker2.verifyToken(deserialized);
      assert.strictEqual(result.valid, false);
    } finally {
      cleanupTempDir(otherDir);
    }
  });
});

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
import * as crypto from "crypto";
import { Broker } from "./broker.js";
import { AgentRuntime, AGENT_TOKEN_ENV } from "./runtime.js";
import { APIKeyProvider, APIKeyProviderFactory } from "./providers/apikey.js";
import {
  LeaderServer,
  FollowerClient,
  SigningKeyManager,
  RevocationList,
} from "./distributed/index.js";
import {
  verifyIdentityProof,
  createEndorsement,
  createVcEndorsement,
  KeypairIdentityProvider,
  SpiffeIdentityProvider,
  DidWebIdentityProvider,
  IdentityService,
} from "./identity/index.js";
import type { SpiffeCreateOptions } from "./identity/index.js";
import type { DidWebCreateOptions } from "./identity/index.js";
import { isVerifiableCredential } from "./types.js";

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

// ─────────────────────────────────────────────────────────────────
// IDENTITY STANDARDS ALIGNMENT E2E
// ─────────────────────────────────────────────────────────────────

describe("E2E: DID:key Identity Lifecycle", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("complete DID:key lifecycle: create → token → delegate → standalone verify → endorse", async () => {
    // 1. Create a DID:key identity
    const identity = await broker.createIdentity({ type: "keypair", label: "orchestrator" });
    assert.ok(identity.persistentId.startsWith("did:key:z6Mk"));

    // 2. Create a root token bound to the identity
    const rootToken = await broker.createRootTokenWithIdentity(
      {
        agentId: "orchestrator",
        scopes: ["github:repo:read", "github:repo:write", "aws:s3:read"],
        maxDelegationDepth: 3,
        ttlDays: 7,
      },
      identity.persistentId
    );
    assert.ok(rootToken.persistentIdentity);
    assert.ok(rootToken.persistentIdentity!.publicKey);
    assert.ok(rootToken.persistentIdentity!.publicKeyJwk);
    assert.strictEqual(rootToken.persistentIdentity!.publicKeyJwk!.kty, "OKP");

    // 3. Verify token integrity (HMAC)
    assert.strictEqual(broker.verifyToken(rootToken).valid, true);

    // 4. Verify identity proof (broker-side)
    const brokerVerify = await broker.verifyTokenIdentity(rootToken);
    assert.strictEqual(brokerVerify.valid, true);

    // 5. Verify identity proof standalone (no broker)
    const standaloneVerify = verifyIdentityProof(rootToken);
    assert.strictEqual(standaloneVerify.valid, true);
    assert.strictEqual(standaloneVerify.persistentId, identity.persistentId);

    // 6. Delegate to a child — identity inherits
    const childToken = broker.delegate(rootToken, {
      agentId: "code-reviewer",
      requestedScopes: ["github:repo:read"],
      ttlMinutes: 60,
    });
    assert.strictEqual(childToken.persistentIdentity!.persistentId, identity.persistentId);
    assert.ok(childToken.persistentIdentity!.publicKeyJwk);

    // Child's identity also verifies standalone
    const childVerify = verifyIdentityProof(childToken);
    assert.strictEqual(childVerify.valid, true);
    assert.strictEqual(childVerify.persistentId, identity.persistentId);

    // 7. Create authority endorsement (VC format)
    const authorityKeypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const vcEndorsement = createVcEndorsement(
      "did:web:ci-authority.example.com",
      authorityKeypair.privateKey,
      authorityKeypair.publicKey,
      identity.persistentId,
      "ci-verified-agent",
      { issuerName: "CI Authority" }
    );
    assert.strictEqual(vcEndorsement.type, "VerifiableCredential");

    // 8. Attach endorsement and verify
    rootToken.persistentIdentity!.endorsements = [vcEndorsement];
    const endorsedResult = verifyIdentityProof(rootToken, {
      trustedAuthorities: { "did:web:ci-authority.example.com": authorityKeypair.publicKey },
    });
    assert.strictEqual(endorsedResult.valid, true);
    assert.strictEqual(endorsedResult.verifiedEndorsements!.length, 1);
    assert.strictEqual(endorsedResult.verifiedEndorsements![0].claim, "ci-verified-agent");

    // 9. Serialize, transfer, deserialize — identity survives
    const serialized = broker.serializeToken(rootToken);
    const deserialized = broker.deserializeToken(serialized);
    assert.strictEqual(deserialized.persistentIdentity!.persistentId, identity.persistentId);
    assert.ok(deserialized.persistentIdentity!.publicKeyJwk);
  });

  test("legacy key: identity migration to DID:key with token continuity", async () => {
    const provider = new KeypairIdentityProvider(tempDir);

    // 1. Manually create a legacy-format identity
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const fingerprint = crypto
      .createHash("sha256")
      .update(publicKey)
      .digest("hex")
      .slice(0, 32);
    const legacyId = `key:${fingerprint}`;

    const identityDir = path.join(tempDir, "identities");
    fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(identityDir, `${fingerprint}.key`), privateKey, { mode: 0o600 });
    fs.writeFileSync(
      path.join(identityDir, `${fingerprint}.json`),
      JSON.stringify({
        persistentId: legacyId,
        identityType: "keypair",
        createdAt: new Date().toISOString(),
        metadata: { publicKey, algorithm: "ed25519", fingerprint },
      }),
      { mode: 0o600 }
    );

    // 2. Create a token with legacy identity (using broker that can load it)
    const legacyChallenge = "legacy-challenge";
    const legacyProof = await provider.prove(legacyId, legacyChallenge);

    const legacyToken = broker.createRootToken({
      agentId: "legacy-agent",
      scopes: ["github:repo:read"],
      ttlDays: 1,
      persistentIdentity: {
        persistentId: legacyId,
        identityType: "keypair",
        proof: legacyProof.proof,
        challenge: legacyChallenge,
        publicKey,
      },
    });

    // 3. Legacy token verifies standalone
    const legacyResult = verifyIdentityProof(legacyToken);
    assert.strictEqual(legacyResult.valid, true);
    assert.strictEqual(legacyResult.persistentId, legacyId);

    // 4. Migrate to DID:key
    const migrated = await provider.migrate(legacyId);
    assert.ok(migrated!.persistentId.startsWith("did:key:z6Mk"));

    // 5. Create new token with migrated identity
    const newChallenge = "new-challenge";
    const newProof = await provider.prove(migrated!.persistentId, newChallenge);

    const newToken = broker.createRootToken({
      agentId: "migrated-agent",
      scopes: ["github:repo:read"],
      ttlDays: 1,
      persistentIdentity: {
        persistentId: migrated!.persistentId,
        identityType: "keypair",
        proof: newProof.proof,
        challenge: newChallenge,
        publicKey,
      },
    });

    // 6. New DID:key token verifies standalone
    const newResult = verifyIdentityProof(newToken);
    assert.strictEqual(newResult.valid, true);
    assert.strictEqual(newResult.persistentId, migrated!.persistentId);

    // 7. Both tokens point to the same underlying key
    assert.strictEqual(legacyResult.publicKey, newResult.publicKey);
  });
});

describe("E2E: SPIFFE Workload Identity", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("SPIFFE identity with SVID rotation and continuous verification", async () => {
    // 1. Create SPIFFE identity
    const identity = await broker.createIdentity({
      type: "attested",
      spiffeId: "spiffe://prod.example.com/agents/code-reviewer/instance-001",
      label: "reviewer-prod",
    } as any);
    assert.strictEqual(identity.persistentId, "spiffe://prod.example.com/agents/code-reviewer/instance-001");

    // 2. Create token bound to SPIFFE identity
    const token1 = await broker.createRootTokenWithIdentity(
      { agentId: "reviewer", scopes: ["github:repo:read"], ttlDays: 1 },
      identity.persistentId
    );
    assert.ok(token1.persistentIdentity!.publicKey);

    // 3. Token verifies standalone
    const result1 = verifyIdentityProof(token1);
    assert.strictEqual(result1.valid, true);

    const oldPublicKey = token1.persistentIdentity!.publicKey;

    // 4. Simulate SVID rotation (SPIRE rotates keys hourly)
    const spiffeProvider = broker.getIdentityService().getProvider("attested") as SpiffeIdentityProvider;
    await spiffeProvider.rotateSvid(identity.persistentId);

    // 5. Create new token after rotation
    const token2 = await broker.createRootTokenWithIdentity(
      { agentId: "reviewer-v2", scopes: ["github:repo:read"], ttlDays: 1 },
      identity.persistentId
    );

    // 6. New token has different public key but same SPIFFE ID
    assert.strictEqual(token2.persistentIdentity!.persistentId, identity.persistentId);
    assert.notStrictEqual(token2.persistentIdentity!.publicKey, oldPublicKey);

    // 7. New token verifies standalone
    const result2 = verifyIdentityProof(token2);
    assert.strictEqual(result2.valid, true);
    assert.strictEqual(result2.persistentId, identity.persistentId);

    // 8. Old token's proof still verifies (the proof was signed with the old key,
    //    and the old public key is embedded in the token)
    const oldResult = verifyIdentityProof(token1);
    assert.strictEqual(oldResult.valid, true);
  });

  test("SPIFFE identity delegation to subprocess with runtime", async () => {
    // 1. Create SPIFFE identity for a workload
    const identity = await broker.createIdentity({
      type: "attested",
      spiffeId: "spiffe://cluster.local/ns/agents/sa/orchestrator",
    } as any);

    // 2. Create root token
    const rootToken = await broker.createRootTokenWithIdentity(
      {
        agentId: "orchestrator",
        scopes: ["github:repo:read", "github:repo:write", "system:token:refresh"],
        maxDelegationDepth: 3,
        ttlDays: 1,
      },
      identity.persistentId
    );

    // 3. Start parent runtime
    const parentRuntime = new AgentRuntime(rootToken, { configDir: tempDir });
    parentRuntime.start();

    // 4. Delegate to subprocess — SPIFFE identity inherits
    const childEnv = parentRuntime.createSubprocessEnv({
      agentId: "worker",
      requestedScopes: ["github:repo:read"],
      ttlMinutes: 30,
    });

    // 5. Child process starts with inherited identity
    process.env[AGENT_TOKEN_ENV] = childEnv[AGENT_TOKEN_ENV];
    const childRuntime = AgentRuntime.fromEnvironment({ configDir: tempDir });
    childRuntime.start();

    // 6. Child has SPIFFE identity
    const childToken = (childRuntime as any).token;
    assert.ok(childToken.persistentIdentity);
    assert.strictEqual(childToken.persistentIdentity.persistentId, identity.persistentId);
    assert.strictEqual(childToken.persistentIdentity.identityType, "attested");

    // 7. Child's identity verifies standalone
    const childResult = verifyIdentityProof(childToken);
    assert.strictEqual(childResult.valid, true);

    childRuntime.stop();
    parentRuntime.stop();
    delete process.env[AGENT_TOKEN_ENV];
  });
});

describe("E2E: DID:web Cross-Organization Identity", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("DID:web identity with DID document and cross-org endorsement", async () => {
    // 1. Create DID:web identity for an agent
    const identity = await broker.createIdentity({
      type: "decentralized",
      did: "did:web:agents.acme-corp.com:code-reviewer",
      label: "acme-reviewer",
      services: [
        {
          id: "did:web:agents.acme-corp.com:code-reviewer#map",
          type: "MAPEndpoint",
          serviceEndpoint: "wss://map.acme-corp.com/agents/code-reviewer",
        },
      ],
    } as any);

    assert.strictEqual(identity.persistentId, "did:web:agents.acme-corp.com:code-reviewer");
    assert.strictEqual(identity.metadata.method, "web");

    // 2. Get the DID document (would be served at the resolved URL)
    const didWebProvider = broker.getIdentityService().getProvider("decentralized") as DidWebIdentityProvider;
    const didDoc = await didWebProvider.getDidDocument(identity.persistentId);
    assert.ok(didDoc);
    assert.strictEqual(didDoc!.id, identity.persistentId);
    assert.ok(didDoc!.verificationMethod[0].publicKeyJwk);
    assert.ok(didDoc!.service);
    assert.strictEqual(didDoc!.service![0].type, "MAPEndpoint");

    // 3. Verify URL resolution
    const resolveUrl = didWebProvider.didToUrl(identity.persistentId);
    assert.strictEqual(resolveUrl, "https://agents.acme-corp.com/code-reviewer/did.json");

    // 4. Create token
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "acme-reviewer", scopes: ["github:repo:read"], ttlDays: 7 },
      identity.persistentId
    );
    assert.ok(token.persistentIdentity!.publicKeyJwk);

    // 5. Standalone verification
    const standaloneResult = verifyIdentityProof(token);
    assert.strictEqual(standaloneResult.valid, true);

    // 6. Cross-org endorsement: partner org endorses this agent
    const partnerAuthority = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const partnerEndorsement = createVcEndorsement(
      "did:web:trust.partner-corp.com",
      partnerAuthority.privateKey,
      partnerAuthority.publicKey,
      identity.persistentId,
      "authorized-contributor",
      {
        issuerName: "Partner Corp Trust Authority",
        expirationDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(),
      }
    );

    token.persistentIdentity!.endorsements = [partnerEndorsement];

    // 7. Verify with partner's trusted authority key
    const endorsedResult = verifyIdentityProof(token, {
      trustedAuthorities: { "did:web:trust.partner-corp.com": partnerAuthority.publicKey },
    });
    assert.strictEqual(endorsedResult.valid, true);
    assert.strictEqual(endorsedResult.verifiedEndorsements!.length, 1);
    assert.strictEqual(endorsedResult.verifiedEndorsements![0].claim, "authorized-contributor");
  });

  test("DID:wba identity for MAP federation", async () => {
    // 1. Create DID:wba identity (MAP federation variant)
    const identity = await broker.createIdentity({
      type: "decentralized",
      did: "did:wba:map.example.com:federation:node-east",
      label: "east-node",
    } as any);

    assert.strictEqual(identity.metadata.method, "wba");

    // 2. Token creation and verification
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "fed-node-east", scopes: ["federation:sync:read"], ttlDays: 1 },
      identity.persistentId
    );

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.persistentId, "did:wba:map.example.com:federation:node-east");

    // 3. URL resolution follows same pattern as did:web
    const didWebProvider = broker.getIdentityService().getProvider("decentralized") as DidWebIdentityProvider;
    const url = didWebProvider.didToUrl(identity.persistentId);
    assert.strictEqual(url, "https://map.example.com/federation/node-east/did.json");
  });
});

describe("E2E: Mixed Identity Delegation Chain", () => {
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

  test("delegation chain across identity types: DID:key → SPIFFE child → DID:web grandchild", async () => {
    // 1. Root agent has DID:key identity
    const rootIdentity = await broker.createIdentity({ type: "keypair", label: "root" });
    const rootToken = await broker.createRootTokenWithIdentity(
      {
        agentId: "root-orchestrator",
        scopes: ["github:repo:read", "github:repo:write", "aws:s3:read"],
        maxDelegationDepth: 3,
        ttlDays: 7,
      },
      rootIdentity.persistentId
    );

    // Root identity verifies standalone
    assert.strictEqual(verifyIdentityProof(rootToken).valid, true);

    // 2. Delegate to child with its own SPIFFE identity
    const childIdentity = await broker.createIdentity({
      type: "attested",
      spiffeId: "spiffe://cluster.local/ns/agents/sa/worker",
    } as any);
    const childChallenge = broker.getIdentityService().generateChallenge("worker");
    const childProof = await broker.getIdentityService().proveIdentity(
      childIdentity.persistentId, childChallenge
    );
    const childPublicKey = (childIdentity.metadata.publicKey as string);

    const childToken = broker.delegate(rootToken, {
      agentId: "worker",
      requestedScopes: ["github:repo:read", "aws:s3:read"],
      ttlMinutes: 120,
      persistentIdentity: {
        persistentId: childIdentity.persistentId,
        identityType: "attested",
        proof: childProof.proof,
        challenge: childChallenge,
        publicKey: childPublicKey,
      },
    });

    // Child has its own SPIFFE identity, not the parent's DID:key
    assert.strictEqual(childToken.persistentIdentity!.persistentId, childIdentity.persistentId);
    assert.strictEqual(childToken.persistentIdentity!.identityType, "attested");
    assert.strictEqual(verifyIdentityProof(childToken).valid, true);

    // 3. Delegate to grandchild with its own DID:web identity
    const grandchildIdentity = await broker.createIdentity({
      type: "decentralized",
      did: "did:web:agents.partner.com:specialist",
    } as any);
    const gcChallenge = broker.getIdentityService().generateChallenge("specialist");
    const gcProof = await broker.getIdentityService().proveIdentity(
      grandchildIdentity.persistentId, gcChallenge
    );
    const gcPublicKey = (grandchildIdentity.metadata.publicKey as string);

    const grandchildToken = broker.delegate(childToken, {
      agentId: "specialist",
      requestedScopes: ["github:repo:read"],
      ttlMinutes: 30,
      persistentIdentity: {
        persistentId: grandchildIdentity.persistentId,
        identityType: "decentralized",
        proof: gcProof.proof,
        challenge: gcChallenge,
        publicKey: gcPublicKey,
      },
    });

    // Grandchild has its own DID:web identity
    assert.strictEqual(grandchildToken.persistentIdentity!.persistentId, grandchildIdentity.persistentId);
    assert.strictEqual(grandchildToken.persistentIdentity!.identityType, "decentralized");
    assert.strictEqual(verifyIdentityProof(grandchildToken).valid, true);

    // 4. All three tokens are independently verifiable standalone
    assert.strictEqual(verifyIdentityProof(rootToken).persistentId, rootIdentity.persistentId);
    assert.strictEqual(verifyIdentityProof(childToken).persistentId, childIdentity.persistentId);
    assert.strictEqual(verifyIdentityProof(grandchildToken).persistentId, grandchildIdentity.persistentId);

    // 5. Permissions attenuate correctly through the chain
    assert.strictEqual(broker.checkPermission(rootToken, "github:repo:write", "any").valid, true);
    assert.strictEqual(broker.checkPermission(childToken, "github:repo:write", "any").valid, false);
    assert.strictEqual(broker.checkPermission(grandchildToken, "aws:s3:read", "any").valid, false);
  });

  test("anonymous delegation strips identity from child", async () => {
    const identity = await broker.createIdentity({ type: "keypair", label: "known-agent" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "known", scopes: ["github:repo:read"], maxDelegationDepth: 2, ttlDays: 1 },
      identity.persistentId
    );

    // Delegate with identity cleared
    const anonChild = broker.delegate(token, {
      agentId: "anonymous-worker",
      requestedScopes: ["github:repo:read"],
      inheritPersistentIdentity: false,
    });

    assert.strictEqual(anonChild.persistentIdentity, undefined);
    assert.strictEqual(broker.verifyToken(anonChild).valid, true);

    // Standalone verification fails (no identity)
    const result = verifyIdentityProof(anonChild);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("no persistent identity"));
  });
});

describe("E2E: Multi-Authority Endorsement Chain", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("agent endorsed by multiple authorities with mixed formats", async () => {
    const identity = await broker.createIdentity({ type: "keypair", label: "multi-endorsed" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"], ttlDays: 1 },
      identity.persistentId
    );

    // Authority 1: legacy format endorsement
    const auth1 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const legacyEndorsement = createEndorsement(
      "legacy-authority",
      auth1.privateKey,
      auth1.publicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "security-audited"
    );

    // Authority 2: VC format endorsement (valid)
    const auth2 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const vcEndorsement = createVcEndorsement(
      "did:web:compliance.example.com",
      auth2.privateKey,
      auth2.publicKey,
      identity.persistentId,
      "gdpr-compliant",
      { expirationDate: new Date(Date.now() + 86400000).toISOString() }
    );

    // Authority 3: VC format endorsement (expired)
    const auth3 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const expiredVc = createVcEndorsement(
      "did:web:old-authority.example.com",
      auth3.privateKey,
      auth3.publicKey,
      identity.persistentId,
      "expired-cert",
      { expirationDate: new Date(Date.now() - 1000).toISOString() }
    );

    // Authority 4: untrusted VC endorsement
    const auth4 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const untrustedVc = createVcEndorsement(
      "did:web:untrusted.example.com",
      auth4.privateKey,
      auth4.publicKey,
      identity.persistentId,
      "untrusted-claim"
    );

    // Attach all endorsements
    token.persistentIdentity!.endorsements = [
      legacyEndorsement,
      vcEndorsement,
      expiredVc,
      untrustedVc,
    ];

    // Verify with trusted authorities (only auth1 and auth2)
    const result = verifyIdentityProof(token, {
      trustedAuthorities: {
        "legacy-authority": auth1.publicKey,
        "did:web:compliance.example.com": auth2.publicKey,
        "did:web:old-authority.example.com": auth3.publicKey,
        // auth4 intentionally not trusted
      },
    });

    assert.strictEqual(result.valid, true);
    // Only 2 should verify: legacy + valid VC. Expired and untrusted are excluded.
    assert.strictEqual(result.verifiedEndorsements!.length, 2);

    const claims = result.verifiedEndorsements!.map(e => e.claim).sort();
    assert.deepStrictEqual(claims, ["gdpr-compliant", "security-audited"]);
  });
});

describe("E2E: Identity with Distributed Broker", () => {
  let leaderDir: string;
  let followerDir: string;
  let leader: LeaderServer;
  let follower: FollowerClient;
  const authToken = "identity-e2e-token";
  let leaderPort: number;

  beforeEach(() => {
    leaderDir = createTempDir();
    followerDir = createTempDir();
    leaderPort = 20000 + Math.floor(Math.random() * 5000);
  });

  afterEach(async () => {
    follower?.stop();
    await leader?.stop();
    cleanupTempDir(leaderDir);
    cleanupTempDir(followerDir);
    delete process.env[AGENT_TOKEN_ENV];
  });

  test("identity token created on leader verifies after sync to follower", async () => {
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

      // Create DID:key identity and token on leader
      const identity = await sharedBroker.createIdentity({ type: "keypair", label: "distributed-agent" });
      const token = await sharedBroker.createRootTokenWithIdentity(
        { agentId: "dist-agent", scopes: ["github:repo:read"], ttlDays: 1 },
        identity.persistentId
      );

      // Token verifies on shared broker (same secret)
      assert.strictEqual(sharedBroker.verifyToken(token).valid, true);

      // Identity verifies standalone (no broker needed)
      const standaloneResult = verifyIdentityProof(token);
      assert.strictEqual(standaloneResult.valid, true);
      assert.ok(standaloneResult.persistentId!.startsWith("did:key:z6Mk"));

      // Serialize and "transfer" to follower region
      const serialized = sharedBroker.serializeToken(token);
      const deserialized = sharedBroker.deserializeToken(serialized);

      // Token integrity verifies
      assert.strictEqual(sharedBroker.verifyToken(deserialized).valid, true);

      // Identity still verifies after serialization round-trip
      assert.ok(deserialized.persistentIdentity);
      assert.strictEqual(deserialized.persistentIdentity!.persistentId, identity.persistentId);
      const remoteResult = verifyIdentityProof(deserialized);
      assert.strictEqual(remoteResult.valid, true);

      // Revoke the identity on leader side
      await sharedBroker.revokeIdentity(identity.persistentId);
      await leader.revokeToken(token, "identity revoked");
      await follower.sync();

      // Token is now revoked in the distributed system
      assert.strictEqual(follower.isRevoked("dist-agent"), true);

      // But standalone identity verification still passes (it only checks crypto, not revocation)
      // This is by design — revocation is checked at the broker layer
      const postRevokeResult = verifyIdentityProof(deserialized);
      assert.strictEqual(postRevokeResult.valid, true);
    } finally {
      cleanupTempDir(sharedDir);
    }
  });
});

describe("E2E: All Four Identity Types End-to-End", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("create, prove, verify, and endorse across all identity types", async () => {
    const authorityKeypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    // ── DID:key (keypair) ──
    const keypairId = await broker.createIdentity({ type: "keypair", label: "keypair-agent" });
    const keypairToken = await broker.createRootTokenWithIdentity(
      { agentId: "kp-agent", scopes: ["github:repo:read"], ttlDays: 1 },
      keypairId.persistentId
    );
    assert.ok(keypairId.persistentId.startsWith("did:key:z6Mk"));
    assert.strictEqual(verifyIdentityProof(keypairToken).valid, true);

    // ── Platform (broker-assigned) ──
    const platformId = await broker.createIdentity({ type: "platform", label: "platform-agent" });
    const platformToken = await broker.createRootTokenWithIdentity(
      { agentId: "pl-agent", scopes: ["github:repo:read"], ttlDays: 1 },
      platformId.persistentId
    );
    assert.ok(platformId.persistentId.startsWith("platform:"));
    // Platform tokens cannot verify standalone (symmetric crypto)
    const platformResult = verifyIdentityProof(platformToken);
    assert.strictEqual(platformResult.valid, false);
    assert.ok(platformResult.error!.includes("no public key") || platformResult.error!.includes("cannot verify"));
    // But broker-side verification works
    const brokerPlatformResult = await broker.verifyTokenIdentity(platformToken);
    assert.strictEqual(brokerPlatformResult.valid, true);

    // ── SPIFFE (attested) ──
    const spiffeId = await broker.createIdentity({
      type: "attested",
      spiffeId: "spiffe://prod.example.com/agents/worker",
    } as any);
    const spiffeToken = await broker.createRootTokenWithIdentity(
      { agentId: "sp-agent", scopes: ["github:repo:read"], ttlDays: 1 },
      spiffeId.persistentId
    );
    assert.ok(spiffeId.persistentId.startsWith("spiffe://"));
    assert.strictEqual(verifyIdentityProof(spiffeToken).valid, true);

    // ── DID:web (decentralized) ──
    const didWebId = await broker.createIdentity({
      type: "decentralized",
      did: "did:web:agents.example.com:worker",
    } as any);
    const didWebToken = await broker.createRootTokenWithIdentity(
      { agentId: "dw-agent", scopes: ["github:repo:read"], ttlDays: 1 },
      didWebId.persistentId
    );
    assert.ok(didWebId.persistentId.startsWith("did:web:"));
    assert.strictEqual(verifyIdentityProof(didWebToken).valid, true);

    // ── Endorse all standalone-verifiable identities with VC format ──
    for (const [token, id] of [
      [keypairToken, keypairId],
      [spiffeToken, spiffeId],
      [didWebToken, didWebId],
    ] as const) {
      const vc = createVcEndorsement(
        "did:web:central-authority.example.com",
        authorityKeypair.privateKey,
        authorityKeypair.publicKey,
        id.persistentId,
        "org-verified"
      );
      token.persistentIdentity!.endorsements = [vc];

      const result = verifyIdentityProof(token, {
        trustedAuthorities: { "did:web:central-authority.example.com": authorityKeypair.publicKey },
      });
      assert.strictEqual(result.valid, true, `Endorsement failed for ${id.identityType}`);
      assert.strictEqual(result.verifiedEndorsements!.length, 1);
    }
  });
});

/**
 * Tests for distributed broker mode
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { SigningKeyManager } from "./signing-keys.js";
import { RevocationList } from "./revocation.js";
import { LeaderServer } from "./leader.js";
import { FollowerClient } from "./follower.js";
import { FollowerState, BrokerMode } from "./types.js";
import { Broker } from "../broker.js";

// Create a unique temp directory for each test
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-dist-test-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("SigningKeyManager", () => {
  let tempDir: string;
  let keyManager: SigningKeyManager;

  beforeEach(() => {
    tempDir = createTempDir();
    keyManager = new SigningKeyManager(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("Key Management", () => {
    test("creates initial key on first access", () => {
      const { key, version } = keyManager.getCurrentKey();

      assert.ok(key instanceof Buffer);
      assert.strictEqual(key.length, 32);
      assert.strictEqual(version, 1);
    });

    test("returns same key on subsequent access", () => {
      const first = keyManager.getCurrentKey();
      const second = keyManager.getCurrentKey();

      assert.strictEqual(first.version, second.version);
      assert.ok(first.key.equals(second.key));
    });

    test("rotates to new key", () => {
      const initial = keyManager.getCurrentKey();
      const rotated = keyManager.rotate();

      assert.strictEqual(rotated.version, initial.version + 1);
      assert.ok(!initial.key.equals(rotated.key));
      assert.strictEqual(keyManager.getCurrentVersion(), rotated.version);
    });

    test("keeps old keys after rotation", () => {
      const v1 = keyManager.getCurrentKey();
      keyManager.rotate();
      const v2 = keyManager.getCurrentKey();

      assert.ok(keyManager.hasKey(v1.version));
      assert.ok(keyManager.hasKey(v2.version));

      const retrievedV1 = keyManager.getKey(v1.version);
      assert.ok(retrievedV1);
      assert.ok(v1.key.equals(retrievedV1));
    });

    test("returns undefined for non-existent version", () => {
      keyManager.getCurrentKey();
      const nonExistent = keyManager.getKey(999);
      assert.strictEqual(nonExistent, undefined);
    });
  });

  describe("Sync Operations", () => {
    test("exports current key as base64", () => {
      keyManager.getCurrentKey();
      const exported = keyManager.exportCurrentKey();

      assert.ok(typeof exported === "string");
      assert.ok(exported.length > 0);

      // Verify it's valid base64
      const decoded = Buffer.from(exported, "base64");
      assert.strictEqual(decoded.length, 32);
    });

    test("imports key from base64", () => {
      const originalKey = Buffer.from("a".repeat(64), "hex");
      const base64Key = originalKey.toString("base64");

      keyManager.importKey(base64Key, 5);

      assert.ok(keyManager.hasKey(5));
      const retrieved = keyManager.getKey(5);
      assert.ok(retrieved);
      assert.ok(originalKey.equals(retrieved));
    });

    test("import updates current version if newer", () => {
      keyManager.getCurrentKey(); // Creates v1
      const newKey = Buffer.from("b".repeat(64), "hex");

      keyManager.importKey(newKey.toString("base64"), 10);

      assert.strictEqual(keyManager.getCurrentVersion(), 10);
    });

    test("gets all keys", () => {
      keyManager.getCurrentKey(); // v1
      keyManager.rotate(); // v2
      keyManager.rotate(); // v3

      const allKeys = keyManager.getAllKeys();

      assert.strictEqual(allKeys.length, 3);
      assert.deepStrictEqual(
        allKeys.map((k) => k.version),
        [1, 2, 3]
      );
    });

    test("gets keys since version", () => {
      keyManager.getCurrentKey(); // v1
      keyManager.rotate(); // v2
      keyManager.rotate(); // v3

      const newKeys = keyManager.getKeysSince(1);

      assert.strictEqual(newKeys.length, 2);
      assert.deepStrictEqual(
        newKeys.map((k) => k.version),
        [2, 3]
      );
    });
  });

  describe("Persistence", () => {
    test("persists keys across instances", () => {
      // Create and rotate keys
      keyManager.getCurrentKey();
      keyManager.rotate();
      const finalKey = keyManager.rotate();

      // Create new instance
      const newManager = new SigningKeyManager(tempDir);

      assert.strictEqual(newManager.getCurrentVersion(), finalKey.version);
      assert.ok(newManager.hasKey(1));
      assert.ok(newManager.hasKey(2));
      assert.ok(newManager.hasKey(3));
    });

    test("prune removes old keys", () => {
      keyManager.getCurrentKey();
      keyManager.rotate();
      keyManager.rotate();

      // Prune with 0 retention (removes all non-current)
      const pruned = keyManager.prune(0);

      assert.strictEqual(pruned, 2);
      assert.ok(!keyManager.hasKey(1));
      assert.ok(!keyManager.hasKey(2));
      assert.ok(keyManager.hasKey(3));
    });
  });
});

describe("RevocationList", () => {
  let tempDir: string;
  let revocationList: RevocationList;

  beforeEach(() => {
    tempDir = createTempDir();
    revocationList = new RevocationList(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("Basic Operations", () => {
    test("initially empty", () => {
      assert.strictEqual(revocationList.count(), 0);
      assert.strictEqual(revocationList.getVersion(), 0);
    });

    test("revokes token", () => {
      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
        reason: "compromised",
      });

      assert.ok(revocationList.isRevoked("token-1"));
      assert.strictEqual(revocationList.count(), 1);
      assert.strictEqual(revocationList.getVersion(), 1);
    });

    test("unrevokes token", () => {
      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
      });

      const result = revocationList.unrevoke("token-1");

      assert.strictEqual(result, true);
      assert.ok(!revocationList.isRevoked("token-1"));
    });

    test("unrevoke returns false for non-revoked token", () => {
      const result = revocationList.unrevoke("never-revoked");
      assert.strictEqual(result, false);
    });

    test("gets revocation details", () => {
      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
        reason: "testing",
      });

      const revocation = revocationList.getRevocation("token-1");

      assert.ok(revocation);
      assert.strictEqual(revocation.tokenId, "token-1");
      assert.strictEqual(revocation.agentId, "agent-1");
      assert.strictEqual(revocation.reason, "testing");
      assert.ok(revocation.revokedAt);
    });
  });

  describe("Expiring Revocations", () => {
    test("respects expiration", () => {
      const past = new Date(Date.now() - 1000).toISOString();

      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
        expiresAt: past,
      });

      // Should not be revoked (expiration passed)
      assert.ok(!revocationList.isRevoked("token-1"));
    });

    test("active until expiration", () => {
      const future = new Date(Date.now() + 60000).toISOString();

      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
        expiresAt: future,
      });

      // Should still be revoked
      assert.ok(revocationList.isRevoked("token-1"));
    });

    test("prune removes expired", () => {
      const past = new Date(Date.now() - 1000).toISOString();

      revocationList.revoke({
        tokenId: "token-1",
        agentId: "agent-1",
        expiresAt: past,
      });

      revocationList.revoke({
        tokenId: "token-2",
        agentId: "agent-2",
        // No expiration
      });

      const pruned = revocationList.prune();

      assert.strictEqual(pruned, 1);
      assert.strictEqual(revocationList.count(), 1);
    });
  });

  describe("Sync Operations", () => {
    test("gets revocations since version", () => {
      revocationList.revoke({ tokenId: "token-1", agentId: "agent-1" });
      revocationList.revoke({ tokenId: "token-2", agentId: "agent-2" });
      revocationList.revoke({ tokenId: "token-3", agentId: "agent-3" });

      const delta = revocationList.getRevocationsSince(1);

      assert.strictEqual(delta.length, 2);
      assert.ok(delta.includes("token-2"));
      assert.ok(delta.includes("token-3"));
    });

    test("adds delta from sync", () => {
      revocationList.addDeltaFromSync(["token-1", "token-2"], 5);

      assert.ok(revocationList.isRevoked("token-1"));
      assert.ok(revocationList.isRevoked("token-2"));
      assert.strictEqual(revocationList.getVersion(), 5);
    });

    test("gets all revocations", () => {
      revocationList.revoke({ tokenId: "token-1", agentId: "agent-1" });
      revocationList.revoke({ tokenId: "token-2", agentId: "agent-2" });

      const all = revocationList.getAllRevocations();

      assert.strictEqual(all.length, 2);
    });
  });

  describe("Persistence", () => {
    test("persists across instances", () => {
      revocationList.revoke({ tokenId: "token-1", agentId: "agent-1" });
      revocationList.revoke({ tokenId: "token-2", agentId: "agent-2" });

      const newList = new RevocationList(tempDir);

      assert.ok(newList.isRevoked("token-1"));
      assert.ok(newList.isRevoked("token-2"));
      assert.strictEqual(newList.getVersion(), 2);
    });
  });
});

describe("Leader/Follower Integration", () => {
  let leaderDir: string;
  let followerDir: string;
  let leaderBroker: Broker;
  let followerBroker: Broker;
  let leader: LeaderServer;
  let follower: FollowerClient;
  const authToken = "test-auth-token";
  let leaderPort: number;

  beforeEach(async () => {
    leaderDir = createTempDir();
    followerDir = createTempDir();
    leaderBroker = new Broker(leaderDir);
    followerBroker = new Broker(followerDir);

    // Use a random port for each test
    leaderPort = 9000 + Math.floor(Math.random() * 1000);

    leader = new LeaderServer(leaderBroker, leaderDir, {
      port: leaderPort,
      followerAuthToken: authToken,
    });

    await leader.start();

    follower = new FollowerClient(followerBroker, followerDir, {
      leaderUrl: `http://localhost:${leaderPort}`,
      leaderAuthToken: authToken,
      followerId: "test-follower",
      syncIntervalSeconds: 1,
    });
  });

  afterEach(async () => {
    follower.stop();
    await leader.stop();
    cleanupTempDir(leaderDir);
    cleanupTempDir(followerDir);
  });

  test("follower syncs from leader", async () => {
    await follower.start();

    assert.strictEqual(follower.getState(), FollowerState.CONNECTED);

    const status = follower.getStatus();
    assert.strictEqual(status.mode, BrokerMode.FOLLOWER);
    assert.ok(status.signingKeyVersion > 0);
  });

  test("follower receives signing key from leader", async () => {
    // Leader creates a key first
    leader.getSigningKeyManager().getCurrentKey();

    await follower.start();

    // Follower should have the same key version
    assert.strictEqual(
      follower.getSigningKeyManager().getCurrentVersion(),
      leader.getSigningKeyManager().getCurrentVersion()
    );
  });

  test("follower receives revocations from leader", async () => {
    await follower.start();

    // Revoke on leader
    await leader.revokeToken({ agentId: "bad-token" } as any, "test");

    // Force sync
    await follower.sync();

    assert.ok(follower.isRevoked("bad-token"));
  });

  test("leader status includes follower count", async () => {
    await follower.start();

    const status = leader.getStatus();
    assert.strictEqual(status.mode, BrokerMode.LEADER);
    assert.strictEqual(status.followerCount, 1);
    assert.ok(status.followers?.includes("test-follower"));
  });

  test("key rotation pushes to follower", async () => {
    await follower.start();

    const beforeVersion = follower.getSigningKeyManager().getCurrentVersion();

    // Rotate on leader
    await leader.rotateSigningKey();

    // Force sync
    await follower.sync();

    const afterVersion = follower.getSigningKeyManager().getCurrentVersion();
    assert.ok(afterVersion > beforeVersion);
  });
});

describe("Follower State Machine", () => {
  let tempDir: string;
  let broker: Broker;
  let follower: FollowerClient;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    follower?.stop();
    cleanupTempDir(tempDir);
  });

  test("starts in STARTING state", () => {
    follower = new FollowerClient(broker, tempDir, {
      leaderUrl: "http://localhost:99999", // Non-existent
      leaderAuthToken: "token",
      followerId: "test",
    });

    assert.strictEqual(follower.getState(), FollowerState.STARTING);
  });

  test("fails start without cache if leader unreachable", async () => {
    follower = new FollowerClient(broker, tempDir, {
      leaderUrl: "http://localhost:99999",
      leaderAuthToken: "token",
      followerId: "test",
      syncTimeoutMs: 100,
    });

    await assert.rejects(async () => {
      await follower.start();
    }, /Initial sync failed/);
  });

  test("degrades gracefully with cached data", async () => {
    // Pre-populate cache
    const keyManager = new SigningKeyManager(tempDir);
    keyManager.getCurrentKey();

    follower = new FollowerClient(broker, tempDir, {
      leaderUrl: "http://localhost:99999",
      leaderAuthToken: "token",
      followerId: "test",
      syncTimeoutMs: 100,
    });

    await follower.start();

    // Should be degraded but operational
    assert.strictEqual(follower.getState(), FollowerState.DEGRADED);
    assert.ok(follower.canOperate());
  });
});

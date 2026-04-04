/**
 * Tests for persistent identity system
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { KeypairIdentityProvider } from "./keypair-provider.js";
import { PlatformIdentityProvider } from "./platform-provider.js";
import { IdentityService } from "./identity-service.js";

// ─────────────────────────────────────────────────────────────────
// KEYPAIR IDENTITY PROVIDER
// ─────────────────────────────────────────────────────────────────

describe("KeypairIdentityProvider", () => {
  let tmpDir: string;
  let provider: KeypairIdentityProvider;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-test-"));
    provider = new KeypairIdentityProvider(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("creates a keypair identity with key: prefix", async () => {
    const identity = await provider.create({ label: "test-agent" });

    assert.ok(identity.persistentId.startsWith("key:"));
    assert.strictEqual(identity.identityType, "keypair");
    assert.strictEqual(identity.label, "test-agent");
    assert.ok(identity.metadata.publicKey);
    assert.strictEqual(identity.metadata.algorithm, "ed25519");
    assert.ok(identity.createdAt);
  });

  test("persists identity to disk and loads it back", async () => {
    const identity = await provider.create({ label: "persist-test" });
    const loaded = await provider.load(identity.persistentId);

    assert.ok(loaded);
    assert.strictEqual(loaded!.persistentId, identity.persistentId);
    assert.strictEqual(loaded!.label, "persist-test");
    assert.strictEqual(loaded!.metadata.publicKey, identity.metadata.publicKey);
  });

  test("returns null for unknown identity", async () => {
    const loaded = await provider.load("key:nonexistent");
    assert.strictEqual(loaded, null);
  });

  test("lists all identities", async () => {
    await provider.create({ label: "agent-1" });
    await provider.create({ label: "agent-2" });

    const identities = await provider.list();
    assert.strictEqual(identities.length, 2);
  });

  test("generates and verifies identity proof", async () => {
    const identity = await provider.create();
    const challenge = "test-challenge-12345";

    const proof = await provider.prove(identity.persistentId, challenge);

    assert.strictEqual(proof.persistentId, identity.persistentId);
    assert.strictEqual(proof.identityType, "keypair");
    assert.strictEqual(proof.challenge, challenge);
    assert.ok(proof.proof);
    assert.ok(proof.provenAt);

    const valid = await provider.verify(proof, challenge);
    assert.strictEqual(valid, true);
  });

  test("rejects proof with wrong challenge", async () => {
    const identity = await provider.create();
    const proof = await provider.prove(identity.persistentId, "challenge-a");

    const valid = await provider.verify(proof, "challenge-b");
    assert.strictEqual(valid, false);
  });

  test("rejects proof with tampered signature", async () => {
    const identity = await provider.create();
    const challenge = "challenge";
    const proof = await provider.prove(identity.persistentId, challenge);

    // Tamper with the proof
    proof.proof = proof.proof.slice(0, -4) + "XXXX";

    const valid = await provider.verify(proof, challenge);
    assert.strictEqual(valid, false);
  });

  test("revokes identity and deletes key material", async () => {
    const identity = await provider.create();

    await provider.revoke(identity.persistentId);

    const loaded = await provider.load(identity.persistentId);
    assert.strictEqual(loaded, null);

    // Verify key file is gone
    const fingerprint = identity.persistentId.slice(4);
    const keyPath = path.join(tmpDir, "identities", `${fingerprint}.key`);
    assert.strictEqual(fs.existsSync(keyPath), false);
  });

  test("two identities have different keys and IDs", async () => {
    const id1 = await provider.create();
    const id2 = await provider.create();

    assert.notStrictEqual(id1.persistentId, id2.persistentId);
    assert.notStrictEqual(id1.metadata.publicKey, id2.metadata.publicKey);
  });

  test("proof from one identity does not verify as another", async () => {
    const id1 = await provider.create();
    const id2 = await provider.create();
    const challenge = "cross-identity-challenge";

    const proof = await provider.prove(id1.persistentId, challenge);

    // Change the persistent ID to the other identity
    proof.persistentId = id2.persistentId;

    const valid = await provider.verify(proof, challenge);
    assert.strictEqual(valid, false);
  });

  test("exports public key", async () => {
    const identity = await provider.create();
    const pubKey = await provider.exportPublicKey(identity.persistentId);

    assert.ok(pubKey);
    assert.ok(pubKey!.includes("BEGIN PUBLIC KEY"));
  });
});

// ─────────────────────────────────────────────────────────────────
// PLATFORM IDENTITY PROVIDER
// ─────────────────────────────────────────────────────────────────

describe("PlatformIdentityProvider", () => {
  let tmpDir: string;
  let provider: PlatformIdentityProvider;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-test-"));
    provider = new PlatformIdentityProvider(tmpDir, "test-issuer");
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("creates a platform identity with platform: prefix", async () => {
    const identity = await provider.create({ label: "my-agent" });

    assert.ok(identity.persistentId.startsWith("platform:"));
    assert.strictEqual(identity.identityType, "platform");
    assert.strictEqual(identity.label, "my-agent");
    assert.strictEqual(identity.metadata.issuer, "test-issuer");
    assert.ok(identity.metadata.uuid);
  });

  test("loads identity from registry", async () => {
    const identity = await provider.create();
    const loaded = await provider.load(identity.persistentId);

    assert.ok(loaded);
    assert.strictEqual(loaded!.persistentId, identity.persistentId);
  });

  test("returns null for unknown identity", async () => {
    const loaded = await provider.load("platform:nonexistent-uuid");
    assert.strictEqual(loaded, null);
  });

  test("lists all identities", async () => {
    await provider.create({ label: "agent-1" });
    await provider.create({ label: "agent-2" });
    await provider.create({ label: "agent-3" });

    const identities = await provider.list();
    assert.strictEqual(identities.length, 3);
  });

  test("generates and verifies HMAC-based proof", async () => {
    const identity = await provider.create();
    const challenge = "platform-challenge-xyz";

    const proof = await provider.prove(identity.persistentId, challenge);
    assert.strictEqual(proof.identityType, "platform");

    const valid = await provider.verify(proof, challenge);
    assert.strictEqual(valid, true);
  });

  test("rejects proof with wrong challenge", async () => {
    const identity = await provider.create();
    const proof = await provider.prove(identity.persistentId, "right-challenge");

    const valid = await provider.verify(proof, "wrong-challenge");
    assert.strictEqual(valid, false);
  });

  test("revokes identity and prevents loading/proving", async () => {
    const identity = await provider.create();

    await provider.revoke(identity.persistentId);

    const loaded = await provider.load(identity.persistentId);
    assert.strictEqual(loaded, null);

    await assert.rejects(
      () => provider.prove(identity.persistentId, "challenge"),
      /revoked/
    );
  });

  test("revoked identity not included in list", async () => {
    const id1 = await provider.create();
    await provider.create();

    await provider.revoke(id1.persistentId);

    const identities = await provider.list();
    assert.strictEqual(identities.length, 1);
  });

  test("reissues a revoked identity", async () => {
    const identity = await provider.create();
    await provider.revoke(identity.persistentId);

    const reissued = await provider.reissue(identity.persistentId);
    assert.ok(reissued);
    assert.strictEqual(reissued!.persistentId, identity.persistentId);

    // Can now prove again
    const proof = await provider.prove(identity.persistentId, "after-reissue");
    const valid = await provider.verify(proof, "after-reissue");
    assert.strictEqual(valid, true);
  });
});

// ─────────────────────────────────────────────────────────────────
// IDENTITY SERVICE
// ─────────────────────────────────────────────────────────────────

describe("IdentityService", () => {
  let tmpDir: string;
  let service: IdentityService;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-test-"));
    service = new IdentityService({ defaultType: "keypair" });
    service.registerProvider(new KeypairIdentityProvider(tmpDir));
    service.registerProvider(new PlatformIdentityProvider(tmpDir));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("lists registered provider types", () => {
    const types = service.listProviderTypes();
    assert.ok(types.includes("keypair"));
    assert.ok(types.includes("platform"));
  });

  test("creates identity with default type", async () => {
    const identity = await service.createIdentity({ label: "default" });
    assert.ok(identity.persistentId.startsWith("key:"));
  });

  test("creates identity with explicit type", async () => {
    const identity = await service.createIdentity({ type: "platform", label: "explicit" });
    assert.ok(identity.persistentId.startsWith("platform:"));
  });

  test("loads identity by persistent ID (auto-dispatches to correct provider)", async () => {
    const keypairId = await service.createIdentity({ type: "keypair" });
    const platformId = await service.createIdentity({ type: "platform" });

    const loaded1 = await service.loadIdentity(keypairId.persistentId);
    assert.ok(loaded1);
    assert.strictEqual(loaded1!.identityType, "keypair");

    const loaded2 = await service.loadIdentity(platformId.persistentId);
    assert.ok(loaded2);
    assert.strictEqual(loaded2!.identityType, "platform");
  });

  test("lists identities across all providers", async () => {
    await service.createIdentity({ type: "keypair" });
    await service.createIdentity({ type: "platform" });
    await service.createIdentity({ type: "keypair" });

    const all = await service.listIdentities();
    assert.strictEqual(all.length, 3);
  });

  test("generates challenge with agent ID and nonce", () => {
    const challenge = service.generateChallenge("code-reviewer");
    assert.ok(challenge.startsWith("code-reviewer:"));
    const parts = challenge.split(":");
    assert.strictEqual(parts.length, 3);
  });

  test("prove and verify cycle works through service", async () => {
    const identity = await service.createIdentity({ type: "keypair" });
    const challenge = service.generateChallenge("test-agent");

    const proof = await service.proveIdentity(identity.persistentId, challenge);
    const valid = await service.verifyProof(proof, challenge);
    assert.strictEqual(valid, true);
  });

  test("prove and verify works for platform identities too", async () => {
    const identity = await service.createIdentity({ type: "platform" });
    const challenge = service.generateChallenge("test-agent");

    const proof = await service.proveIdentity(identity.persistentId, challenge);
    const valid = await service.verifyProof(proof, challenge);
    assert.strictEqual(valid, true);
  });

  test("revokes identity through service", async () => {
    const identity = await service.createIdentity({ type: "keypair" });

    await service.revokeIdentity(identity.persistentId);

    const loaded = await service.loadIdentity(identity.persistentId);
    assert.strictEqual(loaded, null);
  });

  test("throws for unregistered provider type", async () => {
    await assert.rejects(
      () => service.createIdentity({ type: "attested" as any }),
      /No identity provider registered/
    );
  });
});

// ─────────────────────────────────────────────────────────────────
// TOKEN INTEGRATION
// ─────────────────────────────────────────────────────────────────

import { TokenService, generateSecret } from "../token.js";

describe("Token + Identity integration", () => {
  let tmpDir: string;
  let tokenService: TokenService;
  let identityService: IdentityService;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-test-"));
    tokenService = new TokenService(generateSecret());
    identityService = new IdentityService();
    identityService.registerProvider(new KeypairIdentityProvider(tmpDir));
    identityService.registerProvider(new PlatformIdentityProvider(tmpDir));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("creates root token with persistent identity", async () => {
    const identity = await identityService.createIdentity({ type: "keypair" });
    const challenge = identityService.generateChallenge("orchestrator");

    const token = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
        challenge,
      },
    });

    assert.ok(token.persistentIdentity);
    assert.strictEqual(token.persistentIdentity!.persistentId, identity.persistentId);
    assert.strictEqual(token.persistentIdentity!.identityType, "keypair");

    // Token is still valid
    const result = tokenService.verify(token);
    assert.strictEqual(result.valid, true);
  });

  test("persistent identity is inherited through delegation by default", async () => {
    const identity = await identityService.createIdentity({ type: "keypair" });

    const parent = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read", "github:repo:write"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
      },
    });

    const child = tokenService.delegate(parent, {
      agentId: "code-reviewer",
      requestedScopes: ["github:repo:read"],
    });

    assert.ok(child.persistentIdentity);
    assert.strictEqual(
      child.persistentIdentity!.persistentId,
      identity.persistentId
    );
  });

  test("persistent identity can be cleared during delegation", async () => {
    const identity = await identityService.createIdentity({ type: "keypair" });

    const parent = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
      },
    });

    const child = tokenService.delegate(parent, {
      agentId: "anonymous-worker",
      requestedScopes: ["github:repo:read"],
      inheritPersistentIdentity: false,
    });

    assert.strictEqual(child.persistentIdentity, undefined);
  });

  test("child can get its own persistent identity during delegation", async () => {
    const parentIdentity = await identityService.createIdentity({ type: "keypair", label: "parent" });
    const childIdentity = await identityService.createIdentity({ type: "platform", label: "child" });

    const parent = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: parentIdentity.persistentId,
        identityType: parentIdentity.identityType,
      },
    });

    const child = tokenService.delegate(parent, {
      agentId: "specialist",
      requestedScopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: childIdentity.persistentId,
        identityType: childIdentity.identityType,
      },
    });

    assert.ok(child.persistentIdentity);
    assert.strictEqual(
      child.persistentIdentity!.persistentId,
      childIdentity.persistentId
    );
    assert.strictEqual(child.persistentIdentity!.identityType, "platform");
  });

  test("persistent identity survives token refresh", async () => {
    const identity = await identityService.createIdentity({ type: "keypair" });

    const token = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read"],
      ttlDays: 1,
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
      },
    });

    const newExpiry = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const refreshed = tokenService.createRefreshedToken(token, newExpiry);

    assert.ok(refreshed.persistentIdentity);
    assert.strictEqual(
      refreshed.persistentIdentity!.persistentId,
      identity.persistentId
    );
    assert.strictEqual(refreshed.expiresAt, newExpiry);
  });

  test("persistent identity survives serialization round-trip", async () => {
    const identity = await identityService.createIdentity({ type: "platform" });

    const token = tokenService.createRootToken({
      agentId: "orchestrator",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
      },
    });

    const serialized = tokenService.serialize(token);
    const deserialized = tokenService.deserialize(serialized);

    assert.ok(deserialized.persistentIdentity);
    assert.strictEqual(
      deserialized.persistentIdentity!.persistentId,
      identity.persistentId
    );
  });

  test("token without persistent identity still works normally", () => {
    const token = tokenService.createRootToken({
      agentId: "simple-agent",
      scopes: ["github:repo:read"],
    });

    assert.strictEqual(token.persistentIdentity, undefined);
    const result = tokenService.verify(token);
    assert.strictEqual(result.valid, true);
  });
});

// ─────────────────────────────────────────────────────────────────
// BROKER-LEVEL PROOF-OF-POSSESSION
// ─────────────────────────────────────────────────────────────────

import { Broker } from "../broker.js";

describe("Proof-of-possession via Broker", () => {
  let tmpDir: string;
  let broker: Broker;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-pop-"));
    broker = new Broker(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("createRootTokenWithIdentity embeds cryptographic proof (keypair)", async () => {
    const identity = await broker.createIdentity({ type: "keypair", label: "pop-test" });

    const token = await broker.createRootTokenWithIdentity(
      { agentId: "orchestrator", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Token should have persistent identity with proof
    assert.ok(token.persistentIdentity);
    assert.strictEqual(token.persistentIdentity!.persistentId, identity.persistentId);
    assert.strictEqual(token.persistentIdentity!.identityType, "keypair");
    assert.ok(token.persistentIdentity!.challenge, "challenge should be present");
    assert.ok(token.persistentIdentity!.proof, "proof should be present");
  });

  test("createRootTokenWithIdentity embeds cryptographic proof (platform)", async () => {
    const identity = await broker.createIdentity({ type: "platform", label: "pop-platform" });

    const token = await broker.createRootTokenWithIdentity(
      { agentId: "worker", scopes: ["aws:s3:read"] },
      identity.persistentId
    );

    assert.ok(token.persistentIdentity);
    assert.ok(token.persistentIdentity!.proof, "proof should be present");
    assert.ok(token.persistentIdentity!.challenge, "challenge should be present");
  });

  test("verifyTokenIdentity succeeds for valid proof (keypair)", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "verifiable-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const result = await broker.verifyTokenIdentity(token);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.persistentId, identity.persistentId);
  });

  test("verifyTokenIdentity succeeds for valid proof (platform)", async () => {
    const identity = await broker.createIdentity({ type: "platform" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "platform-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const result = await broker.verifyTokenIdentity(token);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.persistentId, identity.persistentId);
  });

  test("verifyTokenIdentity fails for token without identity", async () => {
    const token = broker.createRootToken({
      agentId: "no-identity",
      scopes: ["github:repo:read"],
    });

    const result = await broker.verifyTokenIdentity(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("no persistent identity"));
  });

  test("verifyTokenIdentity fails for token with identity but no proof", async () => {
    // Create a token using createRootToken directly (bypassing PoP flow)
    // This simulates a token created before PoP was wired in
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = broker.createRootToken({
      agentId: "no-proof-agent",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: "keypair",
        challenge: "some-challenge",
        // proof is intentionally missing — token was created without PoP
      },
    });

    const result = await broker.verifyTokenIdentity(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("missing proof"));
  });

  test("verifyTokenIdentity fails for tampered proof (HMAC catches it)", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "tamper-test", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Tamper with the proof — this also invalidates the token's HMAC signature
    // since the proof is part of the signed payload
    token.persistentIdentity!.proof = token.persistentIdentity!.proof!.slice(0, -4) + "XXXX";

    const result = await broker.verifyTokenIdentity(token);
    assert.strictEqual(result.valid, false);
    // HMAC catches the tampering before identity verification runs
    assert.ok(result.error!.includes("Invalid signature"));
  });

  test("verifyTokenIdentity fails after identity revocation", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "revoke-test", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Verify works before revocation
    const beforeRevoke = await broker.verifyTokenIdentity(token);
    assert.strictEqual(beforeRevoke.valid, true);

    // Revoke the identity
    await broker.revokeIdentity(identity.persistentId);

    // Verification should now fail (identity no longer exists)
    const afterRevoke = await broker.verifyTokenIdentity(token);
    assert.strictEqual(afterRevoke.valid, false);
  });

  test("impersonation: cannot claim another agent's identity", async () => {
    const realIdentity = await broker.createIdentity({ type: "keypair", label: "real" });
    const fakeIdentity = await broker.createIdentity({ type: "keypair", label: "fake" });

    // Create a token legitimately bound to the real identity
    const realToken = await broker.createRootTokenWithIdentity(
      { agentId: "real-agent", scopes: ["github:repo:read"] },
      realIdentity.persistentId
    );

    // Attacker tries to swap the persistent ID to claim they're the fake identity
    // while keeping the real identity's proof
    const tamperedToken = {
      ...realToken,
      persistentIdentity: {
        ...realToken.persistentIdentity!,
        persistentId: fakeIdentity.persistentId, // Swap identity
        // proof is still from realIdentity — won't match fakeIdentity's public key
      },
    };

    const result = await broker.verifyTokenIdentity(tamperedToken);
    assert.strictEqual(result.valid, false);
  });

  test("proof from delegated child token is also verifiable", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const parent = await broker.createRootTokenWithIdentity(
      { agentId: "parent", scopes: ["github:repo:read", "github:repo:write"] },
      identity.persistentId
    );

    // Delegate to child — inherits identity + proof
    const child = broker.delegate(parent, {
      agentId: "child",
      requestedScopes: ["github:repo:read"],
    });

    // Child should have the same identity proof
    assert.ok(child.persistentIdentity);
    assert.strictEqual(child.persistentIdentity!.persistentId, identity.persistentId);
    assert.ok(child.persistentIdentity!.proof);

    // And it should verify
    const result = await broker.verifyTokenIdentity(child);
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.persistentId, identity.persistentId);
  });
});

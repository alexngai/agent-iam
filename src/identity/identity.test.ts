/**
 * Tests for persistent identity system
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as crypto from "crypto";
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

// ─────────────────────────────────────────────────────────────────
// STANDALONE VERIFICATION (no broker required)
// ─────────────────────────────────────────────────────────────────

import { verifyIdentityProof, createEndorsement } from "./standalone-verifier.js";

describe("Standalone identity verification (no broker)", () => {
  let tmpDir: string;
  let broker: Broker;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-standalone-"));
    broker = new Broker(tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("verifies keypair identity using only token data", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "remote-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Verify without broker — this is what a remote service would do
    const result = verifyIdentityProof(token);

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.persistentId, identity.persistentId);
    assert.ok(result.publicKey);
  });

  test("token includes public key for remote verification", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    assert.ok(token.persistentIdentity!.publicKey);
    assert.ok(token.persistentIdentity!.publicKey!.includes("BEGIN PUBLIC KEY"));
  });

  test("rejects token with no persistent identity", () => {
    const token = broker.createRootToken({
      agentId: "anon",
      scopes: ["github:repo:read"],
    });

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("no persistent identity"));
  });

  test("rejects token with no public key (platform identity)", async () => {
    // Platform identities use HMAC — no public key to verify standalone
    const identity = await broker.createIdentity({ type: "platform" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "platform-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    // Platform identity has no public key in metadata, so it fails with no publicKey
  });

  test("rejects token with mismatched public key (impersonation attempt)", async () => {
    const realIdentity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      realIdentity.persistentId
    );

    // Attacker generates a different keypair and substitutes it
    const { publicKey: fakeKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    token.persistentIdentity!.publicKey = fakeKey;

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("fingerprint mismatch"));
  });

  test("rejects token with tampered proof", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Tamper with the proof (note: standalone verifier checks the Ed25519 sig,
    // not the HMAC, so this tests a different layer)
    const proofBytes = Buffer.from(token.persistentIdentity!.proof!, "base64url");
    proofBytes[0] ^= 0xff; // Flip bits
    token.persistentIdentity!.proof = proofBytes.toString("base64url");

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("invalid"));
  });

  test("same identity verifies consistently across multiple tokens", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });

    const token1 = await broker.createRootTokenWithIdentity(
      { agentId: "agent-session-1", scopes: ["github:repo:read"] },
      identity.persistentId
    );
    const token2 = await broker.createRootTokenWithIdentity(
      { agentId: "agent-session-2", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const result1 = verifyIdentityProof(token1);
    const result2 = verifyIdentityProof(token2);

    assert.strictEqual(result1.valid, true);
    assert.strictEqual(result2.valid, true);
    // Same identity across sessions
    assert.strictEqual(result1.persistentId, result2.persistentId);
    assert.strictEqual(result1.publicKey, result2.publicKey);
  });
});

// ─────────────────────────────────────────────────────────────────
// AUTHORITY ENDORSEMENTS
// ─────────────────────────────────────────────────────────────────

describe("Authority endorsements", () => {
  let tmpDir: string;
  let broker: Broker;
  let authorityPrivateKey: string;
  let authorityPublicKey: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-endorse-"));
    broker = new Broker(tmpDir);

    // Generate an authority keypair
    const keypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    authorityPrivateKey = keypair.privateKey;
    authorityPublicKey = keypair.publicKey;
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test("authority can endorse an agent identity", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "endorsed-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Authority endorses the agent
    const endorsement = createEndorsement(
      "acme-corp",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "member-of:acme-engineering"
    );

    // Attach endorsement to token
    token.persistentIdentity!.endorsements = [endorsement];

    // Verify with the authority's public key as trusted
    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "acme-corp": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 1);
    assert.strictEqual(result.verifiedEndorsements![0].authorityId, "acme-corp");
    assert.strictEqual(result.verifiedEndorsements![0].claim, "member-of:acme-engineering");
  });

  test("endorsement from untrusted authority is ignored", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const endorsement = createEndorsement(
      "unknown-corp",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "some-claim"
    );
    token.persistentIdentity!.endorsements = [endorsement];

    // Don't include "unknown-corp" in trusted authorities
    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "other-corp": authorityPublicKey },
    });

    // Identity itself is still valid, but no endorsements verified
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("endorsement with forged authority key is rejected", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Attacker generates a different authority key and creates endorsement
    const fakeKeypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const fakeEndorsement = createEndorsement(
      "acme-corp",
      fakeKeypair.privateKey,
      fakeKeypair.publicKey, // Fake authority's public key
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "member-of:acme-engineering"
    );
    token.persistentIdentity!.endorsements = [fakeEndorsement];

    // Service trusts the real acme-corp key, not the fake one
    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "acme-corp": authorityPublicKey },
    });

    // Identity valid, but endorsement rejected (wrong key)
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("expired endorsement is not verified", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const endorsement = createEndorsement(
      "acme-corp",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "member-of:acme",
      new Date(Date.now() - 1000).toISOString() // Already expired
    );
    token.persistentIdentity!.endorsements = [endorsement];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "acme-corp": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("multiple endorsements from different authorities", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Second authority
    const auth2 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const endorsement1 = createEndorsement(
      "acme-corp", authorityPrivateKey, authorityPublicKey,
      identity.persistentId, token.persistentIdentity!.publicKey!,
      "member-of:acme"
    );
    const endorsement2 = createEndorsement(
      "security-auditor", auth2.privateKey, auth2.publicKey,
      identity.persistentId, token.persistentIdentity!.publicKey!,
      "security-vetted"
    );
    token.persistentIdentity!.endorsements = [endorsement1, endorsement2];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: {
        "acme-corp": authorityPublicKey,
        "security-auditor": auth2.publicKey,
      },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 2);
  });

  test("TOFU flow: first contact then recognition", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "new-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // First contact: service has never seen this agent
    const firstContact = verifyIdentityProof(token);
    assert.strictEqual(firstContact.valid, true);
    assert.strictEqual(firstContact.verifiedEndorsements!.length, 0);

    // Service stores the public key (simulated)
    const storedPublicKey = firstContact.publicKey;
    const storedPersistentId = firstContact.persistentId;

    // Second session: agent comes back with a new token, same identity
    const token2 = await broker.createRootTokenWithIdentity(
      { agentId: "returning-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const secondContact = verifyIdentityProof(token2);
    assert.strictEqual(secondContact.valid, true);

    // Service confirms it's the same agent
    assert.strictEqual(secondContact.persistentId, storedPersistentId);
    assert.strictEqual(secondContact.publicKey, storedPublicKey);
  });

  test("platform identity standalone verification gives helpful error", async () => {
    const identity = await broker.createIdentity({ type: "platform" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "platform-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    // Platform identity has no public key, so the error tells the user they can't verify without broker
    assert.ok(result.error!.includes("cannot verify without broker"));
  });
});

// ─────────────────────────────────────────────────────────────────
// ERROR PATH TESTS
// ─────────────────────────────────────────────────────────────────

describe("Error handling and edge cases", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-errors-"));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  // --- KeypairIdentityProvider error paths ---

  test("keypair prove() with corrupted private key gives clear error", async () => {
    const provider = new KeypairIdentityProvider(tmpDir);
    const identity = await provider.create();
    const fingerprint = identity.persistentId.slice(4);

    // Corrupt the private key file
    const keyPath = path.join(tmpDir, "identities", `${fingerprint}.key`);
    fs.writeFileSync(keyPath, "this is not a valid PEM key");

    await assert.rejects(
      () => provider.prove(identity.persistentId, "challenge"),
      (err: Error) => {
        assert.ok(err.message.includes("Failed to sign"));
        assert.ok(err.message.includes("corrupted"));
        return true;
      }
    );
  });

  test("keypair verify() with corrupted public key returns false", async () => {
    const provider = new KeypairIdentityProvider(tmpDir);
    const identity = await provider.create();
    const challenge = "test-challenge";
    const proof = await provider.prove(identity.persistentId, challenge);

    // Corrupt the metadata file's public key
    const fingerprint = identity.persistentId.slice(4);
    const metaPath = path.join(tmpDir, "identities", `${fingerprint}.json`);
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf-8"));
    meta.metadata.publicKey = "not a valid PEM";
    fs.writeFileSync(metaPath, JSON.stringify(meta));

    const valid = await provider.verify(proof, challenge);
    assert.strictEqual(valid, false);
  });

  test("keypair revoke() throws on invalid persistentId format", async () => {
    const provider = new KeypairIdentityProvider(tmpDir);

    await assert.rejects(
      () => provider.revoke("invalid-id"),
      /must start with "key:"/
    );
  });

  test("keypair revoke() succeeds silently when key files are already gone", async () => {
    const provider = new KeypairIdentityProvider(tmpDir);
    const identity = await provider.create();

    // Manually delete the key files
    const fingerprint = identity.persistentId.slice(4);
    fs.unlinkSync(path.join(tmpDir, "identities", `${fingerprint}.key`));
    fs.unlinkSync(path.join(tmpDir, "identities", `${fingerprint}.json`));

    // Should not throw
    await provider.revoke(identity.persistentId);
  });

  // --- PlatformIdentityProvider error paths ---

  test("platform loadRegistry() throws on corrupted JSON", async () => {
    const provider = new PlatformIdentityProvider(tmpDir, "test");

    // Create the identities directory and write corrupted JSON
    const dir = path.join(tmpDir, "identities");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "platform-registry.json"), "{{not json!!");

    await assert.rejects(
      () => provider.list(),
      /corrupted/
    );
  });

  test("platform loadRegistry() throws on JSON missing identities field", async () => {
    const provider = new PlatformIdentityProvider(tmpDir, "test");

    const dir = path.join(tmpDir, "identities");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "platform-registry.json"), '{"foo": "bar"}');

    await assert.rejects(
      () => provider.list(),
      /corrupted/
    );
  });

  test("platform revoke() throws on invalid persistentId format", async () => {
    const provider = new PlatformIdentityProvider(tmpDir, "test");

    await assert.rejects(
      () => provider.revoke("key:something"),
      /must start with "platform:"/
    );
  });

  test("platform revoke() throws on unknown identity", async () => {
    const provider = new PlatformIdentityProvider(tmpDir, "test");

    await assert.rejects(
      () => provider.revoke("platform:nonexistent-uuid"),
      /not found/
    );
  });

  // --- createEndorsement validation ---

  test("createEndorsement throws on empty authorityId", () => {
    assert.throws(
      () => createEndorsement("", "key", "key", "id", "pk", "claim"),
      /authorityId is required/
    );
  });

  test("createEndorsement throws on empty claim", () => {
    assert.throws(
      () => createEndorsement("auth", "key", "key", "id", "pk", ""),
      /claim is required/
    );
  });

  test("createEndorsement throws on invalid private key", () => {
    assert.throws(
      () => createEndorsement("auth", "not-a-key", "not-a-key", "id", "pk", "claim"),
      /invalid authority private key/
    );
  });

  // --- Delegation identity inheritance edge cases ---

  test("delegation with inheritPersistentIdentity false clears identity", async () => {
    const service = new IdentityService({ defaultType: "keypair" });
    service.registerProvider(new KeypairIdentityProvider(tmpDir));
    const tokenService = new TokenService(generateSecret());

    const identity = await service.createIdentity({ type: "keypair" });
    const parent = tokenService.createRootToken({
      agentId: "parent",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: identity.persistentId,
        identityType: identity.identityType,
      },
    });

    const child = tokenService.delegate(parent, {
      agentId: "child",
      requestedScopes: ["github:repo:read"],
      inheritPersistentIdentity: false,
    });

    assert.strictEqual(child.persistentIdentity, undefined);
  });

  // --- Standalone verifier edge cases ---

  test("standalone verifier rejects token with publicKey but no proof", () => {
    const broker = new Broker(tmpDir);
    const token = broker.createRootToken({
      agentId: "agent",
      scopes: ["github:repo:read"],
      persistentIdentity: {
        persistentId: "key:fakefingerprint",
        identityType: "keypair",
        publicKey: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----",
        // proof and challenge intentionally omitted
      },
    });

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
    assert.ok(result.error!.includes("no proof or challenge"));
  });

  test("standalone verifier handles malformed base64url signature gracefully", async () => {
    const broker = new Broker(tmpDir);
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Replace proof with something that's valid base64url but not a valid signature
    token.persistentIdentity!.proof = "AAAA";

    const result = verifyIdentityProof(token);
    assert.strictEqual(result.valid, false);
  });

  test("keypair serialization round-trip with publicKey and endorsements", async () => {
    const broker = new Broker(tmpDir);
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Add a fake endorsement
    const authorityKeypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const endorsement = createEndorsement(
      "test-authority",
      authorityKeypair.privateKey,
      authorityKeypair.publicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "test-claim"
    );
    token.persistentIdentity!.endorsements = [endorsement];

    // Serialize and deserialize
    const serialized = JSON.stringify(token);
    const deserialized = JSON.parse(serialized);

    assert.ok(deserialized.persistentIdentity.publicKey);
    assert.ok(deserialized.persistentIdentity.publicKey.includes("BEGIN PUBLIC KEY"));
    assert.strictEqual(deserialized.persistentIdentity.endorsements.length, 1);
    assert.strictEqual(deserialized.persistentIdentity.endorsements[0].claim, "test-claim");
  });

  test("multiple endorsements with mix of expired and valid", async () => {
    const broker = new Broker(tmpDir);
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const auth = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const validEndorsement = createEndorsement(
      "authority", auth.privateKey, auth.publicKey,
      identity.persistentId, token.persistentIdentity!.publicKey!,
      "valid-claim",
      new Date(Date.now() + 86400000).toISOString() // expires tomorrow
    );
    const expiredEndorsement = createEndorsement(
      "authority", auth.privateKey, auth.publicKey,
      identity.persistentId, token.persistentIdentity!.publicKey!,
      "expired-claim",
      new Date(Date.now() - 1000).toISOString() // already expired
    );
    token.persistentIdentity!.endorsements = [validEndorsement, expiredEndorsement];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "authority": auth.publicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 1);
    assert.strictEqual(result.verifiedEndorsements![0].claim, "valid-claim");
  });

  test("refresh preserves persistentIdentity with publicKey", async () => {
    const broker = new Broker(tmpDir);
    const tokenService = new TokenService(generateSecret());
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"], ttlDays: 1 },
      identity.persistentId
    );

    const newExpiry = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const refreshed = tokenService.createRefreshedToken(token, newExpiry);

    assert.ok(refreshed.persistentIdentity);
    assert.strictEqual(refreshed.persistentIdentity!.persistentId, identity.persistentId);
    assert.ok(refreshed.persistentIdentity!.publicKey);
    assert.ok(refreshed.persistentIdentity!.proof);
    assert.strictEqual(refreshed.expiresAt, newExpiry);
  });
});

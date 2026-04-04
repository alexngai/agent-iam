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

  test("creates a keypair identity with did:key: prefix", async () => {
    const identity = await provider.create({ label: "test-agent" });

    assert.ok(identity.persistentId.startsWith("did:key:z6Mk"), `Expected did:key:z6Mk prefix, got: ${identity.persistentId}`);
    assert.strictEqual(identity.identityType, "keypair");
    assert.strictEqual(identity.label, "test-agent");
    assert.ok(identity.metadata.publicKey);
    assert.ok(identity.metadata.publicKeyJwk);
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
    const fingerprint = identity.metadata.fingerprint as string;
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
    assert.ok(identity.persistentId.startsWith("did:key:z6Mk"), `Expected did:key:z6Mk prefix, got: ${identity.persistentId}`);
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
    assert.ok(result.error!.includes("mismatch"), `Expected mismatch error, got: ${result.error}`);
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
    const fingerprint = identity.metadata.fingerprint as string;

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
    const fingerprint = identity.metadata.fingerprint as string;
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
      /must start with "did:key:" or "key:"/
    );
  });

  test("keypair revoke() succeeds silently when key files are already gone", async () => {
    const provider = new KeypairIdentityProvider(tmpDir);
    const identity = await provider.create();

    // Manually delete the key files
    const fingerprint = identity.metadata.fingerprint as string;
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

// ─────────────────────────────────────────────────────────────────
// DID:KEY AND JWK SUPPORT
// ─────────────────────────────────────────────────────────────────

import {
  publicKeyToDidKey,
  didKeyToRawPublicKey,
  rawPublicKeyToPem,
  publicKeyToJwk,
  jwkToPem,
  isDidKey,
  isLegacyKeyId,
  base58btcEncode,
  base58btcDecode,
} from "./did-key.js";
import { createVcEndorsement, computeVcSigningPayload } from "./standalone-verifier.js";
import { canonicalize } from "./jcs.js";
import { isVerifiableCredential, isLegacyEndorsement } from "../types.js";

describe("DID:key encoding/decoding", () => {
  test("base58btc round-trip", () => {
    const original = crypto.randomBytes(34);
    const encoded = base58btcEncode(original);
    const decoded = base58btcDecode(encoded);
    assert.deepStrictEqual(decoded, original);
  });

  test("base58btc handles leading zeros", () => {
    const bytes = Buffer.from([0, 0, 0, 1, 2, 3]);
    const encoded = base58btcEncode(bytes);
    assert.ok(encoded.startsWith("111")); // Three leading 1s for three zero bytes
    const decoded = base58btcDecode(encoded);
    assert.deepStrictEqual(decoded, bytes);
  });

  test("base58btc rejects invalid characters", () => {
    assert.throws(() => base58btcDecode("invalid0OIl"), /Invalid base58btc character/);
  });

  test("publicKeyToDidKey produces valid DID:key format", () => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const did = publicKeyToDidKey(publicKey);
    assert.ok(did.startsWith("did:key:z6Mk"), `Expected did:key:z6Mk prefix, got: ${did}`);
    assert.ok(isDidKey(did));
    assert.ok(!isLegacyKeyId(did));
  });

  test("DID:key round-trip: encode then decode recovers the same public key", () => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const did = publicKeyToDidKey(publicKey);
    const rawKey = didKeyToRawPublicKey(did);
    const recoveredPem = rawPublicKeyToPem(rawKey);

    assert.strictEqual(recoveredPem.trim(), publicKey.trim());
  });

  test("didKeyToRawPublicKey rejects invalid DID prefix", () => {
    assert.throws(() => didKeyToRawPublicKey("did:web:example.com"), /must start with "did:key:z"/);
  });

  test("didKeyToRawPublicKey rejects wrong multicodec prefix", () => {
    // Encode with wrong prefix (0x1234 instead of 0xed01)
    const fakeKey = Buffer.concat([Buffer.from([0x12, 0x34]), crypto.randomBytes(32)]);
    const fakeDidKey = `did:key:z${base58btcEncode(fakeKey)}`;
    assert.throws(() => didKeyToRawPublicKey(fakeDidKey), /Invalid multicodec prefix/);
  });

  test("same key always produces the same DID:key", () => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const did1 = publicKeyToDidKey(publicKey);
    const did2 = publicKeyToDidKey(publicKey);
    assert.strictEqual(did1, did2);
  });

  test("different keys produce different DID:keys", () => {
    const key1 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    const key2 = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    assert.notStrictEqual(publicKeyToDidKey(key1.publicKey), publicKeyToDidKey(key2.publicKey));
  });
});

describe("JWK support", () => {
  test("publicKeyToJwk produces valid Ed25519 JWK", () => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const jwk = publicKeyToJwk(publicKey);
    assert.strictEqual(jwk.kty, "OKP");
    assert.strictEqual(jwk.crv, "Ed25519");
    assert.ok(jwk.x, "JWK should have x parameter");
    // x should be base64url-encoded 32 bytes
    const xBytes = Buffer.from(jwk.x as string, "base64url");
    assert.strictEqual(xBytes.length, 32);
  });

  test("JWK round-trip: PEM → JWK → PEM", () => {
    const { publicKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const jwk = publicKeyToJwk(publicKey);
    const recoveredPem = jwkToPem(jwk);
    assert.strictEqual(recoveredPem.trim(), publicKey.trim());
  });

  test("token includes publicKeyJwk when created via broker", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-jwk-"));
    try {
      const broker = new Broker(tmpDir2);
      const identity = await broker.createIdentity({ type: "keypair" });
      const token = await broker.createRootTokenWithIdentity(
        { agentId: "jwk-agent", scopes: ["github:repo:read"] },
        identity.persistentId
      );

      assert.ok(token.persistentIdentity!.publicKeyJwk, "Token should have publicKeyJwk");
      assert.strictEqual(token.persistentIdentity!.publicKeyJwk!.kty, "OKP");
      assert.strictEqual(token.persistentIdentity!.publicKeyJwk!.crv, "Ed25519");

      // JWK and PEM should represent the same key
      const pemFromJwk = jwkToPem(token.persistentIdentity!.publicKeyJwk!);
      assert.strictEqual(pemFromJwk.trim(), token.persistentIdentity!.publicKey!.trim());
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });
});

describe("DID:key migration", () => {
  test("migrates legacy key: identity to did:key: format", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-migrate-"));
    try {
      const provider = new KeypairIdentityProvider(tmpDir2);

      // Manually create a legacy-format identity
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

      const identityDir = path.join(tmpDir2, "identities");
      fs.mkdirSync(identityDir, { recursive: true, mode: 0o700 });
      fs.writeFileSync(
        path.join(identityDir, `${fingerprint}.key`),
        privateKey,
        { mode: 0o600 }
      );
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

      // Verify legacy identity loads
      const legacy = await provider.load(legacyId);
      assert.ok(legacy);
      assert.strictEqual(legacy!.persistentId, legacyId);

      // Migrate
      const migrated = await provider.migrate(legacyId);
      assert.ok(migrated);
      assert.ok(migrated!.persistentId.startsWith("did:key:z6Mk"));
      assert.ok(migrated!.metadata.publicKeyJwk, "Migration should add JWK");

      // Load using new DID:key ID
      const loaded = await provider.load(migrated!.persistentId);
      assert.ok(loaded);
      assert.strictEqual(loaded!.persistentId, migrated!.persistentId);

      // Prove/verify still works with new ID
      const challenge = "migration-test-challenge";
      const proof = await provider.prove(migrated!.persistentId, challenge);
      const valid = await provider.verify(proof, challenge);
      assert.strictEqual(valid, true);
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  test("migrate() rejects non-legacy IDs", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-migrate-"));
    try {
      const provider = new KeypairIdentityProvider(tmpDir2);
      await assert.rejects(
        () => provider.migrate("did:key:z6MkInvalid"),
        /Not a legacy key: identity/
      );
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });
});

describe("Backward compatibility — legacy key: format", () => {
  test("legacy key: identities can still be loaded and proven", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-compat-"));
    try {
      const provider = new KeypairIdentityProvider(tmpDir2);

      // Create a legacy-format identity on disk
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

      const identityDir = path.join(tmpDir2, "identities");
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

      // Load, prove, verify with legacy ID
      const loaded = await provider.load(legacyId);
      assert.ok(loaded);
      assert.strictEqual(loaded!.persistentId, legacyId);

      const challenge = "legacy-compat-challenge";
      const proof = await provider.prove(legacyId, challenge);
      const valid = await provider.verify(proof, challenge);
      assert.strictEqual(valid, true);
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  test("standalone verifier accepts legacy key: tokens", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-compat-"));
    try {
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
      const challenge = "legacy-standalone-challenge";

      const privateKeyObj = crypto.createPrivateKey(privateKey);
      const proof = crypto.sign(null, Buffer.from(challenge), privateKeyObj).toString("base64url");

      // Build a token with legacy key: format
      const token = {
        agentId: "legacy-agent",
        scopes: ["github:repo:read"],
        constraints: {},
        delegatable: true,
        maxDelegationDepth: 3,
        currentDepth: 0,
        persistentIdentity: {
          persistentId: legacyId,
          identityType: "keypair",
          proof,
          challenge,
          publicKey,
        },
      } as any;

      const result = verifyIdentityProof(token);
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.persistentId, legacyId);
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  test("IdentityService.inferType routes did:key: to keypair provider", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-infer-"));
    try {
      const service = new IdentityService({ defaultType: "keypair" });
      const provider = new KeypairIdentityProvider(tmpDir2);
      service.registerProvider(provider);

      const identity = await service.createIdentity({ type: "keypair" });
      assert.ok(identity.persistentId.startsWith("did:key:"));

      // Load via IdentityService should route to keypair provider
      const loaded = await service.loadIdentity(identity.persistentId);
      assert.ok(loaded);
      assert.strictEqual(loaded!.persistentId, identity.persistentId);
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });
});

describe("DID:key standalone verification", () => {
  test("verifies DID:key identity using only token data", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-didverify-"));
    try {
      const broker = new Broker(tmpDir2);
      const identity = await broker.createIdentity({ type: "keypair" });
      const token = await broker.createRootTokenWithIdentity(
        { agentId: "did-agent", scopes: ["github:repo:read"] },
        identity.persistentId
      );

      assert.ok(token.persistentIdentity!.persistentId.startsWith("did:key:"));

      const result = verifyIdentityProof(token);
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.persistentId, identity.persistentId);
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  test("rejects DID:key token with substituted public key", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-didverify-"));
    try {
      const broker = new Broker(tmpDir2);
      const identity = await broker.createIdentity({ type: "keypair" });
      const token = await broker.createRootTokenWithIdentity(
        { agentId: "agent", scopes: ["github:repo:read"] },
        identity.persistentId
      );

      // Substitute a different public key
      const { publicKey: fakeKey } = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      token.persistentIdentity!.publicKey = fakeKey;

      const result = verifyIdentityProof(token);
      assert.strictEqual(result.valid, false);
      assert.ok(result.error!.includes("mismatch"));
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });

  test("endorsements work with DID:key identities", async () => {
    const tmpDir2 = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-didendorse-"));
    try {
      const broker = new Broker(tmpDir2);
      const identity = await broker.createIdentity({ type: "keypair" });
      const token = await broker.createRootTokenWithIdentity(
        { agentId: "endorsed-agent", scopes: ["github:repo:read"] },
        identity.persistentId
      );

      const authorityKeypair = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });

      const endorsement = createEndorsement(
        "standards-authority",
        authorityKeypair.privateKey,
        authorityKeypair.publicKey,
        identity.persistentId,
        token.persistentIdentity!.publicKey!,
        "certified-agent"
      );
      token.persistentIdentity!.endorsements = [endorsement];

      const result = verifyIdentityProof(token, {
        trustedAuthorities: { "standards-authority": authorityKeypair.publicKey },
      });

      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.verifiedEndorsements!.length, 1);
      assert.strictEqual(result.verifiedEndorsements![0].claim, "certified-agent");
    } finally {
      fs.rmSync(tmpDir2, { recursive: true, force: true });
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// JCS CANONICALIZATION (RFC 8785)
// ─────────────────────────────────────────────────────────────────

describe("JCS canonicalization", () => {
  test("sorts object keys lexicographically", () => {
    const result = canonicalize({ z: 1, a: 2, m: 3 });
    assert.strictEqual(result, '{"a":2,"m":3,"z":1}');
  });

  test("handles nested objects", () => {
    const result = canonicalize({ b: { z: 1, a: 2 }, a: "hello" });
    assert.strictEqual(result, '{"a":"hello","b":{"a":2,"z":1}}');
  });

  test("handles arrays (preserves order)", () => {
    const result = canonicalize({ items: [3, 1, 2] });
    assert.strictEqual(result, '{"items":[3,1,2]}');
  });

  test("handles null", () => {
    assert.strictEqual(canonicalize(null), "null");
  });

  test("handles booleans", () => {
    assert.strictEqual(canonicalize(true), "true");
    assert.strictEqual(canonicalize(false), "false");
  });

  test("handles strings with special characters", () => {
    assert.strictEqual(canonicalize("hello\nworld"), '"hello\\nworld"');
  });

  test("omits undefined values", () => {
    const result = canonicalize({ a: 1, b: undefined, c: 3 });
    assert.strictEqual(result, '{"a":1,"c":3}');
  });

  test("deterministic: same input always same output", () => {
    const obj = { issuer: { id: "did:key:z6Mk123" }, claim: "test" };
    const r1 = canonicalize(obj);
    const r2 = canonicalize(obj);
    assert.strictEqual(r1, r2);
  });

  test("rejects Infinity and NaN", () => {
    assert.throws(() => canonicalize(Infinity), /Infinity/);
    assert.throws(() => canonicalize(NaN), /NaN/);
  });
});

// ─────────────────────────────────────────────────────────────────
// VC-FORMAT ENDORSEMENTS
// ─────────────────────────────────────────────────────────────────

describe("VC-format endorsements", () => {
  let tmpDir: string;
  let broker: Broker;
  let authorityPrivateKey: string;
  let authorityPublicKey: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-vc-"));
    broker = new Broker(tmpDir);

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

  test("createVcEndorsement produces valid VC structure", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });

    const vc = createVcEndorsement(
      "did:web:acme-corp.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "member-of:acme-engineering",
      { issuerName: "Acme Corp" }
    );

    assert.strictEqual(vc.type, "VerifiableCredential");
    assert.strictEqual(vc.issuer.id, "did:web:acme-corp.com");
    assert.strictEqual(vc.issuer.name, "Acme Corp");
    assert.strictEqual(vc.credentialSubject.id, identity.persistentId);
    assert.strictEqual(vc.credentialSubject.claim, "member-of:acme-engineering");
    assert.strictEqual(vc.proof.type, "Ed25519Signature2020");
    assert.ok(vc.proof.proofValue);
    assert.ok(vc.issuanceDate);
    assert.strictEqual(vc.expirationDate, undefined);
  });

  test("createVcEndorsement with expiration date", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const expiry = new Date(Date.now() + 86400000).toISOString();

    const vc = createVcEndorsement(
      "did:web:acme-corp.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "certified",
      { expirationDate: expiry }
    );

    assert.strictEqual(vc.expirationDate, expiry);
  });

  test("VC endorsement verifies via standalone verifier", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "vc-endorsed-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const vc = createVcEndorsement(
      "did:web:acme-corp.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "member-of:acme-engineering"
    );

    token.persistentIdentity!.endorsements = [vc];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "did:web:acme-corp.com": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 1);
    assert.strictEqual(result.verifiedEndorsements![0].authorityId, "did:web:acme-corp.com");
    assert.strictEqual(result.verifiedEndorsements![0].claim, "member-of:acme-engineering");
  });

  test("VC endorsement from untrusted issuer is ignored", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const vc = createVcEndorsement(
      "did:web:untrusted.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "some-claim"
    );
    token.persistentIdentity!.endorsements = [vc];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "did:web:acme-corp.com": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("expired VC endorsement is not verified", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const vc = createVcEndorsement(
      "did:web:acme-corp.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "expired-claim",
      { expirationDate: new Date(Date.now() - 1000).toISOString() }
    );
    token.persistentIdentity!.endorsements = [vc];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "did:web:acme-corp.com": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("VC endorsement with forged signature is rejected", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    // Create endorsement with a different private key
    const fakeKeypair = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const vc = createVcEndorsement(
      "did:web:acme-corp.com",
      fakeKeypair.privateKey,
      fakeKeypair.publicKey,
      identity.persistentId,
      "forged-claim"
    );
    token.persistentIdentity!.endorsements = [vc];

    // Trust the real authority key, not the forger's
    const result = verifyIdentityProof(token, {
      trustedAuthorities: { "did:web:acme-corp.com": authorityPublicKey },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 0);
  });

  test("type guards distinguish VC from legacy endorsements", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const legacyEndorsement = createEndorsement(
      "legacy-authority",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "legacy-claim"
    );

    const vcEndorsement = createVcEndorsement(
      "did:web:modern-authority.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "vc-claim"
    );

    assert.strictEqual(isLegacyEndorsement(legacyEndorsement), true);
    assert.strictEqual(isVerifiableCredential(legacyEndorsement), false);
    assert.strictEqual(isVerifiableCredential(vcEndorsement), true);
    assert.strictEqual(isLegacyEndorsement(vcEndorsement), false);
  });

  test("mixed legacy and VC endorsements on same token", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });
    const token = await broker.createRootTokenWithIdentity(
      { agentId: "mixed-agent", scopes: ["github:repo:read"] },
      identity.persistentId
    );

    const legacyEndorsement = createEndorsement(
      "legacy-corp",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      token.persistentIdentity!.publicKey!,
      "legacy-claim"
    );

    const vcEndorsement = createVcEndorsement(
      "did:web:modern-corp.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "modern-claim"
    );

    token.persistentIdentity!.endorsements = [legacyEndorsement, vcEndorsement];

    const result = verifyIdentityProof(token, {
      trustedAuthorities: {
        "legacy-corp": authorityPublicKey,
        "did:web:modern-corp.com": authorityPublicKey,
      },
    });

    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.verifiedEndorsements!.length, 2);

    const claims = result.verifiedEndorsements!.map(e => e.claim).sort();
    assert.deepStrictEqual(claims, ["legacy-claim", "modern-claim"]);
  });

  test("createVcEndorsement throws on empty issuerId", () => {
    assert.throws(
      () => createVcEndorsement("", "key", "key", "id", "claim"),
      /issuerId is required/
    );
  });

  test("createVcEndorsement throws on invalid private key", () => {
    assert.throws(
      () => createVcEndorsement("did:web:x.com", "bad-key", "key", "id", "claim"),
      /invalid issuer private key/
    );
  });

  test("VC signing payload is deterministic via JCS", async () => {
    const issuer = { id: "did:web:acme.com", name: "Acme" };
    const subject = { id: "did:key:z6MkTest", claim: "test-claim" };
    const date = "2025-01-01T00:00:00.000Z";

    const payload1 = computeVcSigningPayload(issuer, subject, date);
    const payload2 = computeVcSigningPayload(issuer, subject, date);

    assert.strictEqual(payload1, payload2);
    // Should be sorted by keys
    assert.ok(payload1.includes('"credentialSubject"'));
    assert.ok(payload1.includes('"issuanceDate"'));
    assert.ok(payload1.includes('"issuer"'));
  });

  test("VC serialization round-trip preserves all fields", async () => {
    const identity = await broker.createIdentity({ type: "keypair" });

    const vc = createVcEndorsement(
      "did:web:acme.com",
      authorityPrivateKey,
      authorityPublicKey,
      identity.persistentId,
      "test-claim",
      {
        issuerName: "Acme Corp",
        expirationDate: new Date(Date.now() + 86400000).toISOString(),
      }
    );

    const serialized = JSON.stringify(vc);
    const deserialized = JSON.parse(serialized);

    assert.strictEqual(deserialized.type, "VerifiableCredential");
    assert.strictEqual(deserialized.issuer.id, "did:web:acme.com");
    assert.strictEqual(deserialized.issuer.name, "Acme Corp");
    assert.strictEqual(deserialized.credentialSubject.id, identity.persistentId);
    assert.strictEqual(deserialized.credentialSubject.claim, "test-claim");
    assert.ok(deserialized.expirationDate);
    assert.ok(deserialized.proof.proofValue);
  });
});

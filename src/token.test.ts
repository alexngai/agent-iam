/**
 * Tests for token service
 */

import { test } from "node:test";
import * as assert from "node:assert";
import { TokenService, generateSecret, scopeMatches, resourceMatches } from "./token.js";

test("scopeMatches - exact match", () => {
  assert.strictEqual(scopeMatches("github:repo:read", "github:repo:read"), true);
  assert.strictEqual(scopeMatches("github:repo:read", "github:repo:write"), false);
});

test("scopeMatches - wildcard", () => {
  assert.strictEqual(scopeMatches("github:repo:*", "github:repo:read"), true);
  assert.strictEqual(scopeMatches("github:repo:*", "github:repo:write"), true);
  assert.strictEqual(scopeMatches("github:*", "github:repo:read"), true);
  assert.strictEqual(scopeMatches("*", "github:repo:read"), true);
});

test("scopeMatches - no false positives", () => {
  assert.strictEqual(scopeMatches("github:repo:*", "aws:s3:read"), false);
  assert.strictEqual(scopeMatches("github:repo:read", "github:repo:*"), false);
});

test("resourceMatches - exact match", () => {
  assert.strictEqual(resourceMatches("myorg/myrepo", "myorg/myrepo"), true);
  assert.strictEqual(resourceMatches("myorg/myrepo", "myorg/other"), false);
});

test("resourceMatches - glob patterns", () => {
  assert.strictEqual(resourceMatches("myorg/*", "myorg/repo"), true);
  assert.strictEqual(resourceMatches("myorg/*", "myorg/other"), true);
  assert.strictEqual(resourceMatches("myorg/*", "otherorg/repo"), false);
  assert.strictEqual(resourceMatches("*/repo", "myorg/repo"), true);
  assert.strictEqual(resourceMatches("myorg/repo-*", "myorg/repo-backend"), true);
});

test("TokenService - create and verify root token", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const token = service.createRootToken({
    agentId: "test-root",
    scopes: ["github:repo:read"],
    ttlDays: 1,
  });

  assert.strictEqual(token.agentId, "test-root");
  assert.deepStrictEqual(token.scopes, ["github:repo:read"]);
  assert.strictEqual(token.currentDepth, 0);
  assert.ok(token.signature);

  const result = service.verify(token);
  assert.strictEqual(result.valid, true);
});

test("TokenService - reject tampered token", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const token = service.createRootToken({
    agentId: "test-root",
    scopes: ["github:repo:read"],
  });

  // Tamper with the token
  const tampered = { ...token, scopes: ["github:repo:write"] };

  const result = service.verify(tampered);
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.error, "Invalid signature");
});

test("TokenService - delegation narrows scopes", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const parent = service.createRootToken({
    agentId: "parent",
    scopes: ["github:repo:read", "github:repo:write"],
    ttlDays: 1,
  });

  const child = service.delegate(parent, {
    agentId: "child",
    requestedScopes: ["github:repo:read"],
    ttlMinutes: 60,
  });

  assert.strictEqual(child.parentId, "parent");
  assert.deepStrictEqual(child.scopes, ["github:repo:read"]);
  assert.strictEqual(child.currentDepth, 1);
});

test("TokenService - delegation rejects unauthorized scope", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const parent = service.createRootToken({
    agentId: "parent",
    scopes: ["github:repo:read"],
  });

  assert.throws(
    () => {
      service.delegate(parent, {
        requestedScopes: ["aws:s3:read"],
      });
    },
    { message: 'Scope "aws:s3:read" not allowed by parent token' }
  );
});

test("TokenService - delegation respects max depth", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const root = service.createRootToken({
    agentId: "root",
    scopes: ["github:repo:read"],
    maxDelegationDepth: 1,
  });

  const child = service.delegate(root, {
    agentId: "child",
    requestedScopes: ["github:repo:read"],
  });

  assert.throws(
    () => {
      service.delegate(child, {
        requestedScopes: ["github:repo:read"],
      });
    },
    { message: "Delegation depth exceeded: 1 >= 1" }
  );
});

test("TokenService - checkPermission validates scope and resource", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const token = service.createRootToken({
    agentId: "test",
    scopes: ["github:repo:read"],
    constraints: {
      "github:repo:read": { resources: ["myorg/*"] },
    },
    ttlDays: 1,
  });

  // Valid scope and resource
  let result = service.checkPermission(token, "github:repo:read", "myorg/repo");
  assert.strictEqual(result.valid, true);

  // Invalid resource
  result = service.checkPermission(token, "github:repo:read", "otherorg/repo");
  assert.strictEqual(result.valid, false);
  assert.ok(result.error?.includes("not allowed"));

  // Invalid scope
  result = service.checkPermission(token, "github:repo:write", "myorg/repo");
  assert.strictEqual(result.valid, false);
});

test("TokenService - serialize and deserialize", () => {
  const secret = generateSecret();
  const service = new TokenService(secret);

  const token = service.createRootToken({
    agentId: "test",
    scopes: ["github:repo:read"],
    ttlDays: 1, // Include expiry to ensure full roundtrip
  });

  const serialized = service.serialize(token);
  const deserialized = service.deserialize(serialized);

  // Compare key fields (JSON doesn't preserve undefined)
  assert.strictEqual(deserialized.agentId, token.agentId);
  assert.deepStrictEqual(deserialized.scopes, token.scopes);
  assert.strictEqual(deserialized.signature, token.signature);
  assert.strictEqual(deserialized.expiresAt, token.expiresAt);

  // Verify the deserialized token is still valid
  const result = service.verify(deserialized);
  assert.strictEqual(result.valid, true);
});

console.log("All tests passed!");

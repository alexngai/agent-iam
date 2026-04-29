/**
 * Tests for RFC 8707 audience-bound MCP credentials.
 */

import { test, describe, before } from "node:test";
import * as assert from "node:assert";
import * as crypto from "crypto";
import { SignJWT, importPKCS8 } from "jose";
import { issueMCPCredential, verifyMCPCredential } from "./credential.js";
import type { AgentToken } from "../types.js";

/** Generate an Ed25519 keypair as PEM strings. */
function generateKeypair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return { privateKey: privateKey as string, publicKey: publicKey as string };
}

function tokenWith(scopes: string[], agentId = "agent-1"): AgentToken {
  return {
    agentId,
    scopes,
    constraints: {},
    delegatable: false,
    maxDelegationDepth: 0,
    currentDepth: 0,
  };
}

let signingKey: string;
let publicKey: string;
let altPublicKey: string;

before(() => {
  const kp = generateKeypair();
  signingKey = kp.privateKey;
  publicKey = kp.publicKey;
  altPublicKey = generateKeypair().publicKey;
});

// ─────────────────────────────────────────────────────────────────
// Issuance
// ─────────────────────────────────────────────────────────────────

describe("issueMCPCredential", () => {
  test("issues a JWT with expected audience and subject", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:filesystem:read_file"]),
      serverURI: "https://filesystem.example.com",
      scopes: ["mcp:filesystem:read_file"],
      signingKey,
      issuer: "broker.example.com",
    });

    assert.ok(cred.jwt);
    assert.ok(cred.expiresAt);
    assert.match(cred.jwt, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  test("rejects empty scopes (degenerate credential)", async () => {
    await assert.rejects(
      () =>
        issueMCPCredential({
          agentToken: tokenWith(["mcp:filesystem:*"]),
          serverURI: "https://filesystem.example.com",
          scopes: [],
          signingKey,
          issuer: "broker",
        }),
      /scopes must not be empty/
    );
  });

  test("rejects empty issuer (must be set for audit chain)", async () => {
    await assert.rejects(
      () =>
        issueMCPCredential({
          agentToken: tokenWith(["mcp:fs:read"]),
          serverURI: "https://fs",
          scopes: ["mcp:fs:read"],
          signingKey,
          issuer: "",
        }),
      /issuer is required/
    );
  });

  test("rejects empty serverURI (no audience to bind to)", async () => {
    await assert.rejects(
      () =>
        issueMCPCredential({
          agentToken: tokenWith(["mcp:fs:read"]),
          serverURI: "",
          scopes: ["mcp:fs:read"],
          signingKey,
          issuer: "broker",
        }),
      /serverURI is required/
    );
  });

  test("rejects scopes not granted by the agent token (defense in depth)", async () => {
    await assert.rejects(
      () =>
        issueMCPCredential({
          agentToken: tokenWith(["mcp:filesystem:read_file"]),
          serverURI: "https://filesystem.example.com",
          scopes: ["mcp:filesystem:write_file"],
          signingKey,
          issuer: "broker",
        }),
      /not granted by the agent token/
    );
  });

  test("accepts scopes covered by a token wildcard", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:filesystem:*"]),
      serverURI: "https://filesystem.example.com",
      scopes: ["mcp:filesystem:read_file", "mcp:filesystem:write_file"],
      signingKey,
      issuer: "broker",
    });
    assert.ok(cred.jwt);
  });

  test("expiresAt reflects ttlSeconds option", async () => {
    const before = Date.now();
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
      ttlSeconds: 60,
    });
    const expMs = new Date(cred.expiresAt).getTime();
    assert.ok(expMs - before >= 59_000 && expMs - before <= 61_000,
      `expected ~60s ttl, got ${expMs - before}ms`);
  });
});

// ─────────────────────────────────────────────────────────────────
// Verification — happy path
// ─────────────────────────────────────────────────────────────────

describe("verifyMCPCredential — happy path", () => {
  test("accepts a credential with matching audience", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:filesystem:read_file"]),
      serverURI: "https://filesystem.example.com",
      scopes: ["mcp:filesystem:read_file"],
      signingKey,
      issuer: "broker.example.com",
    });

    const v = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://filesystem.example.com",
    });

    assert.strictEqual(v.valid, true);
    if (v.valid) {
      assert.strictEqual(v.agentId, "agent-1");
      assert.strictEqual(v.audience, "https://filesystem.example.com");
      assert.strictEqual(v.issuer, "broker.example.com");
      assert.deepStrictEqual(v.scopes, ["mcp:filesystem:read_file"]);
    }
  });

  test("returns multi-scope credential as array", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:*"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read_file", "mcp:fs:list_dir"],
      signingKey,
      issuer: "broker",
    });
    const v = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    if (v.valid) {
      assert.deepStrictEqual(v.scopes, ["mcp:fs:read_file", "mcp:fs:list_dir"]);
    } else {
      assert.fail(`expected valid, got: ${v.error}`);
    }
  });

  test("accepts array-form `aud` claim (RFC 7519 spec compliance)", async () => {
    // Regression for review finding M1: third-party brokers may issue tokens
    // with multi-audience claims; we must accept those when the expected
    // audience appears in the array.
    const key = await importPKCS8(signingKey, "EdDSA");
    const now = Math.floor(Date.now() / 1000);
    const jwt = await new SignJWT({ scope: "mcp:fs:read" })
      .setProtectedHeader({ alg: "EdDSA" })
      .setIssuer("broker")
      .setSubject("agent-1")
      .setAudience(["https://fs", "https://fs-replica"]) // array form
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(key);

    const v = await verifyMCPCredential(jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, true);
    if (v.valid) {
      assert.strictEqual(v.audience, "https://fs");
    }

    // And ensure mismatched audience still fails on multi-aud tokens.
    const bad = await verifyMCPCredential(jwt, {
      publicKey,
      expectedAudience: "https://shell",
    });
    assert.strictEqual(bad.valid, false);
  });

  test("issuer match is enforced when expectedIssuer is set", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker-a",
    });

    const ok = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://fs",
      expectedIssuer: "broker-a",
    });
    assert.strictEqual(ok.valid, true);

    const bad = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://fs",
      expectedIssuer: "broker-b",
    });
    assert.strictEqual(bad.valid, false);
  });

  test("forwards optional `act` chain through verification", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
      act: ["user:alice", "agent:assistant"],
    });
    const v = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    if (v.valid) {
      assert.deepStrictEqual(v.act, ["user:alice", "agent:assistant"]);
    } else {
      assert.fail("expected valid");
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// Verification — RFC 8707 attacks
// ─────────────────────────────────────────────────────────────────

describe("verifyMCPCredential — RFC 8707 attack scenarios", () => {
  test("rejects when audience mismatches (cross-server replay)", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:filesystem:read_file"]),
      serverURI: "https://filesystem.example.com",
      scopes: ["mcp:filesystem:read_file"],
      signingKey,
      issuer: "broker",
    });

    const v = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://shell.example.com",
    });

    assert.strictEqual(v.valid, false);
  });

  test("confused deputy: server A passes credential to server B; B rejects", async () => {
    const credForA = await issueMCPCredential({
      agentToken: tokenWith(["mcp:*"]),
      serverURI: "https://a.example.com",
      scopes: ["mcp:a:read"],
      signingKey,
      issuer: "broker",
    });

    // Server B receives the token from compromised/malicious server A
    const v = await verifyMCPCredential(credForA.jwt, {
      publicKey,
      expectedAudience: "https://b.example.com",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects expired credentials", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
      ttlSeconds: 1,
    });

    await new Promise((r) => setTimeout(r, 1500));

    const v = await verifyMCPCredential(cred.jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects credentials signed by a different key", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
    });

    const v = await verifyMCPCredential(cred.jwt, {
      publicKey: altPublicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects tampered credentials", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
    });

    // Flip a character in the payload segment
    const parts = cred.jwt.split(".");
    parts[1] = parts[1].slice(0, -2) + (parts[1].slice(-2, -1) === "A" ? "B" : "A") + parts[1].slice(-1);
    const tampered = parts.join(".");

    const v = await verifyMCPCredential(tampered, {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects alg=none tokens (alg-confusion defense)", async () => {
    // Manually craft an unsigned JWT.
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        sub: "agent-1",
        aud: "https://fs",
        iss: "broker",
        iat: now,
        exp: now + 60,
        scope: "mcp:fs:read",
      })
    ).toString("base64url");
    const jwt = `${header}.${payload}.`; // empty signature

    const v = await verifyMCPCredential(jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects HS256-signed tokens (alg-confusion defense)", async () => {
    // Attacker tries to use the published EdDSA public key as if it were
    // an HMAC secret — a classic alg-confusion attack.
    const header = Buffer.from(
      JSON.stringify({ alg: "HS256", typ: "JWT" })
    ).toString("base64url");
    const now = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        sub: "agent-1",
        aud: "https://fs",
        iss: "broker",
        iat: now,
        exp: now + 60,
        scope: "mcp:fs:read",
      })
    ).toString("base64url");
    const sig = crypto
      .createHmac("sha256", publicKey)
      .update(`${header}.${payload}`)
      .digest("base64url");
    const jwt = `${header}.${payload}.${sig}`;

    const v = await verifyMCPCredential(jwt, {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects malformed JWT", async () => {
    const v = await verifyMCPCredential("not.a.jwt", {
      publicKey,
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
  });

  test("rejects gracefully on invalid public key", async () => {
    const cred = await issueMCPCredential({
      agentToken: tokenWith(["mcp:fs:read"]),
      serverURI: "https://fs",
      scopes: ["mcp:fs:read"],
      signingKey,
      issuer: "broker",
    });

    const v = await verifyMCPCredential(cred.jwt, {
      publicKey: "not a pem",
      expectedAudience: "https://fs",
    });
    assert.strictEqual(v.valid, false);
    if (!v.valid) {
      assert.match(v.error, /[Ii]nvalid public key/);
    }
  });
});

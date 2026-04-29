/**
 * Tests for MCP server identity verification.
 */

import { test, describe } from "node:test";
import * as assert from "node:assert";
import {
  artifactSha256,
  verifyServerIdentity,
} from "./server-trust.js";
import type { MCPServerBinding, SigstoreVerifier } from "./server-trust.js";
import { validateServerManifest } from "./server-schema.js";

const VALID_MANIFEST = {
  name: "io.github.example/server",
  version: "1.2.3",
  description: "Example MCP server",
  repository: { url: "https://github.com/example/server" },
};

const URI = "https://server.example.com";

// ─────────────────────────────────────────────────────────────────
// validateServerManifest
// ─────────────────────────────────────────────────────────────────

describe("validateServerManifest", () => {
  test("accepts a minimally-valid manifest", () => {
    const r = validateServerManifest({ name: "x", version: "1.0" });
    assert.strictEqual(r.valid, true);
  });

  test("accepts a full manifest with optional fields", () => {
    const r = validateServerManifest(VALID_MANIFEST);
    assert.strictEqual(r.valid, true);
  });

  test("rejects when name is missing", () => {
    const r = validateServerManifest({ version: "1.0" });
    assert.strictEqual(r.valid, false);
  });

  test("rejects when version is missing", () => {
    const r = validateServerManifest({ name: "x" });
    assert.strictEqual(r.valid, false);
  });

  test("rejects when name is an empty string", () => {
    const r = validateServerManifest({ name: "", version: "1.0" });
    assert.strictEqual(r.valid, false);
  });

  test("preserves additional unknown fields", () => {
    const r = validateServerManifest({
      name: "x",
      version: "1.0",
      futureField: 42,
    });
    if (r.valid) {
      assert.strictEqual(r.manifest.futureField, 42);
    } else {
      assert.fail("expected valid");
    }
  });
});

// ─────────────────────────────────────────────────────────────────
// verifyServerIdentity — URI check (always-on)
// ─────────────────────────────────────────────────────────────────

describe("verifyServerIdentity — URI check", () => {
  test("passes when observed URI matches binding", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI },
      { uri: URI }
    );
    assert.strictEqual(r.valid, true);
    const uriCheck = r.checks.find((c) => c.path === "uri");
    assert.strictEqual(uriCheck?.valid, true);
  });

  test("fails fast when URI mismatches", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI },
      { uri: "https://attacker.example.com" }
    );
    assert.strictEqual(r.valid, false);
    const uriCheck = r.checks.find((c) => c.path === "uri");
    assert.strictEqual(uriCheck?.valid, false);
    assert.match(uriCheck?.error ?? "", /URI mismatch/);
  });
});

// ─────────────────────────────────────────────────────────────────
// verifyServerIdentity — registry-anchored
// ─────────────────────────────────────────────────────────────────

describe("verifyServerIdentity — registry path", () => {
  test("skipped when binding doesn't request registry check", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI },
      { uri: URI, manifest: VALID_MANIFEST }
    );
    const reg = r.checks.find((c) => c.path === "registry");
    assert.strictEqual(reg?.skipped, true);
    assert.strictEqual(r.valid, true);
  });

  test("passes when registry name matches manifest", async () => {
    const binding: MCPServerBinding = {
      canonicalURI: URI,
      registry: "io.github.example/server",
    };
    const r = await verifyServerIdentity(binding, {
      uri: URI,
      manifest: VALID_MANIFEST,
    });
    assert.strictEqual(r.valid, true);
  });

  test("fails when registry name doesn't match manifest", async () => {
    const binding: MCPServerBinding = {
      canonicalURI: URI,
      registry: "io.github.expected/name",
    };
    const r = await verifyServerIdentity(binding, {
      uri: URI,
      manifest: VALID_MANIFEST,
    });
    assert.strictEqual(r.valid, false);
    const reg = r.checks.find((c) => c.path === "registry");
    assert.match(reg?.error ?? "", /Registry name mismatch/);
  });

  test("fails when manifest is structurally invalid", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, registry: "x" },
      { uri: URI, manifest: { version: "1.0" } /* missing name */ }
    );
    assert.strictEqual(r.valid, false);
    const reg = r.checks.find((c) => c.path === "registry");
    assert.match(reg?.error ?? "", /Manifest invalid/);
  });

  test("fails when registry check requested but no manifest observed", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, registry: "x" },
      { uri: URI }
    );
    assert.strictEqual(r.valid, false);
    const reg = r.checks.find((c) => c.path === "registry");
    assert.match(reg?.error ?? "", /no manifest/);
  });
});

// ─────────────────────────────────────────────────────────────────
// verifyServerIdentity — hash-pin
// ─────────────────────────────────────────────────────────────────

describe("verifyServerIdentity — hash path", () => {
  const tarball = Buffer.from("imagine this is a server tarball");
  const expectedHash = artifactSha256(tarball);

  test("skipped when binding doesn't pin a hash", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI },
      { uri: URI, artifactSha256: expectedHash }
    );
    const hash = r.checks.find((c) => c.path === "hash");
    assert.strictEqual(hash?.skipped, true);
    assert.strictEqual(r.valid, true);
  });

  test("passes when observed hash matches", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sha256: expectedHash },
      { uri: URI, artifactSha256: expectedHash }
    );
    assert.strictEqual(r.valid, true);
  });

  test("passes when hash case differs (lowercase normalized)", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sha256: expectedHash.toUpperCase() },
      { uri: URI, artifactSha256: expectedHash }
    );
    assert.strictEqual(r.valid, true);
  });

  test("fails (does not throw) when binding hash length differs from observed", async () => {
    // Pre-fix bug: crypto.timingSafeEqual throws RangeError on unequal lengths,
    // surfacing as an unhandled rejection rather than a valid:false result.
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sha256: "abc" },
      { uri: URI, artifactSha256: expectedHash }
    );
    assert.strictEqual(r.valid, false);
    const hash = r.checks.find((c) => c.path === "hash");
    assert.match(hash?.error ?? "", /sha256 mismatch/);
  });

  test("fails when observed hash differs (rug-pulled binary)", async () => {
    const tampered = artifactSha256(Buffer.concat([tarball, Buffer.from("X")]));
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sha256: expectedHash },
      { uri: URI, artifactSha256: tampered }
    );
    assert.strictEqual(r.valid, false);
    const hash = r.checks.find((c) => c.path === "hash");
    assert.match(hash?.error ?? "", /sha256 mismatch/);
  });

  test("fails when hash check requested but no artifact observed", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sha256: expectedHash },
      { uri: URI }
    );
    assert.strictEqual(r.valid, false);
    const hash = r.checks.find((c) => c.path === "hash");
    assert.match(hash?.error ?? "", /no artifact hash/);
  });

  test("artifactSha256 helper produces lowercase hex", () => {
    const h = artifactSha256("anything");
    assert.match(h, /^[0-9a-f]{64}$/);
  });
});

// ─────────────────────────────────────────────────────────────────
// verifyServerIdentity — sigstore (injected verifier)
// ─────────────────────────────────────────────────────────────────

describe("verifyServerIdentity — sigstore path", () => {
  const ALWAYS_ACCEPT: SigstoreVerifier = {
    async verify() {
      return true;
    },
  };
  const ALWAYS_REJECT: SigstoreVerifier = {
    async verify() {
      return false;
    },
  };
  const THROW: SigstoreVerifier = {
    async verify() {
      throw new Error("verifier exploded");
    },
  };

  test("skipped when binding has no sigstoreBundle", async () => {
    const r = await verifyServerIdentity({ canonicalURI: URI }, { uri: URI });
    const ss = r.checks.find((c) => c.path === "sigstore");
    assert.strictEqual(ss?.skipped, true);
    assert.strictEqual(r.valid, true);
  });

  test("fails when bundle present but no verifier provided", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sigstoreBundle: "BASE64==" },
      { uri: URI }
    );
    assert.strictEqual(r.valid, false);
    const ss = r.checks.find((c) => c.path === "sigstore");
    assert.match(ss?.error ?? "", /no sigstoreVerifier/);
  });

  test("passes when injected verifier accepts the bundle", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sigstoreBundle: "BASE64==" },
      { uri: URI },
      { sigstoreVerifier: ALWAYS_ACCEPT }
    );
    assert.strictEqual(r.valid, true);
  });

  test("fails when injected verifier rejects the bundle", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sigstoreBundle: "BASE64==" },
      { uri: URI },
      { sigstoreVerifier: ALWAYS_REJECT }
    );
    assert.strictEqual(r.valid, false);
    const ss = r.checks.find((c) => c.path === "sigstore");
    assert.match(ss?.error ?? "", /rejected the bundle/);
  });

  test("fails gracefully when injected verifier throws", async () => {
    const r = await verifyServerIdentity(
      { canonicalURI: URI, sigstoreBundle: "BASE64==" },
      { uri: URI },
      { sigstoreVerifier: THROW }
    );
    assert.strictEqual(r.valid, false);
    const ss = r.checks.find((c) => c.path === "sigstore");
    assert.match(ss?.error ?? "", /verifier threw/);
  });

  test("verifier receives the canonical URI for subject pinning", async () => {
    let capturedURI: string | undefined;
    const captureURI: SigstoreVerifier = {
      async verify(_bundle, opts) {
        capturedURI = opts.expectedURI;
        return true;
      },
    };
    await verifyServerIdentity(
      { canonicalURI: URI, sigstoreBundle: "BASE64==" },
      { uri: URI },
      { sigstoreVerifier: captureURI }
    );
    assert.strictEqual(capturedURI, URI);
  });
});

// ─────────────────────────────────────────────────────────────────
// Stackable composition
// ─────────────────────────────────────────────────────────────────

describe("verifyServerIdentity — stacking", () => {
  test("all-or-nothing: every requested check must pass", async () => {
    const tarball = Buffer.from("artifact");
    const hash = artifactSha256(tarball);

    const binding: MCPServerBinding = {
      canonicalURI: URI,
      registry: "io.github.example/server",
      sha256: hash,
      sigstoreBundle: "B==",
    };

    // All pass
    const ok = await verifyServerIdentity(
      binding,
      { uri: URI, manifest: VALID_MANIFEST, artifactSha256: hash },
      { sigstoreVerifier: { async verify() { return true; } } }
    );
    assert.strictEqual(ok.valid, true);

    // Hash check fails — overall fails despite others passing
    const bad = await verifyServerIdentity(
      binding,
      { uri: URI, manifest: VALID_MANIFEST, artifactSha256: artifactSha256("other") },
      { sigstoreVerifier: { async verify() { return true; } } }
    );
    assert.strictEqual(bad.valid, false);
  });

  test("URI mismatch short-circuits other checks", async () => {
    const binding: MCPServerBinding = {
      canonicalURI: URI,
      registry: "io.github.example/server",
      sha256: "abc",
      sigstoreBundle: "B==",
    };
    const r = await verifyServerIdentity(binding, {
      uri: "https://wrong.example.com",
    });
    assert.strictEqual(r.valid, false);
    // Only URI check should be present; we bail before evaluating others.
    assert.strictEqual(r.checks.length, 1);
    assert.strictEqual(r.checks[0].path, "uri");
  });
});

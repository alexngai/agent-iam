/**
 * MCP Server Identity Verification
 *
 * Optional, opt-in trust signals for the MCP servers an agent connects to.
 * Mirrors the existing `trustedAuthorities` pattern in
 * `src/identity/standalone-verifier.ts` (line 79-80) — MCP servers are not
 * principals in agent-iam's identity graph; they're external services we
 * recognize via signed/pinned attestations.
 *
 * Three stackable verification paths, each optional:
 *
 *   1. Hash-pin     — sha256 of the server tarball/binary. Cheapest;
 *                     fully offline; the only path required for v1.
 *   2. Registry-anchored — fetched `server.json` manifest validated against
 *                          the vendored minimal schema; canonical URI must
 *                          match the binding.
 *   3. Sigstore-attested — provenance bundle verified via a caller-injected
 *                          verifier (we don't ship `@sigstore/verify`
 *                          here to keep the dep tree light and because real
 *                          end-to-end tests would need a vendored bundle
 *                          fixture; consumers wire it up themselves).
 *
 * Default behavior with an empty `MCPServerBinding` is "trust local config"
 * — same as agent-iam's behavior today. Hardened deployments populate the
 * binding's optional fields to opt into checks.
 */

import * as crypto from "crypto";
import { validateServerManifest } from "./server-schema.js";

/** Optional trust binding for an MCP server. All fields are opt-in. */
export interface MCPServerBinding {
  /** Canonical URI of the server (becomes RFC 8707 `aud` for credentials). */
  canonicalURI: string;
  /** Expected MCP Registry name (e.g. `io.github.org/server`). */
  registry?: string;
  /** Expected SHA-256 (lowercase hex) of the server's binary or tarball. */
  sha256?: string;
  /** Sigstore bundle (base64) attesting the server's provenance. */
  sigstoreBundle?: string;
}

/** What the harness has actually observed about the running server. */
export interface ObservedServerManifest {
  /** Canonical URI the harness is connecting to. */
  uri: string;
  /** Raw server.json manifest, if discovered (for registry-anchored check). */
  manifest?: unknown;
  /** Bytes (or pre-computed hash) of the server artifact, for hash-pin check. */
  artifactSha256?: string;
}

/**
 * Sigstore verifier injected by the caller. Returning true means the bundle
 * was cryptographically valid; false (or throwing) means the bundle is bad.
 *
 * Concrete implementations should use `@sigstore/verify` with a pre-fetched
 * trust root. Kept abstract here so the broker doesn't pull network/TUF
 * dependencies.
 */
export interface SigstoreVerifier {
  verify(
    bundleBase64: string,
    options: { expectedURI: string }
  ): Promise<boolean>;
}

/** Options for verifyServerIdentity. */
export interface VerifyServerIdentityOptions {
  /** Caller-provided sigstore verifier; required if binding has sigstoreBundle. */
  sigstoreVerifier?: SigstoreVerifier;
}

/** Per-check outcome inside a server-trust verification. */
export interface ServerTrustCheckResult {
  path: "uri" | "registry" | "hash" | "sigstore";
  valid: boolean;
  skipped?: boolean;
  error?: string;
}

/** Aggregate result of verifyServerIdentity. */
export interface ServerTrustVerification {
  /** True iff every non-skipped check passed. */
  valid: boolean;
  /** Per-path breakdown for audit / diagnostics. */
  checks: ServerTrustCheckResult[];
}

/**
 * Verify the observed server matches the binding the token carries.
 *
 * The URI check always runs (it's how we know we're talking to the right
 * server at all). The other paths run only when the binding opts into them.
 */
export async function verifyServerIdentity(
  binding: MCPServerBinding,
  observed: ObservedServerManifest,
  options?: VerifyServerIdentityOptions
): Promise<ServerTrustVerification> {
  const checks: ServerTrustCheckResult[] = [];

  // 1. URI match — always runs.
  if (observed.uri !== binding.canonicalURI) {
    checks.push({
      path: "uri",
      valid: false,
      error: `URI mismatch: expected ${binding.canonicalURI}, observed ${observed.uri}`,
    });
    return { valid: false, checks };
  }
  checks.push({ path: "uri", valid: true });

  // 2. Registry-anchored — opt-in.
  if (binding.registry !== undefined) {
    if (observed.manifest === undefined) {
      checks.push({
        path: "registry",
        valid: false,
        error: "Binding requires registry check but no manifest was observed",
      });
    } else {
      const result = validateServerManifest(observed.manifest);
      if (!result.valid) {
        checks.push({
          path: "registry",
          valid: false,
          error: `Manifest invalid: ${result.errors.join("; ")}`,
        });
      } else if (result.manifest.name !== binding.registry) {
        checks.push({
          path: "registry",
          valid: false,
          error: `Registry name mismatch: expected ${binding.registry}, manifest says ${result.manifest.name}`,
        });
      } else {
        checks.push({ path: "registry", valid: true });
      }
    }
  } else {
    checks.push({ path: "registry", valid: true, skipped: true });
  }

  // 3. Hash-pin — opt-in.
  if (binding.sha256 !== undefined) {
    if (!observed.artifactSha256) {
      checks.push({
        path: "hash",
        valid: false,
        error: "Binding requires sha256 but no artifact hash was observed",
      });
    } else if (!hashesMatch(binding.sha256, observed.artifactSha256)) {
      // Length-guard before timing-safe compare: timingSafeEqual throws
      // RangeError on length-mismatched buffers, which would surface as an
      // unhandled rejection rather than a `valid: false` result.
      checks.push({
        path: "hash",
        valid: false,
        error: `sha256 mismatch: expected ${binding.sha256}, observed ${observed.artifactSha256}`,
      });
    } else {
      checks.push({ path: "hash", valid: true });
    }
  } else {
    checks.push({ path: "hash", valid: true, skipped: true });
  }

  // 4. Sigstore — opt-in, requires injected verifier.
  if (binding.sigstoreBundle !== undefined) {
    if (!options?.sigstoreVerifier) {
      checks.push({
        path: "sigstore",
        valid: false,
        error:
          "Binding has sigstoreBundle but no sigstoreVerifier was provided; " +
          "supply one via VerifyServerIdentityOptions",
      });
    } else {
      try {
        const ok = await options.sigstoreVerifier.verify(binding.sigstoreBundle, {
          expectedURI: binding.canonicalURI,
        });
        if (ok) {
          checks.push({ path: "sigstore", valid: true });
        } else {
          checks.push({
            path: "sigstore",
            valid: false,
            error: "Sigstore verifier rejected the bundle",
          });
        }
      } catch (err) {
        checks.push({
          path: "sigstore",
          valid: false,
          error: `Sigstore verifier threw: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    }
  } else {
    checks.push({ path: "sigstore", valid: true, skipped: true });
  }

  const valid = checks.every((c) => c.valid);
  return { valid, checks };
}

/**
 * Compute the lowercase hex SHA-256 of a buffer/string. Helper for harnesses
 * that read the server artifact themselves and want to feed it to
 * `verifyServerIdentity`.
 */
export function artifactSha256(data: Buffer | string): string {
  const buf = typeof data === "string" ? Buffer.from(data) : data;
  return crypto.createHash("sha256").update(buf).digest("hex");
}

/** Constant-time hash compare with a pre-check on length to avoid throwing. */
function hashesMatch(a: string, b: string): boolean {
  const x = a.toLowerCase();
  const y = b.toLowerCase();
  if (x.length !== y.length) return false;
  return crypto.timingSafeEqual(Buffer.from(x), Buffer.from(y));
}

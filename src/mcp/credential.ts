/**
 * RFC 8707 Audience-Bound MCP Credentials
 *
 * Broker-issued credentials that an agent presents to a specific MCP server.
 * Each credential is an EdDSA-signed JWT with `aud` set to the server's
 * canonical URI per RFC 8707 (Resource Indicators for OAuth 2.0).
 *
 * Threat addressed: a credential issued for MCP server A must not be
 * replayable against MCP server B. The MCP authorization spec (2025-11-25)
 * **MUSTs** RFC 8707 audience binding for tokens used against MCP servers.
 *
 * Three concrete attacks audience binding prevents:
 *   1. Confused deputy: server A receives a token, calls server B with it.
 *      B sees aud != B and rejects.
 *   2. Compromised-server exfiltration: a compromised filesystem server
 *      can't reuse leaked credentials against unrelated servers.
 *   3. Cross-tenant token reuse: multi-tenant brokers can't accidentally
 *      issue cross-tenant-replayable tokens.
 *
 * This module is pure functions — broker integration (key management, audit
 * logging) lives separately. The signing key is passed in by the caller.
 *
 * Algorithm: EdDSA (Ed25519), matching the rest of agent-iam's identity
 * stack so the same keys / DID:key infrastructure can be reused.
 */

import { SignJWT, jwtVerify, importPKCS8, importSPKI } from "jose";
import type { AgentToken } from "../types.js";
import { scopeMatches } from "../token.js";

const ALG = "EdDSA";
const DEFAULT_TTL_SECONDS = 300;

/** Options for issuing an MCP-bound credential. */
export interface IssueMCPCredentialOptions {
  /** The agent's capability token. Requested scopes must be a subset of these. */
  agentToken: AgentToken;
  /** Canonical URI of the MCP server. Becomes the `aud` claim per RFC 8707. */
  serverURI: string;
  /** Scopes to grant in this credential. Each must be granted by the agent token. */
  scopes: string[];
  /** Ed25519 private key (PEM, PKCS8) the broker uses to sign. */
  signingKey: string;
  /** Issuer identifier (the broker's identity / URI). */
  issuer: string;
  /** Time-to-live in seconds. Default: 300 (5 minutes). */
  ttlSeconds?: number;
  /**
   * Optional `act` chain for forward-compatibility with W3 (Human OBO).
   * RFC 8693 actor identification: ordered list, original principal first.
   */
  act?: string[];
}

/** A signed MCP-bound credential plus its expiry. */
export interface MCPCredential {
  jwt: string;
  expiresAt: string;
}

/**
 * Issue a JWT credential bound to a single MCP server.
 *
 * Validates that every requested scope is granted by the agent's token
 * (defense in depth — the policy layer should also have checked).
 */
export async function issueMCPCredential(
  options: IssueMCPCredentialOptions
): Promise<MCPCredential> {
  if (options.scopes.length === 0) {
    throw new Error("issueMCPCredential: scopes must not be empty");
  }
  if (!options.serverURI) {
    throw new Error("issueMCPCredential: serverURI is required (RFC 8707 audience)");
  }
  if (!options.issuer) {
    throw new Error("issueMCPCredential: issuer is required");
  }

  for (const requested of options.scopes) {
    const allowed = options.agentToken.scopes.some((p) => scopeMatches(p, requested));
    if (!allowed) {
      throw new Error(
        `issueMCPCredential: scope '${requested}' is not granted by the agent token`
      );
    }
  }

  const ttl = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttl;

  const key = await importPKCS8(options.signingKey, ALG);

  let signer = new SignJWT({
    scope: options.scopes.join(" "),
    ...(options.act && options.act.length > 0 ? { act: options.act } : {}),
  })
    .setProtectedHeader({ alg: ALG })
    .setIssuer(options.issuer)
    .setSubject(options.agentToken.agentId)
    .setAudience(options.serverURI)
    .setIssuedAt(now)
    .setExpirationTime(exp);

  const jwt = await signer.sign(key);

  return {
    jwt,
    expiresAt: new Date(exp * 1000).toISOString(),
  };
}

/** Options for verifying an MCP credential on the receiving side. */
export interface VerifyMCPCredentialOptions {
  /** Broker's Ed25519 public key (PEM, SPKI). */
  publicKey: string;
  /** The MCP server's own canonical URI. Token's `aud` must match this. */
  expectedAudience: string;
  /** Optional expected issuer; if set, token's `iss` must match. */
  expectedIssuer?: string;
}

/** Result of verifying an MCP-bound credential. */
export type VerifiedMCPCredential =
  | {
      valid: true;
      agentId: string;
      scopes: string[];
      audience: string;
      issuer: string;
      expiresAt: string;
      act?: string[];
    }
  | { valid: false; error: string };

/**
 * Verify a JWT credential against the expected audience (the calling MCP
 * server's own canonical URI). Rejection on `aud` mismatch is the core
 * RFC 8707 defense.
 */
export async function verifyMCPCredential(
  jwt: string,
  options: VerifyMCPCredentialOptions
): Promise<VerifiedMCPCredential> {
  let key;
  try {
    key = await importSPKI(options.publicKey, ALG);
  } catch (err) {
    return {
      valid: false,
      error: `Invalid public key: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let payload;
  try {
    const result = await jwtVerify(jwt, key, {
      audience: options.expectedAudience,
      // Explicit algorithm pin — defense against alg-confusion attacks
      // (e.g., a token forged with `alg: "none"` or `alg: "HS256"` against
      // our public key as if it were an HMAC secret).
      algorithms: [ALG],
      ...(options.expectedIssuer ? { issuer: options.expectedIssuer } : {}),
    });
    payload = result.payload;
  } catch (err) {
    return {
      valid: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  if (typeof payload.sub !== "string") {
    return { valid: false, error: "Missing or invalid `sub` claim" };
  }
  // RFC 7519 allows `aud` to be a string OR a string array. jose has already
  // verified the expectedAudience appears in either form by this point.
  const audIsString = typeof payload.aud === "string";
  const audIsStringArray =
    Array.isArray(payload.aud) && payload.aud.every((a) => typeof a === "string");
  if (!audIsString && !audIsStringArray) {
    return { valid: false, error: "Missing or invalid `aud` claim" };
  }
  if (typeof payload.iss !== "string") {
    return { valid: false, error: "Missing `iss` claim" };
  }
  if (typeof payload.exp !== "number") {
    return { valid: false, error: "Missing `exp` claim" };
  }
  if (typeof payload.scope !== "string") {
    return { valid: false, error: "Missing or non-string `scope` claim" };
  }

  // Report the expected audience as the matched one — jose has already
  // verified it appears in payload.aud (whether string or array form).
  return {
    valid: true,
    agentId: payload.sub,
    scopes: payload.scope.split(" ").filter((s) => s.length > 0),
    audience: options.expectedAudience,
    issuer: payload.iss,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    ...(Array.isArray(payload.act) ? { act: payload.act as string[] } : {}),
  };
}

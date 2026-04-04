/**
 * Standalone Identity Verification
 *
 * Verifies agent identity proofs using ONLY the data in the token.
 * No broker access, no provider lookup, no disk I/O required.
 *
 * This enables the key scenario: an agent presents a token to a remote
 * online service, and the service can verify the agent's identity
 * without access to the agent's local broker.
 *
 * Verification flow:
 *   1. Extract public key and proof from token
 *   2. Verify persistentId matches the public key (fingerprint check)
 *   3. Verify the proof was signed by the corresponding private key
 *   4. Optionally verify authority endorsements
 *
 * Trust model:
 *   - Self-signed (TOFU): "this is the same agent I've seen before"
 *     → Verified by: public key fingerprint matches persistentId + valid proof
 *   - Authority-endorsed: "a trusted party vouches for this agent"
 *     → Verified by: authority's signature over agent's public key + claim
 */

import * as crypto from "crypto";
import type { AgentToken, AuthorityEndorsement } from "../types.js";

/** Result of standalone identity verification */
export interface StandaloneVerificationResult {
  /** Whether the identity proof is cryptographically valid */
  valid: boolean;
  /** Error description if invalid */
  error?: string;
  /** The verified persistent ID (only set if valid) */
  persistentId?: string;
  /** The public key from the token (for pinning / TOFU) */
  publicKey?: string;
  /** Verified endorsements (only those that passed verification) */
  verifiedEndorsements?: VerifiedEndorsement[];
}

/** An endorsement that passed verification */
export interface VerifiedEndorsement {
  authorityId: string;
  claim: string;
  issuedAt: string;
  expiresAt?: string;
}

/**
 * Verify an agent's identity using only the data in the token.
 * No broker access required — works anywhere.
 *
 * @param token - The agent token containing persistentIdentity
 * @param options - Optional verification settings
 * @returns Verification result with persistentId and verified endorsements
 */
export function verifyIdentityProof(
  token: AgentToken,
  options?: {
    /** Trusted authority public keys (authorityId → PEM). Only endorsements from these are verified. */
    trustedAuthorities?: Record<string, string>;
    /** Whether to require the persistentId to match the public key fingerprint (default: true) */
    requireFingerprintMatch?: boolean;
  }
): StandaloneVerificationResult {
  const requireFingerprintMatch = options?.requireFingerprintMatch ?? true;

  // 1. Check token has persistent identity
  if (!token.persistentIdentity) {
    return { valid: false, error: "Token has no persistent identity" };
  }

  const { persistentId, identityType, proof, challenge, publicKey } = token.persistentIdentity;

  // 2. For self-certifying verification, we need the public key in the token
  if (!publicKey) {
    return {
      valid: false,
      error: "Token has no public key — cannot verify without broker access",
    };
  }

  if (!proof || !challenge) {
    return {
      valid: false,
      error: "Token has no proof or challenge — identity was not proven at creation time",
    };
  }

  // 3. Verify the persistentId matches the public key fingerprint
  //    This prevents an attacker from substituting a different public key
  if (requireFingerprintMatch && identityType === "keypair") {
    const expectedFingerprint = crypto
      .createHash("sha256")
      .update(publicKey)
      .digest("hex")
      .slice(0, 32);
    const expectedId = `key:${expectedFingerprint}`;

    if (persistentId !== expectedId) {
      return {
        valid: false,
        error: `Public key fingerprint mismatch: key does not match claimed identity ${persistentId}`,
      };
    }
  }

  // 4. Verify the proof (Ed25519 signature over the challenge)
  if (identityType === "keypair") {
    try {
      const pubKeyObj = crypto.createPublicKey(publicKey);
      const signatureBuffer = Buffer.from(proof, "base64url");
      const verified = crypto.verify(null, Buffer.from(challenge), pubKeyObj, signatureBuffer);

      if (!verified) {
        return {
          valid: false,
          error: "Identity proof signature is invalid",
        };
      }
    } catch (err) {
      return {
        valid: false,
        error: `Failed to verify proof: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else {
    // Platform (HMAC) identities cannot be verified without the broker's secret.
    // This is a fundamental limitation of symmetric crypto — the verifier needs the same secret.
    return {
      valid: false,
      error: `Identity type "${identityType}" cannot be verified standalone — ` +
        `symmetric (HMAC) identities require broker access for verification. ` +
        `Use a keypair identity for standalone/remote verification, ` +
        `or use Broker.verifyTokenIdentity() for broker-mediated verification.`,
    };
  }

  // 5. Verify authority endorsements (if any, and if trusted authorities provided)
  const verifiedEndorsements: VerifiedEndorsement[] = [];

  if (token.persistentIdentity.endorsements && options?.trustedAuthorities) {
    for (const endorsement of token.persistentIdentity.endorsements) {
      const verified = verifyEndorsement(
        endorsement,
        persistentId,
        publicKey,
        options.trustedAuthorities
      );
      if (verified) {
        verifiedEndorsements.push({
          authorityId: endorsement.authorityId,
          claim: endorsement.claim,
          issuedAt: endorsement.issuedAt,
          expiresAt: endorsement.expiresAt,
        });
      }
    }
  }

  return {
    valid: true,
    persistentId,
    publicKey,
    verifiedEndorsements,
  };
}

/**
 * Create an authority endorsement — signs the agent's public key + claim.
 * Called by the authority (not the agent).
 *
 * @param authorityId - Identifier for this authority
 * @param authorityPrivateKey - Authority's Ed25519 private key (PEM)
 * @param authorityPublicKey - Authority's Ed25519 public key (PEM)
 * @param agentPersistentId - The agent's persistent ID
 * @param agentPublicKey - The agent's public key (PEM)
 * @param claim - What the authority is attesting (e.g., "member-of:acme-org")
 * @param expiresAt - Optional expiry for the endorsement
 */
export function createEndorsement(
  authorityId: string,
  authorityPrivateKey: string,
  authorityPublicKey: string,
  agentPersistentId: string,
  agentPublicKey: string,
  claim: string,
  expiresAt?: string
): AuthorityEndorsement {
  // Validate inputs
  if (!authorityId) throw new Error("authorityId is required");
  if (!authorityPrivateKey) throw new Error("authorityPrivateKey is required");
  if (!authorityPublicKey) throw new Error("authorityPublicKey is required");
  if (!agentPersistentId) throw new Error("agentPersistentId is required");
  if (!agentPublicKey) throw new Error("agentPublicKey is required");
  if (!claim) throw new Error("claim is required");

  // The signed payload: persistentId + publicKey + claim
  // This binds the endorsement to a specific agent identity and claim
  const payload = `${agentPersistentId}\n${agentPublicKey}\n${claim}`;

  let signature: Buffer;
  try {
    const privateKeyObj = crypto.createPrivateKey(authorityPrivateKey);
    signature = crypto.sign(null, Buffer.from(payload), privateKeyObj);
  } catch (err) {
    throw new Error(
      `Failed to sign endorsement: invalid authority private key. ` +
      `(${err instanceof Error ? err.message : String(err)})`
    );
  }

  return {
    authorityId,
    authorityPublicKey,
    claim,
    signature: signature.toString("base64url"),
    issuedAt: new Date().toISOString(),
    expiresAt,
  };
}

/**
 * Verify a single endorsement.
 * Checks that a trusted authority signed this agent's identity + claim.
 */
function verifyEndorsement(
  endorsement: AuthorityEndorsement,
  agentPersistentId: string,
  agentPublicKey: string,
  trustedAuthorities: Record<string, string>
): boolean {
  // Check if we trust this authority
  const trustedKey = trustedAuthorities[endorsement.authorityId];
  if (!trustedKey) {
    return false; // Unknown authority
  }

  // Check endorsement hasn't expired
  if (endorsement.expiresAt && new Date(endorsement.expiresAt) < new Date()) {
    return false;
  }

  // Verify the authority's public key matches what we trust
  // (prevents an attacker from substituting a different authority key)
  if (endorsement.authorityPublicKey !== trustedKey) {
    return false;
  }

  // Reconstruct the signed payload and verify
  const payload = `${agentPersistentId}\n${agentPublicKey}\n${endorsement.claim}`;

  try {
    const pubKeyObj = crypto.createPublicKey(trustedKey);
    const signatureBuffer = Buffer.from(endorsement.signature, "base64url");
    return crypto.verify(null, Buffer.from(payload), pubKeyObj, signatureBuffer);
  } catch {
    return false;
  }
}

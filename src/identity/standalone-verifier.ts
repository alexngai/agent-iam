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
 *   2. Verify persistentId matches the public key:
 *      - DID:key (did:key:z6Mk...): decode DID to extract raw key, compare with token's public key
 *      - Legacy (key:{fingerprint}): verify SHA-256 fingerprint matches public key
 *   3. Verify the proof was signed by the corresponding private key
 *   4. Optionally verify endorsements (both VC and legacy formats)
 *
 * Trust model:
 *   - Self-signed (TOFU): "this is the same agent I've seen before"
 *     → Verified by: public key matches persistentId + valid proof
 *   - Authority-endorsed: "a trusted party vouches for this agent"
 *     → Verified by: authority's signature over agent's identity + claim
 */

import * as crypto from "crypto";
import type {
  AgentToken,
  AuthorityEndorsement,
  VerifiableCredential,
  Endorsement,
} from "../types.js";
import { isVerifiableCredential } from "../types.js";
import {
  isDidKey,
  isLegacyKeyId,
  didKeyToRawPublicKey,
  rawPublicKeyToPem,
  computeLegacyFingerprint,
} from "./did-key.js";
import { canonicalize } from "./jcs.js";

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
 * Supports both DID:key (did:key:z6Mk...) and legacy (key:{fingerprint}) formats.
 * Supports both VC-format and legacy AuthorityEndorsement formats for endorsements.
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
    /** Whether to require the persistentId to match the public key (default: true) */
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

  // 3. Verify the persistentId matches the public key
  //    - For keypair identities: DID:key or legacy fingerprint check
  //    - For attested (SPIFFE) identities: the SPIFFE URI is not derived from the key,
  //      so we skip the fingerprint match. Trust is established via the SVID certificate
  //      chain or TOFU (pinning the public key on first encounter).
  if (requireFingerprintMatch && identityType === "keypair") {
    const matchResult = verifyKeyMatch(persistentId, publicKey);
    if (!matchResult.valid) {
      return matchResult;
    }
  }

  // 4. Verify the proof (Ed25519 signature over the challenge)
  //    Keypair, attested (SPIFFE), and decentralized (DID:web) identities all use Ed25519.
  if (identityType === "keypair" || identityType === "attested" || identityType === "decentralized") {
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
    return {
      valid: false,
      error: `Identity type "${identityType}" cannot be verified standalone — ` +
        `symmetric (HMAC) identities require broker access for verification. ` +
        `Use a keypair identity for standalone/remote verification, ` +
        `or use Broker.verifyTokenIdentity() for broker-mediated verification.`,
    };
  }

  // 5. Verify endorsements (both VC and legacy formats)
  const verifiedEndorsements: VerifiedEndorsement[] = [];

  if (token.persistentIdentity.endorsements && options?.trustedAuthorities) {
    for (const endorsement of token.persistentIdentity.endorsements) {
      const verified = isVerifiableCredential(endorsement)
        ? verifyVcEndorsement(endorsement, options.trustedAuthorities)
        : verifyLegacyEndorsement(endorsement, persistentId, publicKey, options.trustedAuthorities);

      if (verified) {
        if (isVerifiableCredential(endorsement)) {
          verifiedEndorsements.push({
            authorityId: endorsement.issuer.id,
            claim: endorsement.credentialSubject.claim,
            issuedAt: endorsement.issuanceDate,
            expiresAt: endorsement.expirationDate,
          });
        } else {
          verifiedEndorsements.push({
            authorityId: endorsement.authorityId,
            claim: endorsement.claim,
            issuedAt: endorsement.issuedAt,
            expiresAt: endorsement.expiresAt,
          });
        }
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
 * Verify that a persistentId matches the given public key.
 * Supports both DID:key and legacy key:{fingerprint} formats.
 */
function verifyKeyMatch(
  persistentId: string,
  publicKeyPem: string
): StandaloneVerificationResult {
  if (isDidKey(persistentId)) {
    try {
      const rawKeyFromDid = didKeyToRawPublicKey(persistentId);
      const pemFromDid = rawPublicKeyToPem(rawKeyFromDid);

      if (pemFromDid.trim() !== publicKeyPem.trim()) {
        return {
          valid: false,
          error: `Public key mismatch: key does not match DID:key identity ${persistentId}`,
        };
      }
    } catch (err) {
      return {
        valid: false,
        error: `Invalid DID:key format: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  } else if (isLegacyKeyId(persistentId)) {
    const expectedFingerprint = computeLegacyFingerprint(publicKeyPem);
    const expectedId = `key:${expectedFingerprint}`;

    if (persistentId !== expectedId) {
      return {
        valid: false,
        error: `Public key fingerprint mismatch: key does not match claimed identity ${persistentId}`,
      };
    }
  } else {
    return {
      valid: false,
      error: `Unknown keypair identity format: ${persistentId} (expected "did:key:" or "key:")`,
    };
  }

  return { valid: true };
}

// ─────────────────────────────────────────────────────────────────
// VC-FORMAT ENDORSEMENT CREATION AND VERIFICATION
// ─────────────────────────────────────────────────────────────────

/**
 * Compute the canonical signing payload for a VC-format endorsement.
 * Uses JCS (RFC 8785) canonicalization of the credential's core fields.
 */
export function computeVcSigningPayload(
  issuer: VerifiableCredential["issuer"],
  credentialSubject: VerifiableCredential["credentialSubject"],
  issuanceDate: string,
  expirationDate?: string,
): string {
  const payload: Record<string, unknown> = {
    issuer,
    credentialSubject,
    issuanceDate,
  };
  if (expirationDate !== undefined) {
    payload.expirationDate = expirationDate;
  }
  return canonicalize(payload);
}

/**
 * Create a W3C Verifiable Credential-format endorsement.
 *
 * @param issuerId - Authority identifier (DID or URI)
 * @param issuerPrivateKey - Authority's Ed25519 private key (PEM)
 * @param issuerPublicKey - Authority's Ed25519 public key (PEM) — used to derive verificationMethod
 * @param agentPersistentId - The agent's persistent ID (e.g., "did:key:z6Mk...")
 * @param claim - What is being attested
 * @param options - Optional fields (issuerName, expirationDate, verificationMethod)
 */
export function createVcEndorsement(
  issuerId: string,
  issuerPrivateKey: string,
  issuerPublicKey: string,
  agentPersistentId: string,
  claim: string,
  options?: {
    issuerName?: string;
    expirationDate?: string;
    verificationMethod?: string;
  }
): VerifiableCredential {
  if (!issuerId) throw new Error("issuerId is required");
  if (!issuerPrivateKey) throw new Error("issuerPrivateKey is required");
  if (!agentPersistentId) throw new Error("agentPersistentId is required");
  if (!claim) throw new Error("claim is required");

  const issuanceDate = new Date().toISOString();

  const issuer: VerifiableCredential["issuer"] = { id: issuerId };
  if (options?.issuerName) {
    issuer.name = options.issuerName;
  }

  const credentialSubject = {
    id: agentPersistentId,
    claim,
  };

  // Compute canonical signing payload via JCS
  const signingPayload = computeVcSigningPayload(
    issuer,
    credentialSubject,
    issuanceDate,
    options?.expirationDate,
  );

  let proofValue: string;
  try {
    const privateKeyObj = crypto.createPrivateKey(issuerPrivateKey);
    const signature = crypto.sign(null, Buffer.from(signingPayload), privateKeyObj);
    proofValue = signature.toString("base64url");
  } catch (err) {
    throw new Error(
      `Failed to sign VC endorsement: invalid issuer private key. ` +
      `(${err instanceof Error ? err.message : String(err)})`
    );
  }

  // Default verificationMethod: use issuer's DID key ID or fall back to issuerId
  const verificationMethod = options?.verificationMethod ?? `${issuerId}#key-1`;

  return {
    type: "VerifiableCredential",
    issuer,
    issuanceDate,
    expirationDate: options?.expirationDate,
    credentialSubject,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod,
      created: issuanceDate,
      proofValue,
    },
  };
}

/**
 * Create a legacy-format authority endorsement.
 * Preserved for backward compatibility.
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
  if (!authorityId) throw new Error("authorityId is required");
  if (!authorityPrivateKey) throw new Error("authorityPrivateKey is required");
  if (!authorityPublicKey) throw new Error("authorityPublicKey is required");
  if (!agentPersistentId) throw new Error("agentPersistentId is required");
  if (!agentPublicKey) throw new Error("agentPublicKey is required");
  if (!claim) throw new Error("claim is required");

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
 * Verify a VC-format endorsement.
 * Reconstructs the JCS canonical payload and verifies the proof signature.
 */
function verifyVcEndorsement(
  vc: VerifiableCredential,
  trustedAuthorities: Record<string, string>
): boolean {
  // Look up trusted key by issuer.id
  const trustedKey = trustedAuthorities[vc.issuer.id];
  if (!trustedKey) {
    return false;
  }

  // Check expiration
  if (vc.expirationDate && new Date(vc.expirationDate) < new Date()) {
    return false;
  }

  // Reconstruct the signed payload
  const signingPayload = computeVcSigningPayload(
    vc.issuer,
    vc.credentialSubject,
    vc.issuanceDate,
    vc.expirationDate,
  );

  try {
    const pubKeyObj = crypto.createPublicKey(trustedKey);
    const signatureBuffer = Buffer.from(vc.proof.proofValue, "base64url");
    return crypto.verify(null, Buffer.from(signingPayload), pubKeyObj, signatureBuffer);
  } catch {
    return false;
  }
}

/**
 * Verify a legacy-format authority endorsement.
 */
function verifyLegacyEndorsement(
  endorsement: AuthorityEndorsement,
  agentPersistentId: string,
  agentPublicKey: string,
  trustedAuthorities: Record<string, string>
): boolean {
  const trustedKey = trustedAuthorities[endorsement.authorityId];
  if (!trustedKey) {
    return false;
  }

  if (endorsement.expiresAt && new Date(endorsement.expiresAt) < new Date()) {
    return false;
  }

  if (endorsement.authorityPublicKey !== trustedKey) {
    return false;
  }

  const payload = `${agentPersistentId}\n${agentPublicKey}\n${endorsement.claim}`;

  try {
    const pubKeyObj = crypto.createPublicKey(trustedKey);
    const signatureBuffer = Buffer.from(endorsement.signature, "base64url");
    return crypto.verify(null, Buffer.from(payload), pubKeyObj, signatureBuffer);
  } catch {
    return false;
  }
}

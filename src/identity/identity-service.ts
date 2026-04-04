/**
 * Identity Service
 *
 * Orchestrates identity providers and bridges identity with the token system.
 * This is the main entry point for identity operations:
 *
 * - Creating and managing persistent identities
 * - Generating identity proofs for token binding
 * - Verifying identity proofs on incoming tokens
 * - Selecting the right provider based on identity type
 *
 * The service holds a registry of providers and dispatches operations
 * to the correct one based on the identity type prefix.
 */

import * as crypto from "crypto";
import type {
  PersistentIdentity,
  IdentityProof,
  IdentityProvider,
  IdentityType,
  CreateIdentityOptions,
} from "./types.js";

/** Configuration for the IdentityService */
export interface IdentityServiceConfig {
  /** Default identity type when creating new identities */
  defaultType: IdentityType;
}

export class IdentityService {
  private providers: Map<IdentityType, IdentityProvider> = new Map();
  private config: IdentityServiceConfig;

  constructor(config?: Partial<IdentityServiceConfig>) {
    this.config = {
      defaultType: config?.defaultType ?? "keypair",
    };
  }

  /**
   * Register an identity provider.
   * Multiple providers can be registered for different identity types.
   */
  registerProvider(provider: IdentityProvider): void {
    this.providers.set(provider.type, provider);
  }

  /** Get a registered provider by type */
  getProvider(type: IdentityType): IdentityProvider {
    const provider = this.providers.get(type);
    if (!provider) {
      throw new Error(
        `No identity provider registered for type "${type}". ` +
        `Available: ${[...this.providers.keys()].join(", ") || "none"}`
      );
    }
    return provider;
  }

  /** List registered provider types */
  listProviderTypes(): IdentityType[] {
    return [...this.providers.keys()];
  }

  // ─────────────────────────────────────────────────────────────────
  // IDENTITY LIFECYCLE
  // ─────────────────────────────────────────────────────────────────

  /**
   * Create a new persistent identity using the specified (or default) provider.
   */
  async createIdentity(
    options?: CreateIdentityOptions & { type?: IdentityType }
  ): Promise<PersistentIdentity> {
    const type = options?.type ?? this.config.defaultType;
    const provider = this.getProvider(type);
    return provider.create(options);
  }

  /**
   * Load an identity by its persistent ID.
   * Automatically determines the provider from the ID prefix.
   */
  async loadIdentity(persistentId: string): Promise<PersistentIdentity | null> {
    const type = this.inferType(persistentId);
    if (!type) {
      // Try all providers
      for (const provider of this.providers.values()) {
        const identity = await provider.load(persistentId);
        if (identity) return identity;
      }
      return null;
    }

    const provider = this.providers.get(type);
    if (!provider) return null;
    return provider.load(persistentId);
  }

  /**
   * List all identities across all providers.
   */
  async listIdentities(): Promise<PersistentIdentity[]> {
    const all: PersistentIdentity[] = [];
    for (const provider of this.providers.values()) {
      const identities = await provider.list();
      all.push(...identities);
    }
    return all;
  }

  /**
   * Revoke an identity.
   */
  async revokeIdentity(persistentId: string): Promise<void> {
    const type = this.inferType(persistentId);
    if (!type) {
      throw new Error(`Cannot determine provider for identity: ${persistentId}`);
    }

    const provider = this.getProvider(type);
    await provider.revoke(persistentId);
  }

  // ─────────────────────────────────────────────────────────────────
  // PROOF GENERATION AND VERIFICATION
  // ─────────────────────────────────────────────────────────────────

  /**
   * Generate a challenge string for identity proof.
   * The challenge incorporates token-specific data to prevent replay.
   *
   * @param agentId - The agent role ID from the token
   * @param nonce - Optional external nonce (auto-generated if not provided)
   */
  generateChallenge(agentId: string, nonce?: string): string {
    const n = nonce ?? crypto.randomBytes(16).toString("base64url");
    const timestamp = Date.now().toString(36);
    return `${agentId}:${timestamp}:${n}`;
  }

  /**
   * Generate an identity proof for binding to a token.
   * This proves the token creator controls the persistent identity.
   */
  async proveIdentity(persistentId: string, challenge: string): Promise<IdentityProof> {
    const type = this.inferType(persistentId);
    if (!type) {
      throw new Error(`Cannot determine provider for identity: ${persistentId}`);
    }

    const provider = this.getProvider(type);
    return provider.prove(persistentId, challenge);
  }

  /**
   * Verify an identity proof.
   * Used when receiving a token with a persistent identity claim.
   */
  async verifyProof(proof: IdentityProof, challenge: string): Promise<boolean> {
    const provider = this.providers.get(proof.identityType);
    if (!provider) return false;
    return provider.verify(proof, challenge);
  }

  // ─────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────

  /**
   * Infer the identity type from a persistent ID prefix.
   * Convention:
   *   "did:key:..." → keypair (W3C DID:key, Ed25519)
   *   "key:..."     → keypair (legacy fingerprint format)
   *   "platform:..." → platform
   *   "spiffe://..." → attested
   *   "did:web:..." / "did:wba:..." → decentralized
   */
  private inferType(persistentId: string): IdentityType | null {
    if (persistentId.startsWith("did:key:")) return "keypair";
    if (persistentId.startsWith("key:")) return "keypair";
    if (persistentId.startsWith("platform:")) return "platform";
    if (persistentId.startsWith("spiffe://")) return "attested";
    if (persistentId.startsWith("did:web:")) return "decentralized";
    if (persistentId.startsWith("did:wba:")) return "decentralized";
    return null;
  }
}

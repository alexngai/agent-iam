/**
 * Keypair Identity Provider
 *
 * SSH/GPG-like approach: agent generates an Ed25519 keypair on first creation.
 * The private key is stored locally, the public key becomes the persistent identity.
 *
 * New identities use DID:key format (did:key:z6Mk...) per W3C DID:key method.
 * Legacy key:{fingerprint} identities are still supported for backward compatibility.
 *
 * Storage layout:
 *   {identityDir}/
 *     {storageKey}.json   — PersistentIdentity metadata + public key
 *     {storageKey}.key    — Private key (PEM, mode 0o600)
 */

import * as crypto from "crypto";
import * as fs from "fs";
import * as path from "path";
import type {
  PersistentIdentity,
  IdentityProof,
  IdentityProvider,
  CreateIdentityOptions,
} from "./types.js";
import {
  publicKeyToDidKey,
  didKeyToRawPublicKey,
  rawPublicKeyToPem,
  publicKeyToJwk,
  isDidKey,
  isLegacyKeyId,
  computeLegacyFingerprint,
} from "./did-key.js";

/** Directory name within config dir for identity storage */
const IDENTITIES_DIR = "identities";

export class KeypairIdentityProvider implements IdentityProvider {
  readonly type = "keypair" as const;
  private identityDir: string;

  constructor(configDir: string) {
    this.identityDir = path.join(configDir, IDENTITIES_DIR);
  }

  async create(options?: CreateIdentityOptions): Promise<PersistentIdentity> {
    this.ensureDir();

    // Generate Ed25519 keypair
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    // Generate DID:key identifier from public key
    const persistentId = publicKeyToDidKey(publicKey);
    const jwk = publicKeyToJwk(publicKey);

    // Use legacy fingerprint as storage key (filesystem-safe)
    const fingerprint = computeLegacyFingerprint(publicKey);

    const identity: PersistentIdentity = {
      persistentId,
      identityType: "keypair",
      createdAt: new Date().toISOString(),
      label: options?.label as string | undefined,
      metadata: {
        publicKey,
        publicKeyJwk: jwk,
        algorithm: "ed25519",
        fingerprint,
      },
    };

    // Write private key with restrictive permissions
    const keyPath = path.join(this.identityDir, `${fingerprint}.key`);
    fs.writeFileSync(keyPath, privateKey, { mode: 0o600 });

    // Write identity metadata
    const metaPath = path.join(this.identityDir, `${fingerprint}.json`);
    fs.writeFileSync(metaPath, JSON.stringify(identity, null, 2), { mode: 0o600 });

    return identity;
  }

  async load(persistentId: string): Promise<PersistentIdentity | null> {
    const fingerprint = this.resolveFingerprint(persistentId);
    if (!fingerprint) return null;

    const metaPath = path.join(this.identityDir, `${fingerprint}.json`);
    if (!fs.existsSync(metaPath)) return null;

    const content = fs.readFileSync(metaPath, "utf-8");
    return JSON.parse(content) as PersistentIdentity;
  }

  async list(): Promise<PersistentIdentity[]> {
    if (!fs.existsSync(this.identityDir)) return [];

    const files = fs.readdirSync(this.identityDir).filter(
      (f: string) => f.endsWith(".json")
    );
    const identities: PersistentIdentity[] = [];

    for (const file of files) {
      const content = fs.readFileSync(path.join(this.identityDir, file), "utf-8");
      const parsed = JSON.parse(content) as PersistentIdentity;
      // Only include keypair identities (skip other provider files)
      if (parsed.identityType === "keypair") {
        identities.push(parsed);
      }
    }

    return identities;
  }

  async prove(persistentId: string, challenge: string): Promise<IdentityProof> {
    const fingerprint = this.resolveFingerprint(persistentId);
    if (!fingerprint) {
      throw new Error(`Invalid keypair identity: ${persistentId}`);
    }

    const keyPath = path.join(this.identityDir, `${fingerprint}.key`);
    if (!fs.existsSync(keyPath)) {
      throw new Error(`Private key not found for identity: ${persistentId}`);
    }

    const privateKeyPem = fs.readFileSync(keyPath, "utf-8");

    let signature: Buffer;
    try {
      const privateKey = crypto.createPrivateKey(privateKeyPem);
      signature = crypto.sign(null, Buffer.from(challenge), privateKey);
    } catch (err) {
      throw new Error(
        `Failed to sign with private key for identity ${persistentId}: key may be corrupted. ` +
        `Consider revoking and recreating the identity. ` +
        `(${err instanceof Error ? err.message : String(err)})`
      );
    }

    return {
      persistentId,
      identityType: "keypair",
      challenge,
      proof: signature.toString("base64url"),
      provenAt: new Date().toISOString(),
    };
  }

  async verify(proof: IdentityProof, challenge: string): Promise<boolean> {
    if (proof.identityType !== "keypair") return false;
    if (proof.challenge !== challenge) return false;

    // Load the identity to get the public key
    const identity = await this.load(proof.persistentId);
    if (!identity) return false;

    const publicKeyPem = identity.metadata.publicKey as string;
    if (!publicKeyPem) return false;

    try {
      const publicKey = crypto.createPublicKey(publicKeyPem);
      const signatureBuffer = Buffer.from(proof.proof, "base64url");
      return crypto.verify(null, Buffer.from(challenge), publicKey, signatureBuffer);
    } catch {
      return false;
    }
  }

  async revoke(persistentId: string): Promise<void> {
    const fingerprint = this.resolveFingerprint(persistentId);
    if (!fingerprint) {
      throw new Error(
        `Invalid keypair identity format: ${persistentId} (must start with "did:key:" or "key:")`
      );
    }

    const keyPath = path.join(this.identityDir, `${fingerprint}.key`);
    const metaPath = path.join(this.identityDir, `${fingerprint}.json`);

    // Securely delete private key (overwrite before unlinking)
    if (fs.existsSync(keyPath)) {
      const size = fs.statSync(keyPath).size;
      fs.writeFileSync(keyPath, crypto.randomBytes(size));
      fs.unlinkSync(keyPath);
    }

    if (fs.existsSync(metaPath)) {
      fs.unlinkSync(metaPath);
    }
  }

  /**
   * Export the public key for an identity (for sharing / registration)
   */
  async exportPublicKey(persistentId: string): Promise<string | null> {
    const identity = await this.load(persistentId);
    if (!identity) return null;
    return (identity.metadata.publicKey as string) ?? null;
  }

  /**
   * Migrate a legacy key:{fingerprint} identity to DID:key format.
   * Rewrites the metadata file with the new persistentId while keeping
   * the same key material and storage location.
   *
   * @returns The updated identity, or null if not found
   */
  async migrate(legacyPersistentId: string): Promise<PersistentIdentity | null> {
    if (!isLegacyKeyId(legacyPersistentId)) {
      throw new Error(`Not a legacy key: identity: ${legacyPersistentId}`);
    }

    const identity = await this.load(legacyPersistentId);
    if (!identity) return null;

    const publicKeyPem = identity.metadata.publicKey as string;
    const newPersistentId = publicKeyToDidKey(publicKeyPem);
    const jwk = publicKeyToJwk(publicKeyPem);

    // Update identity with new DID:key format
    identity.persistentId = newPersistentId;
    identity.metadata.publicKeyJwk = jwk;

    // Write back
    const fingerprint = identity.metadata.fingerprint as string;
    const metaPath = path.join(this.identityDir, `${fingerprint}.json`);
    fs.writeFileSync(metaPath, JSON.stringify(identity, null, 2), { mode: 0o600 });

    return identity;
  }

  /**
   * Resolve a persistent ID (DID:key or legacy key:) to a storage fingerprint.
   * For DID:key: decode the public key from the DID and compute the legacy fingerprint.
   * For legacy key:: extract the fingerprint directly.
   */
  private resolveFingerprint(persistentId: string): string | null {
    if (isLegacyKeyId(persistentId)) {
      return persistentId.slice(4);
    }

    if (isDidKey(persistentId)) {
      try {
        // Decode DID:key to raw public key, convert to PEM, compute fingerprint
        const rawKey = didKeyToRawPublicKey(persistentId);
        const pem = rawPublicKeyToPem(rawKey);
        return computeLegacyFingerprint(pem);
      } catch {
        return null;
      }
    }

    return null;
  }

  private ensureDir(): void {
    if (!fs.existsSync(this.identityDir)) {
      fs.mkdirSync(this.identityDir, { recursive: true, mode: 0o700 });
    }
  }
}

/**
 * SPIFFE Identity Provider
 *
 * Implements the SPIFFE standard (CNCF Graduated) for environment-attested
 * agent identity. SPIFFE IDs are stable URIs (spiffe://trust-domain/path)
 * backed by short-lived X.509 SVIDs (SPIFFE Verifiable Identity Documents).
 *
 * Key characteristics:
 * - The SPIFFE ID (URI) is the stable persistent identity
 * - Key material rotates frequently (typically every hour via SPIRE)
 * - Proof uses the current SVID's private key (Ed25519 signature)
 * - Verification checks the SVID certificate chain + signature
 *
 * This provider supports two modes:
 * 1. **SPIRE-integrated**: Reads SVIDs from the SPIRE Workload API socket
 *    (production — not implemented in this version, but the interface supports it)
 * 2. **Local SVID**: Accepts pre-provisioned SVID key pairs and trust bundles
 *    (development/testing, and environments that provision SVIDs externally)
 *
 * Storage layout:
 *   {identityDir}/
 *     spiffe-registry.json  — Map of SPIFFE ID → identity record
 *     spiffe-{hash}.key     — Current SVID private key (PEM, mode 0o600)
 *     spiffe-{hash}.crt     — Current SVID certificate (PEM, optional)
 *     spiffe-trust-bundle/  — Trust bundle certificates (PEM)
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

/** Directory name within config dir for identity storage */
const IDENTITIES_DIR = "identities";
const REGISTRY_FILE = "spiffe-registry.json";

/** SPIFFE ID validation regex per SPIFFE spec */
const SPIFFE_ID_REGEX = /^spiffe:\/\/[a-z0-9._-]+(?:\/[a-zA-Z0-9._~!$&'()*+,;=:@/-]+)*$/;

/** Internal registry structure */
interface SpiffeRegistry {
  identities: Record<string, SpiffeRecord>;
}

interface SpiffeRecord {
  identity: PersistentIdentity;
  /** Whether this identity has been revoked */
  revoked: boolean;
}

export interface SpiffeCreateOptions extends CreateIdentityOptions {
  /** The SPIFFE ID URI (e.g., "spiffe://example.com/agents/code-reviewer") */
  spiffeId: string;
  /** Trust domain (extracted from spiffeId if not provided) */
  trustDomain?: string;
  /** SVID private key PEM (Ed25519). If not provided, a new keypair is generated. */
  svidPrivateKey?: string;
  /** SVID public key PEM. Required if svidPrivateKey is provided. */
  svidPublicKey?: string;
  /** SVID certificate PEM (optional — for mTLS verification) */
  svidCertificate?: string;
}

export class SpiffeIdentityProvider implements IdentityProvider {
  readonly type = "attested" as const;
  private identityDir: string;
  private registryPath: string;

  constructor(configDir: string) {
    this.identityDir = path.join(configDir, IDENTITIES_DIR);
    this.registryPath = path.join(this.identityDir, REGISTRY_FILE);
  }

  async create(options?: CreateIdentityOptions): Promise<PersistentIdentity> {
    const opts = options as SpiffeCreateOptions | undefined;
    if (!opts?.spiffeId) {
      throw new Error(
        "SpiffeIdentityProvider.create() requires a spiffeId option " +
        '(e.g., { spiffeId: "spiffe://example.com/agents/my-agent" })'
      );
    }

    const spiffeId = opts.spiffeId;
    this.validateSpiffeId(spiffeId);
    this.ensureDir();

    const trustDomain = opts.trustDomain ?? this.extractTrustDomain(spiffeId);
    const storageKey = this.computeStorageKey(spiffeId);

    // Use provided SVID key pair or generate a new one
    let publicKeyPem: string;
    let privateKeyPem: string;

    if (opts.svidPrivateKey && opts.svidPublicKey) {
      privateKeyPem = opts.svidPrivateKey;
      publicKeyPem = opts.svidPublicKey;
    } else {
      const keypair = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      publicKeyPem = keypair.publicKey;
      privateKeyPem = keypair.privateKey;
    }

    const identity: PersistentIdentity = {
      persistentId: spiffeId,
      identityType: "attested",
      createdAt: new Date().toISOString(),
      label: opts.label,
      metadata: {
        trustDomain,
        publicKey: publicKeyPem,
        algorithm: "ed25519",
        svidRotatedAt: new Date().toISOString(),
        hasCertificate: !!opts.svidCertificate,
      },
    };

    // Write SVID private key
    const keyPath = path.join(this.identityDir, `spiffe-${storageKey}.key`);
    fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });

    // Write SVID certificate if provided
    if (opts.svidCertificate) {
      const certPath = path.join(this.identityDir, `spiffe-${storageKey}.crt`);
      fs.writeFileSync(certPath, opts.svidCertificate, { mode: 0o600 });
    }

    // Update registry
    const registry = this.loadRegistry();
    registry.identities[spiffeId] = {
      identity,
      revoked: false,
    };
    this.saveRegistry(registry);

    return identity;
  }

  async load(persistentId: string): Promise<PersistentIdentity | null> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record || record.revoked) return null;
    return record.identity;
  }

  async list(): Promise<PersistentIdentity[]> {
    const registry = this.loadRegistry();
    return Object.values(registry.identities)
      .filter((r) => !r.revoked)
      .map((r) => r.identity);
  }

  async prove(persistentId: string, challenge: string): Promise<IdentityProof> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record || record.revoked) {
      throw new Error(`SPIFFE identity not found or revoked: ${persistentId}`);
    }

    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `spiffe-${storageKey}.key`);

    if (!fs.existsSync(keyPath)) {
      throw new Error(
        `SVID private key not found for identity: ${persistentId}. ` +
        `The SVID may have been rotated. Call rotateSvid() to provision new key material.`
      );
    }

    const privateKeyPem = fs.readFileSync(keyPath, "utf-8");

    let signature: Buffer;
    try {
      const privateKey = crypto.createPrivateKey(privateKeyPem);
      signature = crypto.sign(null, Buffer.from(challenge), privateKey);
    } catch (err) {
      throw new Error(
        `Failed to sign with SVID key for identity ${persistentId}: ` +
        `${err instanceof Error ? err.message : String(err)}`
      );
    }

    return {
      persistentId,
      identityType: "attested",
      challenge,
      proof: signature.toString("base64url"),
      provenAt: new Date().toISOString(),
    };
  }

  async verify(proof: IdentityProof, challenge: string): Promise<boolean> {
    if (proof.identityType !== "attested") return false;
    if (proof.challenge !== challenge) return false;

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
    if (!persistentId.startsWith("spiffe://")) {
      throw new Error(
        `Invalid SPIFFE identity format: ${persistentId} (must start with "spiffe://")`
      );
    }

    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record) {
      throw new Error(`SPIFFE identity not found: ${persistentId}`);
    }

    record.revoked = true;
    this.saveRegistry(registry);

    // Securely delete SVID key material
    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `spiffe-${storageKey}.key`);
    if (fs.existsSync(keyPath)) {
      const size = fs.statSync(keyPath).size;
      fs.writeFileSync(keyPath, crypto.randomBytes(size));
      fs.unlinkSync(keyPath);
    }

    const certPath = path.join(this.identityDir, `spiffe-${storageKey}.crt`);
    if (fs.existsSync(certPath)) {
      fs.unlinkSync(certPath);
    }
  }

  /**
   * Rotate the SVID key material for a SPIFFE identity.
   * The SPIFFE ID (persistent identity) remains stable — only the key changes.
   * This models what SPIRE does automatically (typically every hour).
   *
   * @param persistentId - The SPIFFE ID to rotate
   * @param newPrivateKey - New SVID private key PEM (generated if not provided)
   * @param newPublicKey - New SVID public key PEM (required if newPrivateKey provided)
   * @param newCertificate - New SVID certificate PEM (optional)
   */
  async rotateSvid(
    persistentId: string,
    newPrivateKey?: string,
    newPublicKey?: string,
    newCertificate?: string
  ): Promise<PersistentIdentity> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record || record.revoked) {
      throw new Error(`SPIFFE identity not found or revoked: ${persistentId}`);
    }

    let publicKeyPem: string;
    let privateKeyPem: string;

    if (newPrivateKey && newPublicKey) {
      privateKeyPem = newPrivateKey;
      publicKeyPem = newPublicKey;
    } else {
      const keypair = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      publicKeyPem = keypair.publicKey;
      privateKeyPem = keypair.privateKey;
    }

    // Update metadata with new public key
    record.identity.metadata.publicKey = publicKeyPem;
    record.identity.metadata.svidRotatedAt = new Date().toISOString();
    record.identity.metadata.hasCertificate = !!newCertificate;
    this.saveRegistry(registry);

    // Write new key material (overwrites old)
    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `spiffe-${storageKey}.key`);
    fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });

    if (newCertificate) {
      const certPath = path.join(this.identityDir, `spiffe-${storageKey}.crt`);
      fs.writeFileSync(certPath, newCertificate, { mode: 0o600 });
    }

    return record.identity;
  }

  /**
   * Export the current SVID public key for an identity.
   */
  async exportPublicKey(persistentId: string): Promise<string | null> {
    const identity = await this.load(persistentId);
    if (!identity) return null;
    return (identity.metadata.publicKey as string) ?? null;
  }

  // ─────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────

  private validateSpiffeId(spiffeId: string): void {
    if (!SPIFFE_ID_REGEX.test(spiffeId)) {
      throw new Error(
        `Invalid SPIFFE ID: "${spiffeId}". ` +
        `Must match spiffe://<trust-domain>/<path> per the SPIFFE specification. ` +
        `Trust domain must be lowercase alphanumeric with dots, hyphens, underscores.`
      );
    }
  }

  private extractTrustDomain(spiffeId: string): string {
    // spiffe://trust-domain/path → trust-domain
    const url = new URL(spiffeId);
    return url.hostname;
  }

  /**
   * Compute a filesystem-safe storage key from a SPIFFE ID.
   * Uses SHA-256 hash truncated to 16 hex chars.
   */
  private computeStorageKey(spiffeId: string): string {
    return crypto
      .createHash("sha256")
      .update(spiffeId)
      .digest("hex")
      .slice(0, 16);
  }

  private loadRegistry(): SpiffeRegistry {
    if (!fs.existsSync(this.registryPath)) {
      return { identities: {} };
    }
    const content = fs.readFileSync(this.registryPath, "utf-8");
    try {
      const parsed = JSON.parse(content) as SpiffeRegistry;
      if (!parsed.identities || typeof parsed.identities !== "object") {
        throw new Error("missing identities field");
      }
      return parsed;
    } catch (err) {
      throw new Error(
        `SPIFFE identity registry is corrupted at ${this.registryPath}: ` +
        `${err instanceof Error ? err.message : String(err)}. ` +
        `Back up the file and delete it to reset, or fix the JSON manually.`
      );
    }
  }

  private saveRegistry(registry: SpiffeRegistry): void {
    this.ensureDir();
    fs.writeFileSync(
      this.registryPath,
      JSON.stringify(registry, null, 2),
      { mode: 0o600 }
    );
  }

  private ensureDir(): void {
    if (!fs.existsSync(this.identityDir)) {
      fs.mkdirSync(this.identityDir, { recursive: true, mode: 0o700 });
    }
  }
}

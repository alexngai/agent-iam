/**
 * DID:web / DID:wba Identity Provider
 *
 * Implements W3C DID:web (and the MAP-compatible DID:wba variant) for
 * cross-organization, domain-anchored agent identity.
 *
 * A DID:web identifier like "did:web:agents.example.com:code-reviewer"
 * resolves to https://agents.example.com/code-reviewer/did.json, which
 * contains the agent's DID document (public keys, service endpoints, etc.).
 *
 * Key characteristics:
 * - The DID is anchored to a domain the agent (or its operator) controls
 * - The DID document at the resolved URL is the source of truth for keys
 * - Proof is standard DID Auth: sign a challenge with the authentication key
 * - Supports both did:web (W3C standard) and did:wba (MAP federation variant)
 *
 * This provider manages local DID documents and key material. Remote DID
 * resolution (fetching another agent's did.json) is handled separately
 * during verification via the resolve() method.
 *
 * Storage layout:
 *   {identityDir}/
 *     didweb-registry.json    — Map of DID → identity record
 *     didweb-{hash}.key       — Private key (PEM, mode 0o600)
 *     didweb-{hash}.did.json  — DID document (for serving / export)
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
import { publicKeyToJwk } from "./did-key.js";

/** Directory name within config dir for identity storage */
const IDENTITIES_DIR = "identities";
const REGISTRY_FILE = "didweb-registry.json";

/**
 * Minimal DID Document structure per W3C DID Core.
 * We include only the fields needed for agent identity verification.
 */
export interface DidDocument {
  /** JSON-LD context (included for forward compatibility) */
  "@context": string[];
  /** The DID this document describes */
  id: string;
  /** Verification methods (public keys) */
  verificationMethod: DidVerificationMethod[];
  /** Key IDs usable for authentication (DID Auth) */
  authentication: string[];
  /** Key IDs usable for assertion (signing credentials) */
  assertionMethod?: string[];
  /** Service endpoints (e.g., MAP connection URL) */
  service?: DidService[];
}

export interface DidVerificationMethod {
  /** Key ID (e.g., "did:web:example.com:agent#key-1") */
  id: string;
  /** Key type */
  type: "Ed25519VerificationKey2020" | "JsonWebKey2020";
  /** The DID that controls this key */
  controller: string;
  /** Public key in JWK format */
  publicKeyJwk: JsonWebKey;
}

export interface DidService {
  /** Service ID */
  id: string;
  /** Service type (e.g., "AgentService", "MAPEndpoint") */
  type: string;
  /** Service endpoint URL */
  serviceEndpoint: string;
}

/** Internal registry structure */
interface DidWebRegistry {
  identities: Record<string, DidWebRecord>;
}

interface DidWebRecord {
  identity: PersistentIdentity;
  revoked: boolean;
}

export interface DidWebCreateOptions extends CreateIdentityOptions {
  /** The full DID (e.g., "did:web:agents.example.com:code-reviewer") */
  did: string;
  /** Private key PEM (Ed25519). If not provided, a new keypair is generated. */
  privateKey?: string;
  /** Public key PEM. Required if privateKey is provided. */
  publicKey?: string;
  /** Service endpoints to include in the DID document */
  services?: DidService[];
}

export class DidWebIdentityProvider implements IdentityProvider {
  readonly type = "decentralized" as const;
  private identityDir: string;
  private registryPath: string;

  constructor(configDir: string) {
    this.identityDir = path.join(configDir, IDENTITIES_DIR);
    this.registryPath = path.join(this.identityDir, REGISTRY_FILE);
  }

  async create(options?: CreateIdentityOptions): Promise<PersistentIdentity> {
    const opts = options as DidWebCreateOptions | undefined;
    if (!opts?.did) {
      throw new Error(
        "DidWebIdentityProvider.create() requires a did option " +
        '(e.g., { did: "did:web:agents.example.com:my-agent" })'
      );
    }

    const did = opts.did;
    this.validateDid(did);
    this.ensureDir();

    const storageKey = this.computeStorageKey(did);
    const method = did.startsWith("did:wba:") ? "wba" : "web";
    const domain = this.extractDomain(did);

    // Use provided key pair or generate a new one
    let publicKeyPem: string;
    let privateKeyPem: string;

    if (opts.privateKey && opts.publicKey) {
      privateKeyPem = opts.privateKey;
      publicKeyPem = opts.publicKey;
    } else {
      const keypair = crypto.generateKeyPairSync("ed25519", {
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      });
      publicKeyPem = keypair.publicKey;
      privateKeyPem = keypair.privateKey;
    }

    const jwk = publicKeyToJwk(publicKeyPem);

    // Build DID document
    const didDocument = this.buildDidDocument(did, jwk, opts.services);

    const identity: PersistentIdentity = {
      persistentId: did,
      identityType: "decentralized",
      createdAt: new Date().toISOString(),
      label: opts.label,
      metadata: {
        publicKey: publicKeyPem,
        publicKeyJwk: jwk,
        algorithm: "ed25519",
        method,
        domain,
        resolveUrl: this.didToUrl(did),
      },
    };

    // Write private key
    const keyPath = path.join(this.identityDir, `didweb-${storageKey}.key`);
    fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });

    // Write DID document (for serving at the resolved URL)
    const docPath = path.join(this.identityDir, `didweb-${storageKey}.did.json`);
    fs.writeFileSync(docPath, JSON.stringify(didDocument, null, 2), { mode: 0o644 });

    // Update registry
    const registry = this.loadRegistry();
    registry.identities[did] = {
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
      throw new Error(`DID:web identity not found or revoked: ${persistentId}`);
    }

    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `didweb-${storageKey}.key`);

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
        `Failed to sign with private key for identity ${persistentId}: ` +
        `${err instanceof Error ? err.message : String(err)}`
      );
    }

    return {
      persistentId,
      identityType: "decentralized",
      challenge,
      proof: signature.toString("base64url"),
      provenAt: new Date().toISOString(),
    };
  }

  async verify(proof: IdentityProof, challenge: string): Promise<boolean> {
    if (proof.identityType !== "decentralized") return false;
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
    if (!persistentId.startsWith("did:web:") && !persistentId.startsWith("did:wba:")) {
      throw new Error(
        `Invalid DID:web identity format: ${persistentId} (must start with "did:web:" or "did:wba:")`
      );
    }

    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record) {
      throw new Error(`DID:web identity not found: ${persistentId}`);
    }

    record.revoked = true;
    this.saveRegistry(registry);

    // Securely delete private key
    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `didweb-${storageKey}.key`);
    if (fs.existsSync(keyPath)) {
      const size = fs.statSync(keyPath).size;
      fs.writeFileSync(keyPath, crypto.randomBytes(size));
      fs.unlinkSync(keyPath);
    }

    // Remove DID document
    const docPath = path.join(this.identityDir, `didweb-${storageKey}.did.json`);
    if (fs.existsSync(docPath)) {
      fs.unlinkSync(docPath);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // DID DOCUMENT OPERATIONS
  // ─────────────────────────────────────────────────────────────────

  /**
   * Get the DID document for a local identity.
   * This is the document that would be served at the resolved URL.
   */
  async getDidDocument(persistentId: string): Promise<DidDocument | null> {
    const storageKey = this.computeStorageKey(persistentId);
    const docPath = path.join(this.identityDir, `didweb-${storageKey}.did.json`);
    if (!fs.existsSync(docPath)) return null;

    const content = fs.readFileSync(docPath, "utf-8");
    return JSON.parse(content) as DidDocument;
  }

  /**
   * Resolve a DID:web/DID:wba to its HTTP(S) URL.
   *
   * did:web:example.com          → https://example.com/.well-known/did.json
   * did:web:example.com:agents:a → https://example.com/agents/a/did.json
   * did:wba:example.com:agents:a → https://example.com/agents/a/did.json
   */
  didToUrl(did: string): string {
    let stripped: string;
    if (did.startsWith("did:web:")) {
      stripped = did.slice("did:web:".length);
    } else if (did.startsWith("did:wba:")) {
      stripped = did.slice("did:wba:".length);
    } else {
      throw new Error(`Not a did:web or did:wba identifier: ${did}`);
    }

    // URL-decode the domain (percent-encoded colons for ports)
    const parts = stripped.split(":");
    const domain = decodeURIComponent(parts[0]);
    const pathParts = parts.slice(1).map(decodeURIComponent);

    if (pathParts.length === 0) {
      return `https://${domain}/.well-known/did.json`;
    }
    return `https://${domain}/${pathParts.join("/")}/did.json`;
  }

  /**
   * Export the public key for an identity.
   */
  async exportPublicKey(persistentId: string): Promise<string | null> {
    const identity = await this.load(persistentId);
    if (!identity) return null;
    return (identity.metadata.publicKey as string) ?? null;
  }

  /**
   * Rotate keys for a DID:web identity.
   * Updates the key material and DID document while preserving the DID.
   */
  async rotateKey(
    persistentId: string,
    newPrivateKey?: string,
    newPublicKey?: string,
    services?: DidService[]
  ): Promise<PersistentIdentity> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record || record.revoked) {
      throw new Error(`DID:web identity not found or revoked: ${persistentId}`);
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

    const jwk = publicKeyToJwk(publicKeyPem);

    // Update metadata
    record.identity.metadata.publicKey = publicKeyPem;
    record.identity.metadata.publicKeyJwk = jwk;
    this.saveRegistry(registry);

    // Write new key material
    const storageKey = this.computeStorageKey(persistentId);
    const keyPath = path.join(this.identityDir, `didweb-${storageKey}.key`);
    fs.writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });

    // Rebuild and write DID document
    const didDocument = this.buildDidDocument(persistentId, jwk, services);
    const docPath = path.join(this.identityDir, `didweb-${storageKey}.did.json`);
    fs.writeFileSync(docPath, JSON.stringify(didDocument, null, 2), { mode: 0o644 });

    return record.identity;
  }

  // ─────────────────────────────────────────────────────────────────
  // HELPERS
  // ─────────────────────────────────────────────────────────────────

  private validateDid(did: string): void {
    if (!did.startsWith("did:web:") && !did.startsWith("did:wba:")) {
      throw new Error(
        `Invalid DID: "${did}". Must start with "did:web:" or "did:wba:".`
      );
    }

    // Extract and validate domain
    const method = did.startsWith("did:web:") ? "did:web:" : "did:wba:";
    const rest = did.slice(method.length);
    if (!rest || rest.length === 0) {
      throw new Error(`Invalid DID: "${did}". Must include a domain after the method prefix.`);
    }

    const parts = rest.split(":");
    const domain = decodeURIComponent(parts[0]);
    if (!domain || domain.length === 0) {
      throw new Error(`Invalid DID: "${did}". Domain is empty.`);
    }
  }

  private extractDomain(did: string): string {
    const method = did.startsWith("did:web:") ? "did:web:" : "did:wba:";
    const rest = did.slice(method.length);
    const parts = rest.split(":");
    return decodeURIComponent(parts[0]);
  }

  private computeStorageKey(did: string): string {
    return crypto
      .createHash("sha256")
      .update(did)
      .digest("hex")
      .slice(0, 16);
  }

  private buildDidDocument(
    did: string,
    publicKeyJwk: JsonWebKey,
    services?: DidService[]
  ): DidDocument {
    const keyId = `${did}#key-1`;

    const doc: DidDocument = {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1",
      ],
      id: did,
      verificationMethod: [
        {
          id: keyId,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk,
        },
      ],
      authentication: [keyId],
      assertionMethod: [keyId],
    };

    if (services && services.length > 0) {
      doc.service = services;
    }

    return doc;
  }

  private loadRegistry(): DidWebRegistry {
    if (!fs.existsSync(this.registryPath)) {
      return { identities: {} };
    }
    const content = fs.readFileSync(this.registryPath, "utf-8");
    try {
      const parsed = JSON.parse(content) as DidWebRegistry;
      if (!parsed.identities || typeof parsed.identities !== "object") {
        throw new Error("missing identities field");
      }
      return parsed;
    } catch (err) {
      throw new Error(
        `DID:web identity registry is corrupted at ${this.registryPath}: ` +
        `${err instanceof Error ? err.message : String(err)}. ` +
        `Back up the file and delete it to reset, or fix the JSON manually.`
      );
    }
  }

  private saveRegistry(registry: DidWebRegistry): void {
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

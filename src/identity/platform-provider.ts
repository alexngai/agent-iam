/**
 * Platform Identity Provider
 *
 * OAuth/OIDC-like approach: the broker (or external authority) assigns a stable
 * UUID to each agent. Identity is backed by a registry file that the broker
 * manages. Best for team / enterprise deployments where administrative control
 * over agent lifecycle is needed.
 *
 * Storage layout:
 *   {identityDir}/
 *     platform-registry.json  — Map of persistentId → identity record
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

/** Registry file name */
const REGISTRY_FILE = "platform-registry.json";

/** Internal registry structure */
interface PlatformRegistry {
  identities: Record<string, PlatformRecord>;
}

interface PlatformRecord {
  identity: PersistentIdentity;
  /** HMAC secret for this agent (used for prove/verify) */
  secret: string;
  /** Who registered this identity */
  registeredBy?: string;
  /** Whether this identity has been revoked */
  revoked: boolean;
}

export class PlatformIdentityProvider implements IdentityProvider {
  readonly type = "platform" as const;
  private identityDir: string;
  private registryPath: string;
  /** Issuer identifier for this platform */
  private issuer: string;

  constructor(configDir: string, issuer?: string) {
    this.identityDir = path.join(configDir, "identities");
    this.registryPath = path.join(this.identityDir, REGISTRY_FILE);
    this.issuer = issuer ?? `agent-iam:${path.basename(configDir)}`;
  }

  async create(options?: CreateIdentityOptions): Promise<PersistentIdentity> {
    this.ensureDir();

    const uuid = crypto.randomUUID();
    const persistentId = `platform:${uuid}`;

    // Generate a per-agent HMAC secret for proof generation
    const secret = crypto.randomBytes(32).toString("base64url");

    const identity: PersistentIdentity = {
      persistentId,
      identityType: "platform",
      createdAt: new Date().toISOString(),
      label: options?.label as string | undefined,
      metadata: {
        uuid,
        issuer: this.issuer,
        registeredBy: options?.registeredBy as string | undefined,
      },
    };

    const registry = this.loadRegistry();
    registry.identities[persistentId] = {
      identity,
      secret,
      registeredBy: options?.registeredBy as string | undefined,
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
      throw new Error(`Identity not found or revoked: ${persistentId}`);
    }

    // HMAC the challenge with the agent's secret
    const proof = crypto
      .createHmac("sha256", record.secret)
      .update(challenge)
      .digest("base64url");

    return {
      persistentId,
      identityType: "platform",
      challenge,
      proof,
      provenAt: new Date().toISOString(),
    };
  }

  async verify(proof: IdentityProof, challenge: string): Promise<boolean> {
    if (proof.identityType !== "platform") return false;
    if (proof.challenge !== challenge) return false;

    const registry = this.loadRegistry();
    const record = registry.identities[proof.persistentId];
    if (!record || record.revoked) return false;

    const expected = crypto
      .createHmac("sha256", record.secret)
      .update(challenge)
      .digest("base64url");

    // Constant-time comparison
    return crypto.timingSafeEqual(
      Buffer.from(proof.proof),
      Buffer.from(expected)
    );
  }

  async revoke(persistentId: string): Promise<void> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (record) {
      record.revoked = true;
      // Zero out the secret
      record.secret = "";
      this.saveRegistry(registry);
    }
  }

  /**
   * Re-issue a revoked identity (recovery). Platform-specific capability.
   * Generates a new secret but preserves the persistent ID.
   */
  async reissue(persistentId: string): Promise<PersistentIdentity | null> {
    const registry = this.loadRegistry();
    const record = registry.identities[persistentId];
    if (!record) return null;

    record.revoked = false;
    record.secret = crypto.randomBytes(32).toString("base64url");
    this.saveRegistry(registry);

    return record.identity;
  }

  private loadRegistry(): PlatformRegistry {
    if (!fs.existsSync(this.registryPath)) {
      return { identities: {} };
    }
    const content = fs.readFileSync(this.registryPath, "utf-8");
    return JSON.parse(content) as PlatformRegistry;
  }

  private saveRegistry(registry: PlatformRegistry): void {
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

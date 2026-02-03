/**
 * Revocation list for tracking revoked tokens
 *
 * Supports:
 * - Token revocation with optional expiry
 * - Version-based delta sync between leader and followers
 * - Persistence to disk
 */

import * as fs from "fs";
import * as path from "path";
import type { RevokedToken } from "./types.js";

/** Revocation list storage file */
const REVOCATION_FILE = "revocations.json";

/** Persisted revocation list format */
interface PersistedRevocations {
  version: number;
  revocations: RevokedToken[];
}

/** Revocation entry with version tracking */
interface VersionedRevocation extends RevokedToken {
  /** Version when this revocation was added */
  addedAtVersion: number;
}

export class RevocationList {
  private configDir: string;
  private revocationsPath: string;
  private revocations: Map<string, VersionedRevocation> = new Map();
  private version: number = 0;

  constructor(configDir: string) {
    this.configDir = configDir;
    this.revocationsPath = path.join(configDir, REVOCATION_FILE);
    this.load();
  }

  /**
   * Get the current revocation list version
   */
  getVersion(): number {
    return this.version;
  }

  /**
   * Check if a token is revoked
   */
  isRevoked(tokenId: string): boolean {
    const revocation = this.revocations.get(tokenId);
    if (!revocation) {
      return false;
    }

    // Check if revocation has expired
    if (revocation.expiresAt) {
      const expiresAt = new Date(revocation.expiresAt);
      if (expiresAt < new Date()) {
        // Revocation expired, remove it
        this.revocations.delete(tokenId);
        this.persist();
        return false;
      }
    }

    return true;
  }

  /**
   * Revoke a token
   */
  revoke(params: {
    tokenId: string;
    agentId: string;
    reason?: string;
    expiresAt?: string;
  }): void {
    this.version++;

    const revocation: VersionedRevocation = {
      tokenId: params.tokenId,
      agentId: params.agentId,
      revokedAt: new Date().toISOString(),
      reason: params.reason,
      expiresAt: params.expiresAt,
      addedAtVersion: this.version,
    };

    this.revocations.set(params.tokenId, revocation);
    this.persist();
  }

  /**
   * Unrevoke a token (restore access)
   */
  unrevoke(tokenId: string): boolean {
    if (!this.revocations.has(tokenId)) {
      return false;
    }

    this.version++;
    this.revocations.delete(tokenId);
    this.persist();
    return true;
  }

  /**
   * Get revocation details for a token
   */
  getRevocation(tokenId: string): RevokedToken | undefined {
    const revocation = this.revocations.get(tokenId);
    if (!revocation) {
      return undefined;
    }

    // Return without internal version tracking
    return {
      tokenId: revocation.tokenId,
      agentId: revocation.agentId,
      revokedAt: revocation.revokedAt,
      reason: revocation.reason,
      expiresAt: revocation.expiresAt,
    };
  }

  /**
   * Get all revocations (for full sync)
   */
  getAllRevocations(): RevokedToken[] {
    return Array.from(this.revocations.values()).map((r) => ({
      tokenId: r.tokenId,
      agentId: r.agentId,
      revokedAt: r.revokedAt,
      reason: r.reason,
      expiresAt: r.expiresAt,
    }));
  }

  /**
   * Get revocations added since a specific version (for delta sync)
   */
  getRevocationsSince(sinceVersion: number): string[] {
    const delta: string[] = [];

    for (const [tokenId, revocation] of this.revocations) {
      if (revocation.addedAtVersion > sinceVersion) {
        delta.push(tokenId);
      }
    }

    return delta;
  }

  /**
   * Add revocations from sync (follower receiving from leader)
   */
  addFromSync(revocations: RevokedToken[], newVersion: number): void {
    for (const revocation of revocations) {
      this.revocations.set(revocation.tokenId, {
        ...revocation,
        addedAtVersion: newVersion,
      });
    }

    this.version = newVersion;
    this.persist();
  }

  /**
   * Add revocation IDs from delta sync
   * Note: This only marks tokens as revoked, without full details
   */
  addDeltaFromSync(tokenIds: string[], newVersion: number): void {
    const now = new Date().toISOString();

    for (const tokenId of tokenIds) {
      if (!this.revocations.has(tokenId)) {
        this.revocations.set(tokenId, {
          tokenId,
          agentId: "unknown", // Will be unknown from delta sync
          revokedAt: now,
          reason: "Synced from leader",
          addedAtVersion: newVersion,
        });
      }
    }

    this.version = newVersion;
    this.persist();
  }

  /**
   * Get total count of revoked tokens
   */
  count(): number {
    return this.revocations.size;
  }

  /**
   * Prune expired revocations
   */
  prune(): number {
    const now = new Date();
    let pruned = 0;

    for (const [tokenId, revocation] of this.revocations) {
      if (revocation.expiresAt) {
        const expiresAt = new Date(revocation.expiresAt);
        if (expiresAt < now) {
          this.revocations.delete(tokenId);
          pruned++;
        }
      }
    }

    if (pruned > 0) {
      this.persist();
    }

    return pruned;
  }

  /**
   * Load revocations from disk
   */
  private load(): void {
    if (!fs.existsSync(this.revocationsPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(this.revocationsPath, "utf-8");
      const persisted = JSON.parse(content) as PersistedRevocations;

      this.version = persisted.version;

      for (const revocation of persisted.revocations) {
        this.revocations.set(revocation.tokenId, {
          ...revocation,
          addedAtVersion: this.version, // Assume all loaded at current version
        });
      }
    } catch {
      // Ignore errors, start fresh
    }
  }

  /**
   * Persist revocations to disk
   */
  private persist(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }

    const persisted: PersistedRevocations = {
      version: this.version,
      revocations: this.getAllRevocations(),
    };

    fs.writeFileSync(
      this.revocationsPath,
      JSON.stringify(persisted, null, 2),
      { mode: 0o600 }
    );
  }

  /**
   * Clear all revocations (for testing)
   */
  clear(): void {
    this.revocations.clear();
    this.version = 0;
    if (fs.existsSync(this.revocationsPath)) {
      fs.unlinkSync(this.revocationsPath);
    }
  }
}

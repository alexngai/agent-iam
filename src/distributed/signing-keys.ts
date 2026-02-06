/**
 * Signing key manager with versioning for distributed mode
 *
 * Manages multiple signing keys to support:
 * - Key rotation without invalidating existing tokens
 * - Distributed key synchronization
 * - Verification of tokens signed with older keys
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import type { VersionedKey } from "./types.js";

/** Signing keys storage file */
const KEYS_FILE = "signing_keys.json";

/** Persisted key format */
interface PersistedKey {
  version: number;
  key: string; // base64-encoded
  createdAt: string;
  deprecatedAt?: string;
}

interface PersistedKeys {
  currentVersion: number;
  keys: PersistedKey[];
}

export class SigningKeyManager {
  private configDir: string;
  private keysPath: string;
  private keys: Map<number, VersionedKey> = new Map();
  private currentVersion: number = 0;

  constructor(configDir: string) {
    this.configDir = configDir;
    this.keysPath = path.join(configDir, KEYS_FILE);
    this.load();
  }

  /**
   * Get the current signing key and version
   */
  getCurrentKey(): { key: Buffer; version: number } {
    const versionedKey = this.keys.get(this.currentVersion);
    if (!versionedKey) {
      // No keys exist, create initial key
      return this.rotate();
    }
    return { key: versionedKey.key, version: this.currentVersion };
  }

  /**
   * Get the current key version
   */
  getCurrentVersion(): number {
    return this.currentVersion;
  }

  /**
   * Get a specific key by version (for verifying old tokens)
   */
  getKey(version: number): Buffer | undefined {
    return this.keys.get(version)?.key;
  }

  /**
   * Check if a key version exists
   */
  hasKey(version: number): boolean {
    return this.keys.has(version);
  }

  /**
   * Add a key received from sync
   */
  addKey(key: Buffer, version: number, createdAt?: string): void {
    if (this.keys.has(version)) {
      // Already have this version
      return;
    }

    this.keys.set(version, {
      version,
      key,
      createdAt: createdAt ?? new Date().toISOString(),
    });

    if (version > this.currentVersion) {
      this.currentVersion = version;
    }

    this.persist();
  }

  /**
   * Rotate to a new signing key (leader only)
   *
   * Old keys are kept for verification of existing tokens.
   */
  rotate(): { key: Buffer; version: number } {
    const newKey = crypto.randomBytes(32);
    const newVersion = this.currentVersion + 1;
    const now = new Date().toISOString();

    // Mark old key as deprecated
    const oldKey = this.keys.get(this.currentVersion);
    if (oldKey) {
      oldKey.deprecatedAt = now;
    }

    // Add new key
    this.keys.set(newVersion, {
      version: newVersion,
      key: newKey,
      createdAt: now,
    });

    this.currentVersion = newVersion;
    this.persist();

    return { key: newKey, version: newVersion };
  }

  /**
   * Get all keys (for full sync to new follower)
   */
  getAllKeys(): VersionedKey[] {
    return Array.from(this.keys.values()).sort((a, b) => a.version - b.version);
  }

  /**
   * Get keys newer than a specific version (for delta sync)
   */
  getKeysSince(version: number): VersionedKey[] {
    return this.getAllKeys().filter((k) => k.version > version);
  }

  /**
   * Prune old keys that are no longer needed
   *
   * Keys are kept if:
   * - They are the current key
   * - They were created within the retention period
   * - They are needed for verifying unexpired tokens
   */
  prune(retentionDays: number = 30): number {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - retentionDays);
    const cutoffStr = cutoff.toISOString();

    let pruned = 0;
    for (const [version, versionedKey] of this.keys) {
      if (version === this.currentVersion) continue;
      if (versionedKey.createdAt > cutoffStr) continue;

      this.keys.delete(version);
      pruned++;
    }

    if (pruned > 0) {
      this.persist();
    }

    return pruned;
  }

  /**
   * Export current key as base64 (for sync response)
   */
  exportCurrentKey(): string {
    const { key } = this.getCurrentKey();
    return key.toString("base64");
  }

  /**
   * Import a key from base64 (from sync response)
   */
  importKey(base64Key: string, version: number): void {
    const key = Buffer.from(base64Key, "base64");
    this.addKey(key, version);
  }

  /**
   * Load keys from disk
   */
  private load(): void {
    if (!fs.existsSync(this.keysPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(this.keysPath, "utf-8");
      const persisted = JSON.parse(content) as PersistedKeys;

      this.currentVersion = persisted.currentVersion;

      for (const pk of persisted.keys) {
        this.keys.set(pk.version, {
          version: pk.version,
          key: Buffer.from(pk.key, "base64"),
          createdAt: pk.createdAt,
          deprecatedAt: pk.deprecatedAt,
        });
      }
    } catch {
      // Ignore errors, will create new keys
    }
  }

  /**
   * Persist keys to disk
   */
  private persist(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }

    const persisted: PersistedKeys = {
      currentVersion: this.currentVersion,
      keys: Array.from(this.keys.values()).map((vk) => ({
        version: vk.version,
        key: vk.key.toString("base64"),
        createdAt: vk.createdAt,
        deprecatedAt: vk.deprecatedAt,
      })),
    };

    fs.writeFileSync(this.keysPath, JSON.stringify(persisted, null, 2), {
      mode: 0o600,
    });
  }

  /**
   * Clear all keys (for testing)
   */
  clear(): void {
    this.keys.clear();
    this.currentVersion = 0;
    if (fs.existsSync(this.keysPath)) {
      fs.unlinkSync(this.keysPath);
    }
  }
}

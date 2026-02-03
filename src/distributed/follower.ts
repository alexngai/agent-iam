/**
 * Follower broker that syncs from a leader
 *
 * Features:
 * - Periodic sync with leader
 * - Graceful degradation when leader unavailable
 * - Local caching for offline operation
 * - State machine for connection status
 */

import type { Broker } from "../broker.js";
import { SigningKeyManager } from "./signing-keys.js";
import { RevocationList } from "./revocation.js";
import {
  FollowerState,
  BrokerMode,
  STATE_THRESHOLDS,
  type FollowerConfig,
  type SyncRequest,
  type SyncResponse,
  type DistributedStatus,
} from "./types.js";

/** Default configuration values */
const DEFAULT_SYNC_INTERVAL = 60 * 1000; // 60 seconds
const DEFAULT_SYNC_TIMEOUT = 30 * 1000; // 30 seconds

export class FollowerClient {
  private broker: Broker;
  private config: FollowerConfig;
  private configDir: string;
  private signingKeyManager: SigningKeyManager;
  private revocationList: RevocationList;
  private providerConfigsVersion: number = 0;

  private state: FollowerState = FollowerState.STARTING;
  private lastSyncAt: Date | null = null;
  private lastSyncError: string | null = null;
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private isRunning: boolean = false;

  constructor(broker: Broker, configDir: string, config: FollowerConfig) {
    this.broker = broker;
    this.config = config;
    this.configDir = configDir;
    this.signingKeyManager = new SigningKeyManager(configDir);
    this.revocationList = new RevocationList(configDir);
  }

  /**
   * Start the follower with initial sync
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    this.isRunning = true;
    this.state = FollowerState.INITIAL_SYNC;

    // Perform initial sync
    try {
      await this.sync();
      this.state = FollowerState.CONNECTED;
    } catch (error) {
      // Check if we have cached data
      if (this.signingKeyManager.getCurrentVersion() > 0) {
        this.state = FollowerState.DEGRADED;
        console.warn(
          `Initial sync failed, using cached data: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      } else {
        this.isRunning = false;
        throw new Error(
          `Initial sync failed and no cached data available: ${
            error instanceof Error ? error.message : String(error)
          }`
        );
      }
    }

    // Start periodic sync
    const intervalMs =
      (this.config.syncIntervalSeconds ?? 60) * 1000 || DEFAULT_SYNC_INTERVAL;
    this.syncInterval = setInterval(() => this.syncWithStateUpdate(), intervalMs);
  }

  /**
   * Stop the follower
   */
  stop(): void {
    this.isRunning = false;

    if (this.syncInterval) {
      clearInterval(this.syncInterval);
      this.syncInterval = null;
    }
  }

  /**
   * Force an immediate sync
   */
  async sync(): Promise<void> {
    const request: SyncRequest = {
      followerId: this.config.followerId,
      signingKeyVersion: this.signingKeyManager.getCurrentVersion(),
      providerConfigsVersion: this.providerConfigsVersion,
      revocationListVersion: this.revocationList.getVersion(),
    };

    const timeoutMs = this.config.syncTimeoutMs ?? DEFAULT_SYNC_TIMEOUT;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(`${this.config.leaderUrl}/sync`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.config.leaderAuthToken}`,
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Sync failed: ${response.status} ${error}`);
      }

      const syncResponse = (await response.json()) as SyncResponse;
      this.applySyncResponse(syncResponse);

      this.lastSyncAt = new Date();
      this.lastSyncError = null;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Apply sync response from leader
   */
  private applySyncResponse(response: SyncResponse): void {
    // Update signing key if provided
    if (response.signingKey) {
      this.signingKeyManager.importKey(
        response.signingKey,
        response.signingKeyVersion
      );
    }

    // Update revocation list
    if (response.revocationListDelta.length > 0) {
      this.revocationList.addDeltaFromSync(
        response.revocationListDelta,
        response.revocationListVersion
      );
    }

    // Update provider configs if provided
    if (response.providerConfigs) {
      // Provider configs are handled through broker's config service
      // This would need integration with the broker's config
      this.providerConfigsVersion = response.providerConfigsVersion;
    }
  }

  /**
   * Sync with state machine updates
   */
  private async syncWithStateUpdate(): Promise<void> {
    try {
      await this.sync();
      this.state = FollowerState.CONNECTED;
    } catch (error) {
      this.lastSyncError =
        error instanceof Error ? error.message : String(error);
      this.updateStateOnFailure();
    }
  }

  /**
   * Update state based on time since last successful sync
   */
  private updateStateOnFailure(): void {
    if (!this.lastSyncAt) {
      // Never synced successfully
      if (this.signingKeyManager.getCurrentVersion() > 0) {
        this.state = FollowerState.DEGRADED;
      } else {
        this.state = FollowerState.OFFLINE;
      }
      return;
    }

    const secondsSinceSync =
      (Date.now() - this.lastSyncAt.getTime()) / 1000;

    if (secondsSinceSync > STATE_THRESHOLDS.OFFLINE_THRESHOLD_SECONDS) {
      this.state = FollowerState.OFFLINE;
    } else if (secondsSinceSync > STATE_THRESHOLDS.LIMITED_THRESHOLD_SECONDS) {
      this.state = FollowerState.LIMITED;
    } else if (secondsSinceSync > STATE_THRESHOLDS.DEGRADED_THRESHOLD_SECONDS) {
      this.state = FollowerState.DEGRADED;
    }
    // Otherwise keep current state
  }

  /**
   * Check if a token is revoked
   */
  isRevoked(tokenId: string): boolean {
    return this.revocationList.isRevoked(tokenId);
  }

  /**
   * Get signing key by version
   */
  getSigningKey(version: number): Buffer | undefined {
    return this.signingKeyManager.getKey(version);
  }

  /**
   * Get current signing key
   */
  getCurrentSigningKey(): { key: Buffer; version: number } {
    return this.signingKeyManager.getCurrentKey();
  }

  /**
   * Get the signing key manager
   */
  getSigningKeyManager(): SigningKeyManager {
    return this.signingKeyManager;
  }

  /**
   * Get the revocation list
   */
  getRevocationList(): RevocationList {
    return this.revocationList;
  }

  /**
   * Get current state
   */
  getState(): FollowerState {
    return this.state;
  }

  /**
   * Check if connected (or recently connected)
   */
  isConnected(): boolean {
    return (
      this.state === FollowerState.CONNECTED ||
      this.state === FollowerState.DEGRADED
    );
  }

  /**
   * Check if operations should be allowed based on state
   */
  canOperate(): boolean {
    // Operations allowed unless completely offline with no cache
    return this.signingKeyManager.getCurrentVersion() > 0;
  }

  /**
   * Get follower status
   */
  getStatus(): DistributedStatus {
    return {
      mode: BrokerMode.FOLLOWER,
      state: this.state,
      signingKeyVersion: this.signingKeyManager.getCurrentVersion(),
      providerConfigsVersion: this.providerConfigsVersion,
      revocationCount: this.revocationList.count(),
      lastSyncAt: this.lastSyncAt?.toISOString(),
      leaderUrl: this.config.leaderUrl,
    };
  }

  /**
   * Get detailed status including errors
   */
  getDetailedStatus(): DistributedStatus & { lastSyncError?: string } {
    return {
      ...this.getStatus(),
      lastSyncError: this.lastSyncError ?? undefined,
    };
  }
}

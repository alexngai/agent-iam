/**
 * Types for distributed broker mode (leader/follower)
 */

/** Broker operational mode */
export enum BrokerMode {
  /** Single-machine, no sync */
  STANDALONE = "standalone",
  /** Authoritative broker that followers sync from */
  LEADER = "leader",
  /** Broker that syncs state from leader */
  FOLLOWER = "follower",
}

/** Follower connection state */
export enum FollowerState {
  /** Starting up, not yet synced */
  STARTING = "starting",
  /** Performing initial sync */
  INITIAL_SYNC = "initial_sync",
  /** Connected and syncing normally */
  CONNECTED = "connected",
  /** Leader unreachable for > 5 minutes, using cached data */
  DEGRADED = "degraded",
  /** Leader unreachable for > 1 hour, limited operations */
  LIMITED = "limited",
  /** Leader unreachable for > 24 hours */
  OFFLINE = "offline",
}

/** Sync request from follower to leader */
export interface SyncRequest {
  /** Unique identifier for this follower */
  followerId: string;
  /** Current signing key version known to follower */
  signingKeyVersion: number;
  /** Current provider configs version */
  providerConfigsVersion: number;
  /** Current revocation list version */
  revocationListVersion: number;
  /** List of known root token IDs (for delta sync) */
  knownRootTokens?: string[];
}

/** Sync response from leader to follower */
export interface SyncResponse {
  /** New signing key (base64-encoded), only if changed */
  signingKey?: string;
  /** Current signing key version */
  signingKeyVersion: number;
  /** Provider configurations, only if changed */
  providerConfigs?: Record<string, unknown>;
  /** Current provider configs version */
  providerConfigsVersion: number;
  /** Delta of newly revoked token IDs since follower's version */
  revocationListDelta: string[];
  /** Current revocation list version */
  revocationListVersion: number;
  /** Recommended seconds until next sync */
  nextSyncSeconds: number;
  /** Leader's current timestamp (for clock skew detection) */
  leaderTimestamp: string;
}

/** Push message types for WebSocket */
export enum PushMessageType {
  /** Token has been revoked */
  REVOCATION = "revocation",
  /** Signing key has been rotated */
  KEY_ROTATION = "key_rotation",
  /** Provider config updated */
  CONFIG_UPDATE = "config_update",
}

/** Push message for WebSocket notifications */
export interface PushMessage {
  type: PushMessageType;
  timestamp: string;
  data: RevocationPush | KeyRotationPush | ConfigUpdatePush;
}

/** Revocation push data */
export interface RevocationPush {
  tokenId: string;
  reason?: string;
  revokedAt: string;
}

/** Key rotation push data */
export interface KeyRotationPush {
  newKeyVersion: number;
  newKey: string; // base64-encoded
}

/** Config update push data */
export interface ConfigUpdatePush {
  newVersion: number;
  configs: Record<string, unknown>;
}

/** Revoked token entry */
export interface RevokedToken {
  tokenId: string;
  agentId: string;
  revokedAt: string;
  reason?: string;
  /** If set, revocation expires and token becomes valid again */
  expiresAt?: string;
}

/** Versioned signing key */
export interface VersionedKey {
  version: number;
  key: Buffer;
  createdAt: string;
  /** If set, this key should not be used for signing after this time */
  deprecatedAt?: string;
}

/** Information about a connected follower (leader-side) */
export interface FollowerInfo {
  followerId: string;
  lastSyncAt: string;
  signingKeyVersion: number;
  providerConfigsVersion: number;
  revocationListVersion: number;
  ipAddress?: string;
}

/** Distributed broker status */
export interface DistributedStatus {
  mode: BrokerMode;
  state?: FollowerState;
  signingKeyVersion: number;
  providerConfigsVersion: number;
  revocationCount: number;
  /** For followers: when last synced */
  lastSyncAt?: string;
  /** For followers: leader URL */
  leaderUrl?: string;
  /** For leaders: connected follower count */
  followerCount?: number;
  /** For leaders: list of follower IDs */
  followers?: string[];
}

/** Configuration for follower mode */
export interface FollowerConfig {
  /** Leader broker URL */
  leaderUrl: string;
  /** Authentication token for leader */
  leaderAuthToken: string;
  /** Unique identifier for this follower */
  followerId: string;
  /** Sync interval in seconds (default: 60) */
  syncIntervalSeconds?: number;
  /** Timeout for sync requests in ms (default: 30000) */
  syncTimeoutMs?: number;
  /** Whether to use WebSocket for push notifications */
  useWebSocket?: boolean;
}

/** Configuration for leader mode */
export interface LeaderConfig {
  /** Port to listen on (default: 8443) */
  port?: number;
  /** Host to bind to (default: 0.0.0.0) */
  host?: string;
  /** TLS certificate path (optional) */
  tlsCertPath?: string;
  /** TLS key path (optional) */
  tlsKeyPath?: string;
  /** Shared secret for follower authentication */
  followerAuthToken: string;
}

/** Thresholds for state transitions */
export const STATE_THRESHOLDS = {
  /** Seconds without sync before entering DEGRADED state */
  DEGRADED_THRESHOLD_SECONDS: 5 * 60, // 5 minutes
  /** Seconds without sync before entering LIMITED state */
  LIMITED_THRESHOLD_SECONDS: 60 * 60, // 1 hour
  /** Seconds without sync before entering OFFLINE state */
  OFFLINE_THRESHOLD_SECONDS: 24 * 60 * 60, // 24 hours
} as const;

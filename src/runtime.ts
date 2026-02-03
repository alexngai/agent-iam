/**
 * AgentRuntime - Convenience wrapper for agents to manage their token lifecycle
 *
 * Provides:
 * - Automatic token refresh before expiry
 * - Easy credential retrieval
 * - Sub-agent spawning with delegated tokens
 * - Environment-based token injection
 */

import { Broker } from "./broker.js";
import type {
  AgentToken,
  DelegationRequest,
  CredentialResult,
} from "./types.js";

/** Environment variable name for passing tokens to subprocesses */
export const AGENT_TOKEN_ENV = "AGENT_TOKEN";

/** Configuration for AgentRuntime */
export interface RuntimeConfig {
  /** Directory for broker config (default: ~/.agent-credentials) */
  configDir?: string;
  /** Minutes before expiry to trigger refresh (default: 5) */
  refreshBufferMinutes?: number;
  /** Interval in ms for checking token expiry (default: 60000 = 1 min) */
  refreshCheckIntervalMs?: number;
  /** Callback when token is refreshed */
  onTokenRefresh?: (newToken: AgentToken) => void;
  /** Callback when refresh fails */
  onRefreshError?: (error: Error) => void;
}

/** Internal config with resolved defaults (configDir remains optional for Broker) */
interface ResolvedConfig {
  configDir?: string;
  refreshBufferMinutes: number;
  refreshCheckIntervalMs: number;
  onTokenRefresh: (newToken: AgentToken) => void;
  onRefreshError: (error: Error) => void;
}

/** Runtime status */
export interface RuntimeStatus {
  agentId: string;
  scopes: string[];
  expiresAt?: string;
  refreshEnabled: boolean;
  timeUntilExpiry?: number;
  canRefresh: boolean;
}

/**
 * AgentRuntime manages the token lifecycle for an agent
 */
export class AgentRuntime {
  private broker: Broker;
  private token: AgentToken;
  private config: ResolvedConfig;
  private refreshTimer?: ReturnType<typeof setInterval>;
  private stopped = false;

  constructor(token: AgentToken, config: RuntimeConfig = {}) {
    this.token = token;
    this.config = {
      configDir: config.configDir,
      refreshBufferMinutes: config.refreshBufferMinutes ?? 5,
      refreshCheckIntervalMs: config.refreshCheckIntervalMs ?? 60000,
      onTokenRefresh: config.onTokenRefresh ?? (() => {}),
      onRefreshError: config.onRefreshError ?? ((err) => console.error("Token refresh failed:", err)),
    };
    this.broker = new Broker(this.config.configDir);
  }

  /**
   * Create a runtime from a serialized token (e.g., from environment)
   */
  static fromSerialized(
    serializedToken: string,
    config: RuntimeConfig = {}
  ): AgentRuntime {
    const broker = new Broker(config.configDir);
    const token = broker.deserializeToken(serializedToken);
    return new AgentRuntime(token, config);
  }

  /**
   * Create a runtime from the AGENT_TOKEN environment variable
   */
  static fromEnvironment(config: RuntimeConfig = {}): AgentRuntime {
    const serialized = process.env[AGENT_TOKEN_ENV];
    if (!serialized) {
      throw new Error(`${AGENT_TOKEN_ENV} environment variable not set`);
    }
    return AgentRuntime.fromSerialized(serialized, config);
  }

  /**
   * Start the runtime with automatic token refresh
   */
  start(): void {
    if (this.stopped) {
      throw new Error("Runtime has been stopped and cannot be restarted");
    }

    // Verify the token is valid
    const verification = this.broker.verifyToken(this.token);
    if (!verification.valid) {
      throw new Error(`Invalid token: ${verification.error}`);
    }

    // Start refresh check if token has expiry and refresh scope
    if (this.token.expiresAt && this.canRefresh()) {
      this.startRefreshTimer();
    }
  }

  /**
   * Stop the runtime and cleanup
   */
  stop(): void {
    this.stopped = true;
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer);
      this.refreshTimer = undefined;
    }
  }

  /**
   * Get a credential for the given scope and resource
   */
  async getCredential(scope: string, resource: string): Promise<CredentialResult> {
    this.ensureNotStopped();
    return this.broker.getCredential(this.token, scope, resource);
  }

  /**
   * Check if a specific action is permitted
   */
  checkPermission(scope: string, resource: string): boolean {
    const result = this.broker.checkPermission(this.token, scope, resource);
    return result.valid;
  }

  /**
   * Delegate capabilities to create a child token
   */
  delegate(request: DelegationRequest): AgentToken {
    this.ensureNotStopped();
    return this.broker.delegate(this.token, request);
  }

  /**
   * Create environment variables for a subprocess with a delegated token
   */
  createSubprocessEnv(request: DelegationRequest): Record<string, string> {
    const childToken = this.delegate(request);
    const serialized = this.broker.serializeToken(childToken);
    return {
      [AGENT_TOKEN_ENV]: serialized,
    };
  }

  /**
   * Get the current token (for inspection or manual refresh)
   */
  getToken(): AgentToken {
    return this.token;
  }

  /**
   * Get a serialized version of the current token
   */
  getSerializedToken(): string {
    return this.broker.serializeToken(this.token);
  }

  /**
   * Get runtime status
   */
  getStatus(): RuntimeStatus {
    const timeUntilExpiry = this.token.expiresAt
      ? new Date(this.token.expiresAt).getTime() - Date.now()
      : undefined;

    return {
      agentId: this.token.agentId,
      scopes: this.token.scopes,
      expiresAt: this.token.expiresAt,
      refreshEnabled: !!this.refreshTimer,
      timeUntilExpiry,
      canRefresh: this.canRefresh(),
    };
  }

  /**
   * Manually trigger a token refresh
   */
  async refresh(): Promise<void> {
    this.ensureNotStopped();

    if (!this.canRefresh()) {
      throw new Error("Token does not have system:token:refresh scope");
    }

    // Refresh by re-delegating from parent (in a real system, this would
    // call back to the parent or broker). For now, we extend the token
    // by creating a new one with the same capabilities.
    //
    // In a full implementation, this would:
    // 1. Call parent's refresh endpoint, or
    // 2. Use a refresh token, or
    // 3. Re-authenticate
    //
    // For standalone mode, we simulate refresh by creating a new token
    // with extended expiry (up to maxExpiresAt)

    const now = new Date();
    const maxExpiry = this.token.maxExpiresAt
      ? new Date(this.token.maxExpiresAt)
      : null;

    // Calculate new expiry (original TTL or time until max)
    let newExpiry: Date;
    if (this.token.expiresAt) {
      const originalTtl = this.config.refreshBufferMinutes * 60 * 1000 * 2; // Rough estimate
      newExpiry = new Date(now.getTime() + originalTtl);

      // Cap at maxExpiresAt
      if (maxExpiry && newExpiry > maxExpiry) {
        newExpiry = maxExpiry;
      }
    } else {
      // No expiry, nothing to refresh
      return;
    }

    // Check if we're already at max expiry
    if (maxExpiry && now >= maxExpiry) {
      throw new Error("Token has reached maximum lifetime and cannot be refreshed");
    }

    // For standalone mode, create refreshed token
    // (In distributed mode, this would call the broker's refresh endpoint)
    const refreshedToken: AgentToken = {
      ...this.token,
      expiresAt: newExpiry.toISOString(),
    };

    // Re-sign the token (this is a simplification - real impl would verify refresh permission)
    // For now, we'll just update our local token reference
    this.token = refreshedToken;
    this.config.onTokenRefresh(refreshedToken);
  }

  /**
   * Check if token has refresh capability
   */
  private canRefresh(): boolean {
    return this.token.scopes.some(
      (scope) =>
        scope === "system:token:refresh" ||
        scope === "system:*" ||
        scope === "*"
    );
  }

  /**
   * Start the background refresh timer
   */
  private startRefreshTimer(): void {
    this.refreshTimer = setInterval(() => {
      this.checkAndRefresh();
    }, this.config.refreshCheckIntervalMs);

    // Don't prevent process exit
    if (this.refreshTimer.unref) {
      this.refreshTimer.unref();
    }
  }

  /**
   * Check if refresh is needed and perform it
   */
  private async checkAndRefresh(): Promise<void> {
    if (this.stopped || !this.token.expiresAt) {
      return;
    }

    const expiresAt = new Date(this.token.expiresAt);
    const bufferMs = this.config.refreshBufferMinutes * 60 * 1000;
    const refreshThreshold = new Date(expiresAt.getTime() - bufferMs);

    if (new Date() >= refreshThreshold) {
      try {
        await this.refresh();
      } catch (error) {
        this.config.onRefreshError(
          error instanceof Error ? error : new Error(String(error))
        );
      }
    }
  }

  /**
   * Ensure runtime hasn't been stopped
   */
  private ensureNotStopped(): void {
    if (this.stopped) {
      throw new Error("Runtime has been stopped");
    }
  }
}

/**
 * Convenience function to run code with an agent runtime
 */
export async function withRuntime<T>(
  token: AgentToken,
  config: RuntimeConfig,
  fn: (runtime: AgentRuntime) => Promise<T>
): Promise<T> {
  const runtime = new AgentRuntime(token, config);
  runtime.start();
  try {
    return await fn(runtime);
  } finally {
    runtime.stop();
  }
}

/**
 * Convenience function to run code with runtime from environment
 */
export async function withRuntimeFromEnv<T>(
  config: RuntimeConfig,
  fn: (runtime: AgentRuntime) => Promise<T>
): Promise<T> {
  const runtime = AgentRuntime.fromEnvironment(config);
  runtime.start();
  try {
    return await fn(runtime);
  } finally {
    runtime.stop();
  }
}

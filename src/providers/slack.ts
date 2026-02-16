/**
 * Slack provider adapter
 *
 * Supports two authentication modes:
 * - Bot Token: Agent acts as itself (the Slack app/bot) using a bot token (xoxb-...)
 * - User OAuth: Agent acts on behalf of a user using OAuth2 with token rotation (xoxp-...)
 *
 * Slack bot tokens don't expire and permissions are fixed at app install time.
 * User tokens can be refreshed using Slack's token rotation feature.
 */

import type { CredentialResult } from "../types.js";

/** Slack scope mapping from our format to Slack API scopes */
const SCOPE_MAPPING: Record<string, string[]> = {
  // Chat / messaging
  "slack:chat:write": ["chat:write"],
  "slack:chat:read": ["channels:history", "groups:history", "im:history", "mpim:history"],

  // Channels
  "slack:channels:read": ["channels:read", "groups:read"],
  "slack:channels:write": ["channels:manage", "groups:write"],
  "slack:channels:join": ["channels:join"],

  // Direct messages
  "slack:im:read": ["im:read"],
  "slack:im:write": ["im:write"],

  // Files
  "slack:files:read": ["files:read"],
  "slack:files:write": ["files:write"],

  // Reactions
  "slack:reactions:read": ["reactions:read"],
  "slack:reactions:write": ["reactions:write"],

  // Users
  "slack:users:read": ["users:read"],
  "slack:users:read.email": ["users:read.email"],

  // Pins / bookmarks
  "slack:pins:read": ["pins:read"],
  "slack:pins:write": ["pins:write"],

  // User profile
  "slack:usergroups:read": ["usergroups:read"],
  "slack:usergroups:write": ["usergroups:write"],
};

/** Slack provider configuration */
export interface SlackProviderConfig {
  /** Authentication mode */
  mode: "bot" | "user";
  /** Bot token (xoxb-...) or User token (xoxp-...) */
  token: string;
  /** OAuth2 Client ID (required for user mode with token rotation) */
  clientId?: string;
  /** OAuth2 Client Secret (required for user mode with token rotation) */
  clientSecret?: string;
  /** Refresh token for token rotation (user mode only) */
  refreshToken?: string;
  /** Team/workspace ID for scoping */
  teamId?: string;
}

/** Token response from Slack OAuth */
interface SlackTokenResponse {
  ok: boolean;
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in?: number;
  team: { id: string };
  error?: string;
}

/** Auth test response */
interface SlackAuthTestResponse {
  ok: boolean;
  url: string;
  team: string;
  team_id: string;
  user: string;
  user_id: string;
  bot_id?: string;
  error?: string;
}

export class SlackProvider {
  private config: SlackProviderConfig;
  private static readonly TOKEN_ENDPOINT = "https://slack.com/api/oauth.v2.access";
  private static readonly AUTH_TEST_ENDPOINT = "https://slack.com/api/auth.test";

  constructor(config: SlackProviderConfig) {
    this.config = config;
  }

  /**
   * Issue a Slack credential
   *
   * For bot mode: returns the bot token directly (tokens don't expire).
   * For user mode: refreshes the token if rotation is configured, otherwise returns stored token.
   *
   * @param scope - The scope requested (e.g., "slack:chat:write")
   * @param _resource - Resource identifier (e.g., channel ID)
   */
  async issueCredential(scope: string, _resource: string): Promise<CredentialResult> {
    const slackScopes = this.scopeToSlackScopes(scope);

    if (this.config.mode === "bot") {
      return this.issueBotCredential(slackScopes);
    }

    return this.issueUserCredential(slackScopes);
  }

  /**
   * Issue a bot token credential
   * Bot tokens don't expire, so we return the stored token with a generous TTL.
   */
  private async issueBotCredential(slackScopes: string[]): Promise<CredentialResult> {
    // Bot tokens are long-lived; set a 60-minute credential window
    // for cache consistency with other providers
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    return {
      credentialType: "bearer_token",
      credential: {
        token: this.config.token,
        tokenType: "bearer",
        mode: "bot",
        scopes: slackScopes,
        teamId: this.config.teamId,
      },
      expiresAt,
    };
  }

  /**
   * Issue a user token credential
   * If token rotation is configured, refreshes the token.
   * Otherwise returns the stored token.
   */
  private async issueUserCredential(slackScopes: string[]): Promise<CredentialResult> {
    // If we have refresh capability, get a fresh token
    if (this.config.clientId && this.config.clientSecret && this.config.refreshToken) {
      const tokenData = await this.refreshAccessToken();

      // Update stored refresh token if rotated
      if (tokenData.refresh_token) {
        this.config.refreshToken = tokenData.refresh_token;
      }

      const expiresAt = tokenData.expires_in
        ? new Date(Date.now() + tokenData.expires_in * 1000).toISOString()
        : new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString(); // 12 hours default

      return {
        credentialType: "bearer_token",
        credential: {
          token: tokenData.access_token,
          tokenType: "bearer",
          mode: "user",
          scopes: slackScopes,
          teamId: tokenData.team?.id ?? this.config.teamId,
        },
        expiresAt,
      };
    }

    // No refresh capability — return stored token
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    return {
      credentialType: "bearer_token",
      credential: {
        token: this.config.token,
        tokenType: "bearer",
        mode: "user",
        scopes: slackScopes,
        teamId: this.config.teamId,
      },
      expiresAt,
    };
  }

  /**
   * Refresh the access token using the refresh token (Slack token rotation)
   */
  private async refreshAccessToken(): Promise<SlackTokenResponse> {
    const params = new URLSearchParams({
      client_id: this.config.clientId!,
      client_secret: this.config.clientSecret!,
      grant_type: "refresh_token",
      refresh_token: this.config.refreshToken!,
    });

    const response = await fetch(SlackProvider.TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Slack OAuth token refresh failed (HTTP ${response.status}): ${error}`);
    }

    const data = await response.json() as SlackTokenResponse;

    if (!data.ok) {
      throw new Error(`Slack OAuth token refresh failed: ${data.error ?? "unknown error"}`);
    }

    return data;
  }

  /**
   * Convert our scope format to Slack API scopes
   */
  private scopeToSlackScopes(scope: string): string[] {
    // Direct match
    if (SCOPE_MAPPING[scope]) {
      return SCOPE_MAPPING[scope];
    }

    // Handle wildcard scopes
    if (scope === "slack:chat:*") {
      return ["chat:write", "channels:history", "groups:history", "im:history", "mpim:history"];
    }

    if (scope === "slack:channels:*") {
      return ["channels:read", "channels:manage", "channels:join", "groups:read", "groups:write"];
    }

    if (scope === "slack:files:*") {
      return ["files:read", "files:write"];
    }

    if (scope === "slack:reactions:*") {
      return ["reactions:read", "reactions:write"];
    }

    if (scope === "slack:im:*") {
      return ["im:read", "im:write"];
    }

    if (scope === "slack:users:*") {
      return ["users:read", "users:read.email"];
    }

    if (scope === "slack:*") {
      // Return a common set of scopes
      return [
        "chat:write",
        "channels:read",
        "channels:history",
        "im:read",
        "im:write",
        "files:read",
        "reactions:read",
        "reactions:write",
        "users:read",
      ];
    }

    // Default to empty
    return [];
  }

  /**
   * Verify the Slack configuration is valid by calling auth.test
   */
  async verify(): Promise<{ valid: boolean; error?: string }> {
    try {
      const response = await fetch(SlackProvider.AUTH_TEST_ENDPOINT, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.config.token}`,
          "Content-Type": "application/json",
        },
      });

      if (!response.ok) {
        return {
          valid: false,
          error: `Slack API returned HTTP ${response.status}`,
        };
      }

      const data = await response.json() as SlackAuthTestResponse;

      if (!data.ok) {
        return {
          valid: false,
          error: `Slack auth.test failed: ${data.error ?? "unknown error"}`,
        };
      }

      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get identity info for the current token
   */
  async getIdentity(): Promise<{
    team: string;
    teamId: string;
    user: string;
    userId: string;
    botId?: string;
  }> {
    const response = await fetch(SlackProvider.AUTH_TEST_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.config.token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`Slack API returned HTTP ${response.status}`);
    }

    const data = await response.json() as SlackAuthTestResponse;

    if (!data.ok) {
      throw new Error(`Failed to get Slack identity: ${data.error ?? "unknown error"}`);
    }

    return {
      team: data.team,
      teamId: data.team_id,
      user: data.user,
      userId: data.user_id,
      botId: data.bot_id,
    };
  }
}

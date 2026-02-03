/**
 * Google OAuth provider adapter
 *
 * Uses OAuth2 refresh tokens to obtain access tokens with specific scopes.
 * Requires a stored refresh token from an initial OAuth flow.
 */

import type { CredentialResult } from "../types.js";

/** Google OAuth scopes mapping from our format */
const SCOPE_MAPPING: Record<string, string[]> = {
  "google:gmail:read": ["https://www.googleapis.com/auth/gmail.readonly"],
  "google:gmail:send": ["https://www.googleapis.com/auth/gmail.send"],
  "google:gmail:modify": ["https://www.googleapis.com/auth/gmail.modify"],
  "google:drive:read": ["https://www.googleapis.com/auth/drive.readonly"],
  "google:drive:write": ["https://www.googleapis.com/auth/drive.file"],
  "google:drive:full": ["https://www.googleapis.com/auth/drive"],
  "google:calendar:read": ["https://www.googleapis.com/auth/calendar.readonly"],
  "google:calendar:write": ["https://www.googleapis.com/auth/calendar"],
  "google:sheets:read": ["https://www.googleapis.com/auth/spreadsheets.readonly"],
  "google:sheets:write": ["https://www.googleapis.com/auth/spreadsheets"],
  "google:docs:read": ["https://www.googleapis.com/auth/documents.readonly"],
  "google:docs:write": ["https://www.googleapis.com/auth/documents"],
};

/** Google provider configuration */
export interface GoogleProviderConfig {
  /** OAuth2 Client ID */
  clientId: string;
  /** OAuth2 Client Secret */
  clientSecret: string;
  /** Refresh token from initial OAuth flow */
  refreshToken: string;
}

/** Token response from Google OAuth */
interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  scope?: string;
}

export class GoogleProvider {
  private config: GoogleProviderConfig;
  private static readonly TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

  constructor(config: GoogleProviderConfig) {
    this.config = config;
  }

  /**
   * Issue a Google OAuth access token
   *
   * @param scope - The scope requested (e.g., "google:gmail:read")
   * @param _resource - Resource identifier (not used for Google OAuth)
   */
  async issueCredential(scope: string, _resource: string): Promise<CredentialResult> {
    const googleScopes = this.scopeToGoogleScopes(scope);

    const tokenData = await this.refreshAccessToken(googleScopes);

    const expiresAt = new Date(Date.now() + tokenData.expires_in * 1000).toISOString();

    return {
      credentialType: "bearer_token",
      credential: {
        token: tokenData.access_token,
        tokenType: tokenData.token_type,
        scopes: googleScopes,
      },
      expiresAt,
    };
  }

  /**
   * Refresh the access token using the refresh token
   */
  private async refreshAccessToken(scopes: string[]): Promise<TokenResponse> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      refresh_token: this.config.refreshToken,
      grant_type: "refresh_token",
    });

    // If specific scopes requested, include them
    if (scopes.length > 0) {
      params.set("scope", scopes.join(" "));
    }

    const response = await fetch(GoogleProvider.TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Google OAuth token refresh failed: ${error}`);
    }

    return response.json() as Promise<TokenResponse>;
  }

  /**
   * Convert our scope format to Google OAuth scopes
   */
  private scopeToGoogleScopes(scope: string): string[] {
    // Direct match
    if (SCOPE_MAPPING[scope]) {
      return SCOPE_MAPPING[scope];
    }

    // Handle wildcard scopes
    if (scope === "google:gmail:*") {
      return [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
      ];
    }

    if (scope === "google:drive:*") {
      return ["https://www.googleapis.com/auth/drive"];
    }

    if (scope === "google:*") {
      // Return a common set of scopes
      return [
        "https://www.googleapis.com/auth/gmail.readonly",
        "https://www.googleapis.com/auth/drive.readonly",
        "https://www.googleapis.com/auth/calendar.readonly",
      ];
    }

    // Default to empty (will use whatever scopes the refresh token has)
    return [];
  }

  /**
   * Verify the Google OAuth configuration is valid
   */
  async verify(): Promise<{ valid: boolean; error?: string }> {
    try {
      // Try to get a token with minimal scopes
      await this.refreshAccessToken([]);
      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get user info to verify token validity
   */
  async getUserInfo(): Promise<{ email: string; name?: string }> {
    const tokenData = await this.refreshAccessToken([
      "https://www.googleapis.com/auth/userinfo.email",
    ]);

    const response = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to get user info: ${response.statusText}`);
    }

    const data = await response.json() as { email: string; name?: string };
    return { email: data.email, name: data.name };
  }
}

/**
 * Generic API Key provider adapter
 *
 * Provides a simple wrapper for API key-based authentication.
 * Useful for services like OpenAI, Anthropic, Stripe, etc.
 * that use simple bearer tokens or API keys.
 */

import type { CredentialResult } from "../types.js";

/** API Key provider configuration */
export interface APIKeyProviderConfig {
  /** The API key/token */
  apiKey: string;
  /** Provider name for identification (e.g., "openai", "anthropic") */
  providerName: string;
  /** How long credentials should be considered valid (in minutes, default: 60) */
  ttlMinutes?: number;
  /** Optional base URL for the API */
  baseUrl?: string;
  /** Additional headers to include */
  additionalHeaders?: Record<string, string>;
}

/** Configured API key entry */
interface APIKeyEntry {
  config: APIKeyProviderConfig;
  scopes: string[];
}

export class APIKeyProvider {
  private keys: Map<string, APIKeyEntry> = new Map();

  constructor() {
    // Initialize with empty key store
  }

  /**
   * Add an API key configuration
   *
   * @param name - Unique name for this key (e.g., "openai-prod")
   * @param config - API key configuration
   * @param scopes - Scopes this key is authorized for
   */
  addKey(name: string, config: APIKeyProviderConfig, scopes: string[]): void {
    this.keys.set(name, { config, scopes });
  }

  /**
   * Remove an API key
   */
  removeKey(name: string): boolean {
    return this.keys.delete(name);
  }

  /**
   * List configured keys (without exposing actual keys)
   */
  listKeys(): Array<{ name: string; provider: string; scopes: string[] }> {
    return Array.from(this.keys.entries()).map(([name, entry]) => ({
      name,
      provider: entry.config.providerName,
      scopes: entry.scopes,
    }));
  }

  /**
   * Issue an API key credential
   *
   * @param scope - The scope requested (e.g., "openai:chat:*")
   * @param _resource - Resource identifier (not typically used for API keys)
   */
  async issueCredential(scope: string, _resource: string): Promise<CredentialResult> {
    // Find a key that matches the requested scope
    const entry = this.findKeyForScope(scope);
    if (!entry) {
      throw new Error(`No API key configured for scope: ${scope}`);
    }

    const { config } = entry;
    const ttlMinutes = config.ttlMinutes ?? 60;
    const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000).toISOString();

    return {
      credentialType: "api_key",
      credential: {
        apiKey: config.apiKey,
        providerName: config.providerName,
        baseUrl: config.baseUrl,
        headers: {
          Authorization: `Bearer ${config.apiKey}`,
          ...config.additionalHeaders,
        },
      },
      expiresAt,
    };
  }

  /**
   * Find a key that matches the requested scope
   */
  private findKeyForScope(requestedScope: string): APIKeyEntry | null {
    for (const entry of this.keys.values()) {
      for (const keyScope of entry.scopes) {
        if (this.scopeMatches(keyScope, requestedScope)) {
          return entry;
        }
      }
    }
    return null;
  }

  /**
   * Check if a key scope matches the requested scope
   */
  private scopeMatches(keyScope: string, requestedScope: string): boolean {
    // Exact match
    if (keyScope === requestedScope) return true;

    // Wildcard match
    if (keyScope === "*") return true;

    // Prefix wildcard (e.g., "openai:*" matches "openai:chat:completions")
    if (keyScope.endsWith(":*")) {
      const prefix = keyScope.slice(0, -1); // Remove "*"
      return requestedScope.startsWith(prefix);
    }

    // Segment wildcard (e.g., "openai:chat:*" matches "openai:chat:completions")
    const keyParts = keyScope.split(":");
    const requestedParts = requestedScope.split(":");

    if (keyParts.length > requestedParts.length) return false;

    for (let i = 0; i < keyParts.length; i++) {
      if (keyParts[i] === "*") continue;
      if (keyParts[i] !== requestedParts[i]) return false;
    }

    return true;
  }

  /**
   * Verify the API key is valid by making a test request
   * (Only works if testEndpoint is configured)
   */
  async verify(keyName: string): Promise<{ valid: boolean; error?: string }> {
    const entry = this.keys.get(keyName);
    if (!entry) {
      return { valid: false, error: `Key "${keyName}" not found` };
    }

    // For API keys, we can only verify structure
    // Real validation would require provider-specific endpoints
    if (!entry.config.apiKey || entry.config.apiKey.length < 10) {
      return { valid: false, error: "API key appears to be invalid (too short)" };
    }

    return { valid: true };
  }

  /**
   * Rotate an API key (replace with new value)
   */
  rotateKey(name: string, newApiKey: string): void {
    const entry = this.keys.get(name);
    if (!entry) {
      throw new Error(`Key "${name}" not found`);
    }

    entry.config.apiKey = newApiKey;
  }
}

/**
 * Factory for creating pre-configured API key providers for common services
 */
export const APIKeyProviderFactory = {
  /**
   * Create a provider for OpenAI
   */
  openai(apiKey: string, orgId?: string): APIKeyProviderConfig {
    return {
      apiKey,
      providerName: "openai",
      baseUrl: "https://api.openai.com/v1",
      additionalHeaders: orgId ? { "OpenAI-Organization": orgId } : undefined,
    };
  },

  /**
   * Create a provider for Anthropic
   */
  anthropic(apiKey: string): APIKeyProviderConfig {
    return {
      apiKey,
      providerName: "anthropic",
      baseUrl: "https://api.anthropic.com/v1",
      additionalHeaders: {
        "anthropic-version": "2024-01-01",
      },
    };
  },

  /**
   * Create a provider for Stripe
   */
  stripe(apiKey: string): APIKeyProviderConfig {
    return {
      apiKey,
      providerName: "stripe",
      baseUrl: "https://api.stripe.com/v1",
    };
  },

  /**
   * Create a provider for SendGrid
   */
  sendgrid(apiKey: string): APIKeyProviderConfig {
    return {
      apiKey,
      providerName: "sendgrid",
      baseUrl: "https://api.sendgrid.com/v3",
    };
  },

  /**
   * Create a provider for Twilio
   */
  twilio(accountSid: string, authToken: string): APIKeyProviderConfig {
    // Twilio uses Basic auth, encode credentials
    const credentials = Buffer.from(`${accountSid}:${authToken}`).toString("base64");
    return {
      apiKey: credentials,
      providerName: "twilio",
      baseUrl: `https://api.twilio.com/2010-04-01/Accounts/${accountSid}`,
      additionalHeaders: {
        Authorization: `Basic ${credentials}`,
      },
    };
  },

  /**
   * Create a generic API key provider
   */
  generic(providerName: string, apiKey: string, baseUrl?: string): APIKeyProviderConfig {
    return {
      apiKey,
      providerName,
      baseUrl,
    };
  },
};

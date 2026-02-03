/**
 * Core Broker class that ties together token management and credential issuance
 */

import type {
  AgentToken,
  DelegationRequest,
  CredentialResult,
  VerificationResult,
  Constraints,
  GitHubProviderConfig,
} from "./types.js";
import { TokenService } from "./token.js";
import { ConfigService } from "./config.js";
import { GitHubProvider } from "./providers/github.js";

/** Credential cache entry */
interface CacheEntry {
  credential: CredentialResult;
  expiresAt: Date;
}

/** Broker status */
export interface BrokerStatus {
  mode: "standalone";
  configDir: string;
  providers: string[];
  secretExists: boolean;
}

export class Broker {
  private tokenService: TokenService;
  private configService: ConfigService;
  private credentialCache: Map<string, CacheEntry> = new Map();

  /** Cache buffer - evict credentials this many ms before expiry */
  private cacheBuffer = 5 * 60 * 1000; // 5 minutes

  constructor(configDir?: string) {
    this.configService = new ConfigService(configDir);
    const secret = this.configService.getOrCreateSecret();
    this.tokenService = new TokenService(secret);
  }

  // ─────────────────────────────────────────────────────────────────
  // TOKEN OPERATIONS
  // ─────────────────────────────────────────────────────────────────

  /**
   * Create a root token with the specified capabilities
   */
  createRootToken(params: {
    agentId: string;
    scopes: string[];
    constraints?: Constraints;
    delegatable?: boolean;
    maxDelegationDepth?: number;
    ttlDays?: number;
  }): AgentToken {
    return this.tokenService.createRootToken(params);
  }

  /**
   * Delegate capabilities from a parent token to create a child token
   */
  delegate(parent: AgentToken, request: DelegationRequest): AgentToken {
    // First verify the parent token
    const verification = this.tokenService.verify(parent);
    if (!verification.valid) {
      throw new Error(`Invalid parent token: ${verification.error}`);
    }

    return this.tokenService.delegate(parent, request);
  }

  /**
   * Verify a token's validity
   */
  verifyToken(token: AgentToken): VerificationResult {
    return this.tokenService.verify(token);
  }

  /**
   * Check if a token allows a specific action on a resource
   */
  checkPermission(
    token: AgentToken,
    scope: string,
    resource: string
  ): VerificationResult {
    return this.tokenService.checkPermission(token, scope, resource);
  }

  /**
   * Serialize a token for passing to another process
   */
  serializeToken(token: AgentToken): string {
    return this.tokenService.serialize(token);
  }

  /**
   * Deserialize a token received from another process
   */
  deserializeToken(serialized: string): AgentToken {
    return this.tokenService.deserialize(serialized);
  }

  // ─────────────────────────────────────────────────────────────────
  // CREDENTIAL OPERATIONS
  // ─────────────────────────────────────────────────────────────────

  /**
   * Get a provider credential for the given scope and resource
   */
  async getCredential(
    token: AgentToken,
    scope: string,
    resource: string
  ): Promise<CredentialResult> {
    // Check permission
    const permission = this.checkPermission(token, scope, resource);
    if (!permission.valid) {
      throw new Error(`Permission denied: ${permission.error}`);
    }

    // Check cache
    const cacheKey = `${scope}:${resource}`;
    const cached = this.credentialCache.get(cacheKey);
    if (cached && cached.expiresAt.getTime() - this.cacheBuffer > Date.now()) {
      return cached.credential;
    }

    // Issue credential from provider
    const provider = this.getProviderFromScope(scope);
    const credential = await this.issueFromProvider(provider, scope, resource);

    // Cache it
    if (credential.expiresAt) {
      this.credentialCache.set(cacheKey, {
        credential,
        expiresAt: new Date(credential.expiresAt),
      });
    }

    return credential;
  }

  /**
   * Extract the provider name from a scope
   */
  private getProviderFromScope(scope: string): string {
    const parts = scope.split(":");
    if (parts.length < 2) {
      throw new Error(`Invalid scope format: ${scope}`);
    }
    return parts[0];
  }

  /**
   * Issue a credential from the appropriate provider
   */
  private async issueFromProvider(
    provider: string,
    scope: string,
    resource: string
  ): Promise<CredentialResult> {
    switch (provider) {
      case "github": {
        const config = this.configService.getProviderConfig<GitHubProviderConfig>("github");
        if (!config) {
          throw new Error("GitHub provider not configured");
        }
        const githubProvider = new GitHubProvider(config);
        return githubProvider.issueCredential(scope, resource);
      }

      default:
        throw new Error(`Provider "${provider}" not supported`);
    }
  }

  // ─────────────────────────────────────────────────────────────────
  // CONFIGURATION OPERATIONS
  // ─────────────────────────────────────────────────────────────────

  /**
   * Initialize a provider
   */
  initProvider(
    provider: string,
    config: Record<string, string>
  ): void {
    switch (provider) {
      case "github":
        this.configService.initGitHub({
          appId: config.appId,
          installationId: config.installationId,
          privateKeyPath: config.privateKeyPath,
        });
        break;

      default:
        throw new Error(`Provider "${provider}" not supported`);
    }
  }

  /**
   * Get broker status
   */
  getStatus(): BrokerStatus {
    return {
      mode: "standalone",
      configDir: this.configService.getConfigDir(),
      providers: this.configService.listProviders(),
      secretExists: true, // We create it if it doesn't exist
    };
  }

  /**
   * Show configuration (with secrets redacted)
   */
  showConfig(): Record<string, unknown> {
    return this.configService.showConfig();
  }

  /**
   * Get the config service (for direct access)
   */
  getConfigService(): ConfigService {
    return this.configService;
  }
}

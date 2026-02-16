/**
 * Configuration management with JSON file storage
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type {
  BrokerConfig,
  ProvidersConfig,
  GitHubProviderConfig,
  GoogleProviderConfig,
  AWSProviderConfig,
  APIKeyProviderConfig,
  SlackProviderConfig,
} from "./types.js";
import { generateSecret } from "./token.js";

/** Default config directory */
const DEFAULT_CONFIG_DIR = path.join(os.homedir(), ".agent-credentials");

/** Config file names */
const CONFIG_FILE = "config.json";
const SECRET_FILE = "token_secret";

export class ConfigService {
  private configDir: string;
  private configPath: string;
  private secretPath: string;

  constructor(configDir: string = DEFAULT_CONFIG_DIR) {
    this.configDir = configDir;
    this.configPath = path.join(configDir, CONFIG_FILE);
    this.secretPath = path.join(configDir, SECRET_FILE);
  }

  /** Ensure config directory exists with proper permissions */
  ensureConfigDir(): void {
    if (!fs.existsSync(this.configDir)) {
      fs.mkdirSync(this.configDir, { recursive: true, mode: 0o700 });
    }
  }

  /** Load or create the signing secret */
  getOrCreateSecret(): Buffer {
    this.ensureConfigDir();

    if (fs.existsSync(this.secretPath)) {
      return fs.readFileSync(this.secretPath);
    }

    // Generate new secret
    const secret = generateSecret();
    fs.writeFileSync(this.secretPath, secret, { mode: 0o600 });
    return secret;
  }

  /** Load config file */
  loadConfig(): BrokerConfig {
    if (!fs.existsSync(this.configPath)) {
      return { providers: {} };
    }

    const content = fs.readFileSync(this.configPath, "utf-8");
    return JSON.parse(content) as BrokerConfig;
  }

  /** Save config file */
  saveConfig(config: BrokerConfig): void {
    this.ensureConfigDir();
    fs.writeFileSync(
      this.configPath,
      JSON.stringify(config, null, 2),
      { mode: 0o600 }
    );
  }

  /** Get provider configuration */
  getProviderConfig<T>(provider: string): T | undefined {
    const config = this.loadConfig();
    return config.providers[provider] as T | undefined;
  }

  /** Set provider configuration */
  setProviderConfig(provider: string, providerConfig: unknown): void {
    const config = this.loadConfig();
    config.providers[provider] = providerConfig as ProvidersConfig[string];
    this.saveConfig(config);
  }

  /** List configured providers */
  listProviders(): string[] {
    const config = this.loadConfig();
    return Object.keys(config.providers).filter(
      (key) => config.providers[key] !== undefined
    );
  }

  /** Initialize GitHub provider */
  initGitHub(params: {
    appId: string;
    installationId: string;
    privateKeyPath: string;
  }): void {
    // Validate private key exists
    const keyPath = path.isAbsolute(params.privateKeyPath)
      ? params.privateKeyPath
      : path.join(this.configDir, params.privateKeyPath);

    if (!fs.existsSync(keyPath)) {
      throw new Error(`Private key not found: ${keyPath}`);
    }

    const config: GitHubProviderConfig = {
      appId: params.appId,
      installationId: params.installationId,
      privateKeyPath: keyPath,
    };

    this.setProviderConfig("github", config);
  }

  /** Initialize Google OAuth provider */
  initGoogle(params: {
    clientId: string;
    clientSecret: string;
    refreshToken: string;
  }): void {
    const config: GoogleProviderConfig = {
      clientId: params.clientId,
      clientSecret: params.clientSecret,
      refreshToken: params.refreshToken,
    };

    this.setProviderConfig("google", config);
  }

  /** Initialize AWS STS provider */
  initAWS(params: {
    region: string;
    roleArn: string;
    externalId?: string;
    sessionDuration?: number;
    accessKeyId?: string;
    secretAccessKey?: string;
  }): void {
    const config: AWSProviderConfig = {
      region: params.region,
      roleArn: params.roleArn,
      externalId: params.externalId,
      sessionDuration: params.sessionDuration,
      accessKeyId: params.accessKeyId,
      secretAccessKey: params.secretAccessKey,
    };

    this.setProviderConfig("aws", config);
  }

  /** Initialize Slack provider */
  initSlack(params: {
    mode: "bot" | "user";
    token: string;
    clientId?: string;
    clientSecret?: string;
    refreshToken?: string;
    teamId?: string;
  }): void {
    const config: SlackProviderConfig = {
      mode: params.mode,
      token: params.token,
      clientId: params.clientId,
      clientSecret: params.clientSecret,
      refreshToken: params.refreshToken,
      teamId: params.teamId,
    };

    this.setProviderConfig("slack", config);
  }

  /** Add an API key provider */
  addAPIKey(params: {
    name: string;
    providerName: string;
    apiKey: string;
    baseUrl?: string;
    ttlMinutes?: number;
    additionalHeaders?: Record<string, string>;
  }): void {
    const config = this.loadConfig();

    // Initialize apikeys if not present
    if (!config.providers.apikeys) {
      config.providers.apikeys = {};
    }

    const keyConfig: APIKeyProviderConfig = {
      providerName: params.providerName,
      apiKey: params.apiKey,
      baseUrl: params.baseUrl,
      ttlMinutes: params.ttlMinutes,
      additionalHeaders: params.additionalHeaders,
    };

    config.providers.apikeys[params.name] = keyConfig;
    this.saveConfig(config);
  }

  /** Remove an API key */
  removeAPIKey(name: string): boolean {
    const config = this.loadConfig();

    if (!config.providers.apikeys || !config.providers.apikeys[name]) {
      return false;
    }

    delete config.providers.apikeys[name];
    this.saveConfig(config);
    return true;
  }

  /** List configured API keys (names only) */
  listAPIKeys(): string[] {
    const config = this.loadConfig();
    if (!config.providers.apikeys) {
      return [];
    }
    return Object.keys(config.providers.apikeys);
  }

  /** Get API key configuration by name */
  getAPIKeyConfig(name: string): APIKeyProviderConfig | undefined {
    const config = this.loadConfig();
    return config.providers.apikeys?.[name];
  }

  /** Get the config directory path */
  getConfigDir(): string {
    return this.configDir;
  }

  /** Show config (with secrets redacted) */
  showConfig(): Record<string, unknown> {
    const config = this.loadConfig();
    const redacted: Record<string, unknown> = { providers: {} };

    for (const [provider, providerConfig] of Object.entries(config.providers)) {
      if (!providerConfig) continue;

      // Handle nested apikeys specially
      if (provider === "apikeys" && typeof providerConfig === "object") {
        const apikeysRedacted: Record<string, unknown> = {};
        for (const [keyName, keyConfig] of Object.entries(providerConfig)) {
          apikeysRedacted[keyName] = {
            ...keyConfig,
            apiKey: "***REDACTED***",
          };
        }
        (redacted.providers as Record<string, unknown>)[provider] = apikeysRedacted;
        continue;
      }

      const providerRedacted: Record<string, unknown> = { ...providerConfig };

      // Redact sensitive fields
      if ("apiKey" in providerRedacted) {
        providerRedacted.apiKey = "***REDACTED***";
      }
      if ("clientSecret" in providerRedacted) {
        providerRedacted.clientSecret = "***REDACTED***";
      }
      if ("refreshToken" in providerRedacted) {
        providerRedacted.refreshToken = "***REDACTED***";
      }
      if ("secretAccessKey" in providerRedacted) {
        providerRedacted.secretAccessKey = "***REDACTED***";
      }
      if ("privateKeyPath" in providerRedacted) {
        providerRedacted.privateKeyPath = providerRedacted.privateKeyPath;
        providerRedacted.privateKeyExists = fs.existsSync(
          providerRedacted.privateKeyPath as string
        );
      }
      // Redact Slack token (xoxb-... or xoxp-...)
      if (provider === "slack" && "token" in providerRedacted) {
        providerRedacted.token = "***REDACTED***";
      }

      (redacted.providers as Record<string, unknown>)[provider] = providerRedacted;
    }

    return redacted;
  }
}

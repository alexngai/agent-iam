/**
 * Configuration management with JSON file storage
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import type { BrokerConfig, ProvidersConfig, GitHubProviderConfig } from "./types.js";
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

      const providerRedacted: Record<string, unknown> = { ...providerConfig };

      // Redact sensitive fields
      if ("apiKey" in providerRedacted) {
        providerRedacted.apiKey = "***REDACTED***";
      }
      if ("privateKeyPath" in providerRedacted) {
        providerRedacted.privateKeyPath = providerRedacted.privateKeyPath;
        providerRedacted.privateKeyExists = fs.existsSync(
          providerRedacted.privateKeyPath as string
        );
      }

      (redacted.providers as Record<string, unknown>)[provider] = providerRedacted;
    }

    return redacted;
  }
}

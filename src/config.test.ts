/**
 * Tests for config service
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ConfigService } from "./config.js";

// Create a unique temp directory for each test
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-test-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("ConfigService", () => {
  let tempDir: string;
  let configService: ConfigService;

  beforeEach(() => {
    tempDir = createTempDir();
    configService = new ConfigService(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  describe("ensureConfigDir", () => {
    test("creates config directory if not exists", () => {
      const newDir = path.join(tempDir, "subdir", "config");
      const service = new ConfigService(newDir);

      assert.strictEqual(fs.existsSync(newDir), false);
      service.ensureConfigDir();
      assert.strictEqual(fs.existsSync(newDir), true);
    });

    test("does not fail if directory already exists", () => {
      configService.ensureConfigDir();
      configService.ensureConfigDir(); // Should not throw
      assert.strictEqual(fs.existsSync(tempDir), true);
    });
  });

  describe("getOrCreateSecret", () => {
    test("creates new secret if not exists", () => {
      const secret = configService.getOrCreateSecret();

      assert.strictEqual(secret.length, 32);
      assert.ok(fs.existsSync(path.join(tempDir, "token_secret")));
    });

    test("returns same secret on subsequent calls", () => {
      const secret1 = configService.getOrCreateSecret();
      const secret2 = configService.getOrCreateSecret();

      assert.deepStrictEqual(secret1, secret2);
    });

    test("secret file has restricted permissions", () => {
      configService.getOrCreateSecret();
      const stats = fs.statSync(path.join(tempDir, "token_secret"));
      const mode = stats.mode & 0o777;

      // Should be 600 (owner read/write only)
      assert.strictEqual(mode, 0o600);
    });
  });

  describe("loadConfig / saveConfig", () => {
    test("returns empty config if file not exists", () => {
      const config = configService.loadConfig();

      assert.deepStrictEqual(config, { providers: {} });
    });

    test("saves and loads config", () => {
      const config = {
        providers: {
          github: {
            appId: "123",
            installationId: "456",
            privateKeyPath: "/path/to/key.pem",
          },
        },
      };

      configService.saveConfig(config);
      const loaded = configService.loadConfig();

      assert.deepStrictEqual(loaded, config);
    });

    test("config file has restricted permissions", () => {
      configService.saveConfig({ providers: {} });
      const stats = fs.statSync(path.join(tempDir, "config.json"));
      const mode = stats.mode & 0o777;

      assert.strictEqual(mode, 0o600);
    });
  });

  describe("getProviderConfig / setProviderConfig", () => {
    test("returns undefined for unconfigured provider", () => {
      const config = configService.getProviderConfig("github");

      assert.strictEqual(config, undefined);
    });

    test("sets and gets provider config", () => {
      const githubConfig = {
        appId: "123",
        installationId: "456",
        privateKeyPath: "/path/to/key.pem",
      };

      configService.setProviderConfig("github", githubConfig);
      const loaded = configService.getProviderConfig("github");

      assert.deepStrictEqual(loaded, githubConfig);
    });

    test("preserves other providers when setting one", () => {
      configService.setProviderConfig("github", { appId: "1" });
      configService.setProviderConfig("aws", { region: "us-east-1" });

      const github = configService.getProviderConfig("github");
      const aws = configService.getProviderConfig("aws");

      assert.deepStrictEqual(github, { appId: "1" });
      assert.deepStrictEqual(aws, { region: "us-east-1" });
    });
  });

  describe("listProviders", () => {
    test("returns empty array when no providers", () => {
      const providers = configService.listProviders();

      assert.deepStrictEqual(providers, []);
    });

    test("returns configured providers", () => {
      configService.setProviderConfig("github", { appId: "1" });
      configService.setProviderConfig("aws", { region: "us-east-1" });

      const providers = configService.listProviders();

      assert.deepStrictEqual(providers.sort(), ["aws", "github"]);
    });
  });

  describe("initGitHub", () => {
    test("initializes GitHub provider with valid key path", () => {
      // Create a fake private key file
      const keyPath = path.join(tempDir, "test-key.pem");
      fs.writeFileSync(keyPath, "fake-private-key");

      configService.initGitHub({
        appId: "123",
        installationId: "456",
        privateKeyPath: keyPath,
      });

      const config = configService.getProviderConfig("github") as {
        appId: string;
        installationId: string;
        privateKeyPath: string;
      };

      assert.strictEqual(config.appId, "123");
      assert.strictEqual(config.installationId, "456");
      assert.strictEqual(config.privateKeyPath, keyPath);
    });

    test("throws if private key file not found", () => {
      assert.throws(
        () => {
          configService.initGitHub({
            appId: "123",
            installationId: "456",
            privateKeyPath: "/nonexistent/key.pem",
          });
        },
        { message: /Private key not found/ }
      );
    });

    test("resolves relative key path to config directory", () => {
      // Create a key file in the config directory
      const keyPath = path.join(tempDir, "github-app.pem");
      fs.writeFileSync(keyPath, "fake-private-key");

      configService.initGitHub({
        appId: "123",
        installationId: "456",
        privateKeyPath: "github-app.pem", // Relative path
      });

      const config = configService.getProviderConfig("github") as {
        privateKeyPath: string;
      };

      // Should be resolved to absolute path
      assert.strictEqual(config.privateKeyPath, keyPath);
    });
  });

  describe("showConfig", () => {
    test("returns empty config when no providers", () => {
      const shown = configService.showConfig();

      assert.deepStrictEqual(shown, { providers: {} });
    });

    test("redacts API keys", () => {
      configService.setProviderConfig("generic", { apiKey: "secret-key-123" });

      const shown = configService.showConfig();

      assert.strictEqual(
        (shown.providers as Record<string, { apiKey: string }>).generic.apiKey,
        "***REDACTED***"
      );
    });

    test("shows private key existence for GitHub", () => {
      // Create a fake key file
      const keyPath = path.join(tempDir, "test-key.pem");
      fs.writeFileSync(keyPath, "fake-key");

      configService.initGitHub({
        appId: "123",
        installationId: "456",
        privateKeyPath: keyPath,
      });

      const shown = configService.showConfig();
      const github = (shown.providers as Record<string, { privateKeyExists: boolean }>).github;

      assert.strictEqual(github.privateKeyExists, true);
    });

    test("shows false for missing private key", () => {
      // Manually set a config with nonexistent key
      configService.setProviderConfig("github", {
        appId: "123",
        installationId: "456",
        privateKeyPath: "/nonexistent/key.pem",
      });

      const shown = configService.showConfig();
      const github = (shown.providers as Record<string, { privateKeyExists: boolean }>).github;

      assert.strictEqual(github.privateKeyExists, false);
    });
  });

  describe("getConfigDir", () => {
    test("returns the config directory path", () => {
      assert.strictEqual(configService.getConfigDir(), tempDir);
    });
  });
});

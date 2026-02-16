/**
 * Tests for Provider adapters
 */

import { test, describe, beforeEach, afterEach } from "node:test";
import * as assert from "node:assert";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { Broker } from "./broker.js";
import { APIKeyProvider, APIKeyProviderFactory } from "./providers/apikey.js";
import { SlackProvider } from "./providers/slack.js";

// Create a unique temp directory for each test
function createTempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "agent-iam-provider-test-"));
}

function cleanupTempDir(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

describe("APIKeyProvider", () => {
  let provider: APIKeyProvider;

  beforeEach(() => {
    provider = new APIKeyProvider();
  });

  describe("Key Management", () => {
    test("adds and lists keys", () => {
      provider.addKey(
        "test-key",
        {
          apiKey: "sk-test-12345",
          providerName: "openai",
        },
        ["openai:chat:*"]
      );

      const keys = provider.listKeys();
      assert.strictEqual(keys.length, 1);
      assert.strictEqual(keys[0].name, "test-key");
      assert.strictEqual(keys[0].provider, "openai");
      assert.deepStrictEqual(keys[0].scopes, ["openai:chat:*"]);
    });

    test("removes keys", () => {
      provider.addKey(
        "test-key",
        {
          apiKey: "sk-test-12345",
          providerName: "openai",
        },
        ["openai:*"]
      );

      const removed = provider.removeKey("test-key");
      assert.strictEqual(removed, true);
      assert.strictEqual(provider.listKeys().length, 0);
    });

    test("remove returns false for non-existent key", () => {
      const removed = provider.removeKey("non-existent");
      assert.strictEqual(removed, false);
    });

    test("rotates key", () => {
      provider.addKey(
        "test-key",
        {
          apiKey: "old-key",
          providerName: "openai",
        },
        ["openai:*"]
      );

      provider.rotateKey("test-key", "new-key");

      // Verify the key was rotated (we can't directly check the value,
      // but we can verify no error was thrown)
      assert.ok(true);
    });

    test("rotate throws for non-existent key", () => {
      assert.throws(
        () => {
          provider.rotateKey("non-existent", "new-key");
        },
        { message: /not found/ }
      );
    });
  });

  describe("Credential Issuance", () => {
    test("issues credential for matching scope", async () => {
      provider.addKey(
        "openai-prod",
        {
          apiKey: "sk-test-12345",
          providerName: "openai",
          baseUrl: "https://api.openai.com/v1",
          ttlMinutes: 30,
        },
        ["openai:chat:*", "openai:embeddings:*"]
      );

      const cred = await provider.issueCredential("openai:chat:completions", "");

      assert.strictEqual(cred.credentialType, "api_key");
      assert.strictEqual(cred.credential.apiKey, "sk-test-12345");
      assert.strictEqual(cred.credential.providerName, "openai");
      assert.strictEqual(cred.credential.baseUrl, "https://api.openai.com/v1");
      assert.ok(cred.expiresAt);
    });

    test("throws for non-matching scope", async () => {
      provider.addKey(
        "openai-prod",
        {
          apiKey: "sk-test-12345",
          providerName: "openai",
        },
        ["openai:chat:*"]
      );

      await assert.rejects(
        async () => {
          await provider.issueCredential("anthropic:messages:create", "");
        },
        { message: /No API key configured/ }
      );
    });

    test("matches wildcard scopes", async () => {
      provider.addKey(
        "all-access",
        {
          apiKey: "master-key",
          providerName: "multi",
        },
        ["*"]
      );

      const cred = await provider.issueCredential("anything:here", "");
      assert.strictEqual(cred.credential.apiKey, "master-key");
    });

    test("matches prefix wildcard scopes", async () => {
      provider.addKey(
        "openai-all",
        {
          apiKey: "sk-openai",
          providerName: "openai",
        },
        ["openai:*"]
      );

      const cred = await provider.issueCredential("openai:images:generate", "");
      assert.strictEqual(cred.credential.apiKey, "sk-openai");
    });
  });

  describe("Verification", () => {
    test("verify returns valid for proper key", async () => {
      provider.addKey(
        "test-key",
        {
          apiKey: "sk-long-enough-key-12345",
          providerName: "openai",
        },
        ["openai:*"]
      );

      const result = await provider.verify("test-key");
      assert.strictEqual(result.valid, true);
    });

    test("verify returns invalid for missing key", async () => {
      const result = await provider.verify("non-existent");
      assert.strictEqual(result.valid, false);
      assert.ok(result.error?.includes("not found"));
    });

    test("verify returns invalid for short key", async () => {
      provider.addKey(
        "bad-key",
        {
          apiKey: "short",
          providerName: "test",
        },
        ["test:*"]
      );

      const result = await provider.verify("bad-key");
      assert.strictEqual(result.valid, false);
      assert.ok(result.error?.includes("invalid"));
    });
  });
});

describe("APIKeyProviderFactory", () => {
  test("creates OpenAI config", () => {
    const config = APIKeyProviderFactory.openai("sk-test-key");

    assert.strictEqual(config.apiKey, "sk-test-key");
    assert.strictEqual(config.providerName, "openai");
    assert.strictEqual(config.baseUrl, "https://api.openai.com/v1");
  });

  test("creates OpenAI config with org ID", () => {
    const config = APIKeyProviderFactory.openai("sk-test-key", "org-123");

    assert.strictEqual(config.additionalHeaders?.["OpenAI-Organization"], "org-123");
  });

  test("creates Anthropic config", () => {
    const config = APIKeyProviderFactory.anthropic("sk-ant-test");

    assert.strictEqual(config.apiKey, "sk-ant-test");
    assert.strictEqual(config.providerName, "anthropic");
    assert.strictEqual(config.baseUrl, "https://api.anthropic.com/v1");
    assert.ok(config.additionalHeaders?.["anthropic-version"]);
  });

  test("creates Stripe config", () => {
    const config = APIKeyProviderFactory.stripe("sk_test_123");

    assert.strictEqual(config.providerName, "stripe");
    assert.strictEqual(config.baseUrl, "https://api.stripe.com/v1");
  });

  test("creates SendGrid config", () => {
    const config = APIKeyProviderFactory.sendgrid("SG.test-key");

    assert.strictEqual(config.providerName, "sendgrid");
    assert.strictEqual(config.baseUrl, "https://api.sendgrid.com/v3");
  });

  test("creates Twilio config with Basic auth", () => {
    const config = APIKeyProviderFactory.twilio("AC123", "auth-token");

    assert.strictEqual(config.providerName, "twilio");
    assert.ok(config.additionalHeaders?.Authorization?.startsWith("Basic "));
  });

  test("creates generic config", () => {
    const config = APIKeyProviderFactory.generic("myservice", "api-key", "https://api.example.com");

    assert.strictEqual(config.providerName, "myservice");
    assert.strictEqual(config.apiKey, "api-key");
    assert.strictEqual(config.baseUrl, "https://api.example.com");
  });
});

describe("Broker - API Key Integration", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("adds API key via broker", () => {
    broker.addAPIKey({
      name: "openai-test",
      providerName: "openai",
      apiKey: "sk-test-12345",
      baseUrl: "https://api.openai.com/v1",
    });

    const keys = broker.listAPIKeys();
    assert.ok(keys.includes("openai-test"));
  });

  test("removes API key via broker", () => {
    broker.addAPIKey({
      name: "to-remove",
      providerName: "test",
      apiKey: "test-key",
    });

    const removed = broker.removeAPIKey("to-remove");
    assert.strictEqual(removed, true);
    assert.ok(!broker.listAPIKeys().includes("to-remove"));
  });

  test("API keys persist across broker instances", () => {
    broker.addAPIKey({
      name: "persistent-key",
      providerName: "openai",
      apiKey: "sk-persistent",
    });

    // Create new broker instance with same config dir
    const broker2 = new Broker(tempDir);
    const keys = broker2.listAPIKeys();

    assert.ok(keys.includes("persistent-key"));
  });

  test("shows config with redacted API keys", () => {
    broker.addAPIKey({
      name: "secret-key",
      providerName: "openai",
      apiKey: "sk-super-secret",
    });

    const config = broker.showConfig();
    const providers = config.providers as Record<string, unknown>;
    const apikeys = providers.apikeys as Record<string, { apiKey: string }>;

    assert.strictEqual(apikeys["secret-key"].apiKey, "***REDACTED***");
  });
});

describe("Broker - Provider Initialization", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("initializes Google provider", () => {
    broker.initProvider("google", {
      clientId: "client-id-123",
      clientSecret: "client-secret",
      refreshToken: "refresh-token",
    });

    const status = broker.getStatus();
    assert.ok(status.providers.includes("google"));
  });

  test("initializes AWS provider", () => {
    broker.initProvider("aws", {
      region: "us-east-1",
      roleArn: "arn:aws:iam::123456789012:role/test-role",
    });

    const status = broker.getStatus();
    assert.ok(status.providers.includes("aws"));
  });

  test("shows Google config with redacted secrets", () => {
    broker.initProvider("google", {
      clientId: "client-id-123",
      clientSecret: "super-secret",
      refreshToken: "refresh-secret",
    });

    const config = broker.showConfig();
    const providers = config.providers as Record<string, Record<string, string>>;

    assert.strictEqual(providers.google.clientId, "client-id-123");
    assert.strictEqual(providers.google.clientSecret, "***REDACTED***");
    assert.strictEqual(providers.google.refreshToken, "***REDACTED***");
  });

  test("shows AWS config with redacted secrets", () => {
    broker.initProvider("aws", {
      region: "us-west-2",
      roleArn: "arn:aws:iam::123456789012:role/test",
      accessKeyId: "AKIAEXAMPLE",
      secretAccessKey: "secret123",
    });

    const config = broker.showConfig();
    const providers = config.providers as Record<string, Record<string, string>>;

    assert.strictEqual(providers.aws.region, "us-west-2");
    assert.strictEqual(providers.aws.accessKeyId, "AKIAEXAMPLE");
    assert.strictEqual(providers.aws.secretAccessKey, "***REDACTED***");
  });

  test("throws for unknown provider", () => {
    assert.throws(
      () => {
        broker.initProvider("unknown", {});
      },
      { message: /not supported/ }
    );
  });
});

describe("Broker - Credential Retrieval with API Keys", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);

    // Add an API key for testing
    broker.addAPIKey({
      name: "openai",
      providerName: "openai",
      apiKey: "sk-test-credential-key",
      baseUrl: "https://api.openai.com/v1",
      ttlMinutes: 60,
    });
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("gets credential for API key provider", async () => {
    const token = broker.createRootToken({
      agentId: "test",
      scopes: ["openai:chat:completions"],
      ttlDays: 1,
    });

    const cred = await broker.getCredential(token, "openai:chat:completions", "");

    assert.strictEqual(cred.credentialType, "api_key");
    assert.strictEqual(cred.credential.apiKey, "sk-test-credential-key");
    assert.strictEqual(cred.credential.providerName, "openai");
  });

  test("throws for unauthorized scope", async () => {
    const token = broker.createRootToken({
      agentId: "test",
      scopes: ["openai:chat:completions"],
      ttlDays: 1,
    });

    await assert.rejects(
      async () => {
        await broker.getCredential(token, "anthropic:messages:create", "");
      },
      { message: /Permission denied/ }
    );
  });

  test("throws for unconfigured provider", async () => {
    const token = broker.createRootToken({
      agentId: "test",
      scopes: ["stripe:charges:create"],
      ttlDays: 1,
    });

    await assert.rejects(
      async () => {
        await broker.getCredential(token, "stripe:charges:create", "");
      },
      { message: /not supported/ }
    );
  });
});

// ─────────────────────────────────────────────────────────────────
// SLACK PROVIDER TESTS
// ─────────────────────────────────────────────────────────────────

describe("SlackProvider", () => {
  describe("Bot Mode - Credential Issuance", () => {
    test("issues bot token credential", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-bot-token-12345",
        teamId: "T12345",
      });

      const cred = await provider.issueCredential("slack:chat:write", "#general");

      assert.strictEqual(cred.credentialType, "bearer_token");
      assert.strictEqual(cred.credential.token, "xoxb-test-bot-token-12345");
      assert.strictEqual(cred.credential.tokenType, "bearer");
      assert.strictEqual(cred.credential.mode, "bot");
      assert.strictEqual(cred.credential.teamId, "T12345");
      assert.ok(cred.expiresAt);
      assert.ok(Array.isArray(cred.credential.scopes));
      assert.ok((cred.credential.scopes as string[]).includes("chat:write"));
    });

    test("maps chat:read scope to history scopes", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });

      const cred = await provider.issueCredential("slack:chat:read", "");

      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("channels:history"));
      assert.ok(scopes.includes("groups:history"));
      assert.ok(scopes.includes("im:history"));
    });

    test("maps channels:read scope correctly", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });

      const cred = await provider.issueCredential("slack:channels:read", "");

      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("channels:read"));
      assert.ok(scopes.includes("groups:read"));
    });

    test("maps wildcard chat scope", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });

      const cred = await provider.issueCredential("slack:chat:*", "");

      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("chat:write"));
      assert.ok(scopes.includes("channels:history"));
    });

    test("maps wildcard slack scope", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });

      const cred = await provider.issueCredential("slack:*", "");

      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("chat:write"));
      assert.ok(scopes.includes("channels:read"));
      assert.ok(scopes.includes("users:read"));
    });

    test("returns empty scopes for unknown scope", async () => {
      const provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });

      const cred = await provider.issueCredential("slack:unknown:scope", "");

      const scopes = cred.credential.scopes as string[];
      assert.strictEqual(scopes.length, 0);
    });
  });

  describe("User Mode - Credential Issuance", () => {
    test("issues user token credential (no refresh)", async () => {
      const provider = new SlackProvider({
        mode: "user",
        token: "xoxp-test-user-token-12345",
        teamId: "T12345",
      });

      const cred = await provider.issueCredential("slack:chat:write", "#general");

      assert.strictEqual(cred.credentialType, "bearer_token");
      assert.strictEqual(cred.credential.token, "xoxp-test-user-token-12345");
      assert.strictEqual(cred.credential.mode, "user");
      assert.strictEqual(cred.credential.teamId, "T12345");
      assert.ok(cred.expiresAt);
    });
  });

  describe("Scope Mapping", () => {
    let provider: SlackProvider;

    beforeEach(() => {
      provider = new SlackProvider({
        mode: "bot",
        token: "xoxb-test-token",
      });
    });

    test("maps files scopes", async () => {
      const readCred = await provider.issueCredential("slack:files:read", "");
      assert.ok((readCred.credential.scopes as string[]).includes("files:read"));

      const writeCred = await provider.issueCredential("slack:files:write", "");
      assert.ok((writeCred.credential.scopes as string[]).includes("files:write"));
    });

    test("maps reactions scopes", async () => {
      const readCred = await provider.issueCredential("slack:reactions:read", "");
      assert.ok((readCred.credential.scopes as string[]).includes("reactions:read"));

      const writeCred = await provider.issueCredential("slack:reactions:write", "");
      assert.ok((writeCred.credential.scopes as string[]).includes("reactions:write"));
    });

    test("maps users scopes", async () => {
      const cred = await provider.issueCredential("slack:users:read", "");
      assert.ok((cred.credential.scopes as string[]).includes("users:read"));
    });

    test("maps im scopes", async () => {
      const readCred = await provider.issueCredential("slack:im:read", "");
      assert.ok((readCred.credential.scopes as string[]).includes("im:read"));

      const writeCred = await provider.issueCredential("slack:im:write", "");
      assert.ok((writeCred.credential.scopes as string[]).includes("im:write"));
    });

    test("maps wildcard files scope", async () => {
      const cred = await provider.issueCredential("slack:files:*", "");
      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("files:read"));
      assert.ok(scopes.includes("files:write"));
    });

    test("maps wildcard reactions scope", async () => {
      const cred = await provider.issueCredential("slack:reactions:*", "");
      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("reactions:read"));
      assert.ok(scopes.includes("reactions:write"));
    });

    test("maps wildcard channels scope", async () => {
      const cred = await provider.issueCredential("slack:channels:*", "");
      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("channels:read"));
      assert.ok(scopes.includes("channels:manage"));
      assert.ok(scopes.includes("channels:join"));
    });

    test("maps wildcard im scope", async () => {
      const cred = await provider.issueCredential("slack:im:*", "");
      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("im:read"));
      assert.ok(scopes.includes("im:write"));
    });

    test("maps wildcard users scope", async () => {
      const cred = await provider.issueCredential("slack:users:*", "");
      const scopes = cred.credential.scopes as string[];
      assert.ok(scopes.includes("users:read"));
      assert.ok(scopes.includes("users:read.email"));
    });

    test("maps pins scopes", async () => {
      const readCred = await provider.issueCredential("slack:pins:read", "");
      assert.ok((readCred.credential.scopes as string[]).includes("pins:read"));

      const writeCred = await provider.issueCredential("slack:pins:write", "");
      assert.ok((writeCred.credential.scopes as string[]).includes("pins:write"));
    });
  });
});

describe("Broker - Slack Provider Initialization", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("initializes Slack bot provider", () => {
    broker.initProvider("slack", {
      mode: "bot",
      token: "xoxb-test-bot-token",
      teamId: "T12345",
    });

    const status = broker.getStatus();
    assert.ok(status.providers.includes("slack"));
  });

  test("initializes Slack user provider", () => {
    broker.initProvider("slack", {
      mode: "user",
      token: "xoxp-test-user-token",
      clientId: "client-id-123",
      clientSecret: "client-secret-456",
      refreshToken: "xoxe-1-refresh-token",
      teamId: "T12345",
    });

    const status = broker.getStatus();
    assert.ok(status.providers.includes("slack"));
  });

  test("shows Slack config with redacted secrets", () => {
    broker.initProvider("slack", {
      mode: "bot",
      token: "xoxb-super-secret-token",
      teamId: "T12345",
    });

    const config = broker.showConfig();
    const providers = config.providers as Record<string, Record<string, string>>;

    assert.strictEqual(providers.slack.mode, "bot");
    assert.strictEqual(providers.slack.token, "***REDACTED***");
    assert.strictEqual(providers.slack.teamId, "T12345");
  });

  test("shows Slack user config with all secrets redacted", () => {
    broker.initProvider("slack", {
      mode: "user",
      token: "xoxp-secret-user-token",
      clientId: "client-id",
      clientSecret: "secret-client-secret",
      refreshToken: "secret-refresh-token",
    });

    const config = broker.showConfig();
    const providers = config.providers as Record<string, Record<string, string>>;

    assert.strictEqual(providers.slack.mode, "user");
    assert.strictEqual(providers.slack.token, "***REDACTED***");
    assert.strictEqual(providers.slack.clientSecret, "***REDACTED***");
    assert.strictEqual(providers.slack.refreshToken, "***REDACTED***");
    assert.strictEqual(providers.slack.clientId, "client-id");
  });

  test("Slack config persists across broker instances", () => {
    broker.initProvider("slack", {
      mode: "bot",
      token: "xoxb-persistent-token",
      teamId: "T99999",
    });

    const broker2 = new Broker(tempDir);
    const status = broker2.getStatus();
    assert.ok(status.providers.includes("slack"));
  });
});

describe("Broker - Slack Credential Retrieval", () => {
  let tempDir: string;
  let broker: Broker;

  beforeEach(() => {
    tempDir = createTempDir();
    broker = new Broker(tempDir);

    // Configure Slack bot provider
    broker.initProvider("slack", {
      mode: "bot",
      token: "xoxb-test-credential-token",
      teamId: "T12345",
    });
  });

  afterEach(() => {
    cleanupTempDir(tempDir);
  });

  test("gets Slack credential with valid token", async () => {
    const token = broker.createRootToken({
      agentId: "slack-bot",
      scopes: ["slack:chat:write"],
      ttlDays: 1,
    });

    const cred = await broker.getCredential(token, "slack:chat:write", "#general");

    assert.strictEqual(cred.credentialType, "bearer_token");
    assert.strictEqual(cred.credential.token, "xoxb-test-credential-token");
    assert.strictEqual(cred.credential.mode, "bot");
  });

  test("denies Slack credential for unauthorized scope", async () => {
    const token = broker.createRootToken({
      agentId: "slack-bot",
      scopes: ["slack:chat:write"],
      ttlDays: 1,
    });

    await assert.rejects(
      async () => {
        await broker.getCredential(token, "slack:files:write", "");
      },
      { message: /Permission denied/ }
    );
  });

  test("throws when Slack provider not configured", async () => {
    // Use a fresh broker without Slack configured
    const freshDir = createTempDir();
    const freshBroker = new Broker(freshDir);

    const token = freshBroker.createRootToken({
      agentId: "test",
      scopes: ["slack:chat:write"],
      ttlDays: 1,
    });

    await assert.rejects(
      async () => {
        await freshBroker.getCredential(token, "slack:chat:write", "");
      },
      { message: /Slack provider not configured/ }
    );

    cleanupTempDir(freshDir);
  });

  test("Slack credentials work with delegation", async () => {
    const root = broker.createRootToken({
      agentId: "orchestrator",
      scopes: ["slack:chat:write", "slack:channels:read", "slack:files:write"],
      ttlDays: 1,
    });

    // Delegate only chat:write to child
    const child = broker.delegate(root, {
      agentId: "chat-agent",
      requestedScopes: ["slack:chat:write"],
      ttlMinutes: 60,
    });

    // Child should get chat credential
    const cred = await broker.getCredential(child, "slack:chat:write", "#general");
    assert.strictEqual(cred.credentialType, "bearer_token");
    assert.strictEqual(cred.credential.token, "xoxb-test-credential-token");

    // Child should not get files credential
    await assert.rejects(
      async () => {
        await broker.getCredential(child, "slack:files:write", "");
      },
      { message: /Permission denied/ }
    );
  });

  test("Slack credentials work with resource constraints", async () => {
    const root = broker.createRootToken({
      agentId: "orchestrator",
      scopes: ["slack:chat:write"],
      constraints: {
        "slack:chat:write": { resources: ["#engineering-*"] },
      },
      ttlDays: 1,
    });

    // Should work for matching channel
    const result = broker.checkPermission(root, "slack:chat:write", "#engineering-backend");
    assert.strictEqual(result.valid, true);

    // Should fail for non-matching channel
    const denied = broker.checkPermission(root, "slack:chat:write", "#random");
    assert.strictEqual(denied.valid, false);
  });
});

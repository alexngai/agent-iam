#!/usr/bin/env node
/**
 * CLI interface for the Agent Credential Broker
 */

import { Command } from "commander";
import { Broker } from "./broker.js";
import type { Constraints } from "./types.js";

const program = new Command();

program
  .name("agent-iam")
  .description("Agent credential broker for AI agents")
  .version("0.0.1");

// ─────────────────────────────────────────────────────────────────
// CONFIG COMMANDS
// ─────────────────────────────────────────────────────────────────

const configCmd = program.command("config").description("Manage configuration");

configCmd
  .command("show")
  .description("Show current configuration (with secrets redacted)")
  .action(() => {
    const broker = new Broker();
    const config = broker.showConfig();
    console.log(JSON.stringify(config, null, 2));
  });

configCmd
  .command("init <provider>")
  .description("Initialize a provider (github, google, aws)")
  .option("--app-id <appId>", "GitHub App ID")
  .option("--installation-id <installationId>", "GitHub Installation ID")
  .option("--private-key <path>", "Path to private key file")
  .option("--client-id <clientId>", "Google OAuth Client ID")
  .option("--client-secret <clientSecret>", "Google OAuth Client Secret")
  .option("--refresh-token <refreshToken>", "Google OAuth Refresh Token")
  .option("--region <region>", "AWS region")
  .option("--role-arn <roleArn>", "AWS IAM Role ARN")
  .option("--external-id <externalId>", "AWS External ID for role assumption")
  .option("--session-duration <seconds>", "AWS session duration in seconds")
  .option("--access-key-id <accessKeyId>", "AWS Access Key ID")
  .option("--secret-access-key <secretAccessKey>", "AWS Secret Access Key")
  .action((provider, options) => {
    const broker = new Broker();

    try {
      if (provider === "github") {
        if (!options.appId || !options.installationId || !options.privateKey) {
          console.error(
            "GitHub provider requires --app-id, --installation-id, and --private-key"
          );
          process.exit(1);
        }
        broker.initProvider("github", {
          appId: options.appId,
          installationId: options.installationId,
          privateKeyPath: options.privateKey,
        });
        console.log("GitHub provider configured successfully");
      } else if (provider === "google") {
        if (!options.clientId || !options.clientSecret || !options.refreshToken) {
          console.error(
            "Google provider requires --client-id, --client-secret, and --refresh-token"
          );
          process.exit(1);
        }
        broker.initProvider("google", {
          clientId: options.clientId,
          clientSecret: options.clientSecret,
          refreshToken: options.refreshToken,
        });
        console.log("Google provider configured successfully");
      } else if (provider === "aws") {
        if (!options.region || !options.roleArn) {
          console.error("AWS provider requires --region and --role-arn");
          process.exit(1);
        }
        broker.initProvider("aws", {
          region: options.region,
          roleArn: options.roleArn,
          externalId: options.externalId,
          sessionDuration: options.sessionDuration,
          accessKeyId: options.accessKeyId,
          secretAccessKey: options.secretAccessKey,
        });
        console.log("AWS provider configured successfully");
      } else {
        console.error(
          `Unknown provider: ${provider}. Use "github", "google", or "aws".`
        );
        console.error('For API keys, use "agent-iam apikey add"');
        process.exit(1);
      }
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────
// API KEY COMMANDS
// ─────────────────────────────────────────────────────────────────

const apikeyCmd = program.command("apikey").description("Manage API keys");

apikeyCmd
  .command("add")
  .description("Add an API key")
  .requiredOption("--name <name>", "Unique name for this API key")
  .requiredOption("--provider <provider>", "Provider name (e.g., openai, anthropic, stripe)")
  .requiredOption("--key <apiKey>", "The API key")
  .option("--base-url <url>", "Base URL for the API")
  .option("--ttl <minutes>", "TTL in minutes for issued credentials", "60")
  .action((options) => {
    const broker = new Broker();

    try {
      broker.addAPIKey({
        name: options.name,
        providerName: options.provider,
        apiKey: options.key,
        baseUrl: options.baseUrl,
        ttlMinutes: parseInt(options.ttl, 10),
      });
      console.log(`API key "${options.name}" added successfully`);
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

apikeyCmd
  .command("remove <name>")
  .description("Remove an API key")
  .action((name) => {
    const broker = new Broker();

    try {
      const removed = broker.removeAPIKey(name);
      if (removed) {
        console.log(`API key "${name}" removed successfully`);
      } else {
        console.error(`API key "${name}" not found`);
        process.exit(1);
      }
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

apikeyCmd
  .command("list")
  .description("List configured API keys")
  .action(() => {
    const broker = new Broker();
    const keys = broker.listAPIKeys();

    if (keys.length === 0) {
      console.log("No API keys configured");
    } else {
      console.log("Configured API keys:");
      for (const key of keys) {
        console.log(`  - ${key}`);
      }
    }
  });

// ─────────────────────────────────────────────────────────────────
// TOKEN COMMANDS
// ─────────────────────────────────────────────────────────────────

const tokenCmd = program.command("token").description("Manage tokens");

tokenCmd
  .command("create-root")
  .description("Create a root token")
  .requiredOption("--agent-id <id>", "Agent ID")
  .requiredOption("--scopes <scopes>", "Comma-separated list of scopes")
  .option("--constraints <json>", "JSON constraints object")
  .option("--ttl-days <days>", "Token TTL in days", "7")
  .option("--max-depth <depth>", "Maximum delegation depth", "3")
  .option("--no-delegatable", "Disable delegation")
  .action((options) => {
    const broker = new Broker();

    try {
      const scopes = options.scopes.split(",").map((s: string) => s.trim());
      const constraints: Constraints = options.constraints
        ? JSON.parse(options.constraints)
        : {};

      const token = broker.createRootToken({
        agentId: options.agentId,
        scopes,
        constraints,
        delegatable: options.delegatable,
        maxDelegationDepth: parseInt(options.maxDepth, 10),
        ttlDays: parseInt(options.ttlDays, 10),
      });

      const serialized = broker.serializeToken(token);
      console.log(serialized);
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

tokenCmd
  .command("delegate")
  .description("Delegate a token to create a child token")
  .requiredOption("--parent <token>", "Parent token (serialized)")
  .requiredOption("--scopes <scopes>", "Comma-separated list of scopes")
  .option("--agent-id <id>", "Agent ID for child")
  .option("--constraints <json>", "JSON constraints object")
  .option("--ttl-minutes <minutes>", "Token TTL in minutes", "60")
  .option("--no-delegatable", "Disable further delegation")
  .action((options) => {
    const broker = new Broker();

    try {
      const parent = broker.deserializeToken(options.parent);
      const scopes = options.scopes.split(",").map((s: string) => s.trim());
      const constraints: Constraints = options.constraints
        ? JSON.parse(options.constraints)
        : {};

      const child = broker.delegate(parent, {
        agentId: options.agentId,
        requestedScopes: scopes,
        requestedConstraints: constraints,
        delegatable: options.delegatable,
        ttlMinutes: parseInt(options.ttlMinutes, 10),
      });

      const serialized = broker.serializeToken(child);
      console.log(serialized);
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

tokenCmd
  .command("show <token>")
  .description("Decode and display a token")
  .action((tokenStr) => {
    const broker = new Broker();

    try {
      const token = broker.deserializeToken(tokenStr);
      console.log(JSON.stringify(token, null, 2));
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

tokenCmd
  .command("verify <token>")
  .description("Verify a token")
  .action((tokenStr) => {
    const broker = new Broker();

    try {
      const token = broker.deserializeToken(tokenStr);
      const result = broker.verifyToken(token);

      if (result.valid) {
        console.log("Token is valid");
        process.exit(0);
      } else {
        console.error(`Token is invalid: ${result.error}`);
        process.exit(1);
      }
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────
// CREDENTIAL COMMANDS
// ─────────────────────────────────────────────────────────────────

program
  .command("cred <scope> <resource>")
  .description("Get a provider credential")
  .requiredOption("--token <token>", "Agent token (serialized)")
  .option("--format <format>", "Output format (json, token)", "json")
  .action(async (scope, resource, options) => {
    const broker = new Broker();

    try {
      const token = broker.deserializeToken(options.token);
      const credential = await broker.getCredential(token, scope, resource);

      if (options.format === "token") {
        // Just output the token value for easy piping
        const cred = credential.credential as { token?: string };
        if (cred.token) {
          console.log(cred.token);
        } else {
          console.log(JSON.stringify(credential.credential));
        }
      } else {
        console.log(JSON.stringify(credential, null, 2));
      }
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

// ─────────────────────────────────────────────────────────────────
// STATUS COMMAND
// ─────────────────────────────────────────────────────────────────

program
  .command("status")
  .description("Show broker status")
  .action(() => {
    const broker = new Broker();
    const status = broker.getStatus();
    console.log(JSON.stringify(status, null, 2));
  });

// ─────────────────────────────────────────────────────────────────
// DISTRIBUTED MODE COMMANDS
// ─────────────────────────────────────────────────────────────────

import { LeaderServer, FollowerClient, BrokerMode } from "./distributed/index.js";

program
  .command("serve")
  .description("Start the leader HTTP server for distributed mode")
  .option("--port <port>", "Port to listen on", "8443")
  .option("--host <host>", "Host to bind to", "0.0.0.0")
  .option("--auth-token <token>", "Authentication token for followers")
  .option("--tls-cert <path>", "Path to TLS certificate")
  .option("--tls-key <path>", "Path to TLS private key")
  .action(async (options) => {
    const broker = new Broker();

    if (!options.authToken) {
      console.error("Error: --auth-token is required for secure follower authentication");
      process.exit(1);
    }

    const leader = new LeaderServer(broker, broker.getConfigDir(), {
      port: parseInt(options.port, 10),
      host: options.host,
      followerAuthToken: options.authToken,
      tlsCertPath: options.tlsCert,
      tlsKeyPath: options.tlsKey,
    });

    try {
      await leader.start();
      console.log(`Leader server started on ${options.host}:${options.port}`);
      console.log("Press Ctrl+C to stop");

      // Handle shutdown
      process.on("SIGINT", async () => {
        console.log("\nShutting down...");
        await leader.stop();
        process.exit(0);
      });
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

program
  .command("rotate-key")
  .description("Rotate the signing key (leader mode)")
  .option("--auth-token <token>", "Leader authentication token")
  .option("--leader-url <url>", "Leader URL (if running remotely)")
  .action(async (options) => {
    if (options.leaderUrl) {
      // Remote rotation via HTTP
      if (!options.authToken) {
        console.error("Error: --auth-token is required for remote rotation");
        process.exit(1);
      }

      try {
        const response = await fetch(`${options.leaderUrl}/rotate-key`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${options.authToken}`,
          },
        });

        if (!response.ok) {
          const error = await response.text();
          throw new Error(`Rotation failed: ${error}`);
        }

        const result = await response.json() as { version: number };
        console.log(`Key rotated to version ${result.version}`);
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`
        );
        process.exit(1);
      }
    } else {
      // Local rotation (direct access to config)
      const broker = new Broker();
      const { SigningKeyManager } = await import("./distributed/index.js");
      const keyManager = new SigningKeyManager(broker.getConfigDir());
      const { version } = keyManager.rotate();
      console.log(`Key rotated to version ${version}`);
    }
  });

program
  .command("revoke <tokenId>")
  .description("Revoke a token")
  .option("--reason <reason>", "Reason for revocation")
  .option("--auth-token <token>", "Leader authentication token")
  .option("--leader-url <url>", "Leader URL (if running remotely)")
  .action(async (tokenId, options) => {
    if (options.leaderUrl) {
      // Remote revocation via HTTP
      if (!options.authToken) {
        console.error("Error: --auth-token is required for remote revocation");
        process.exit(1);
      }

      try {
        const response = await fetch(`${options.leaderUrl}/revoke/${tokenId}`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${options.authToken}`,
          },
          body: JSON.stringify({ reason: options.reason }),
        });

        if (!response.ok) {
          const error = await response.text();
          throw new Error(`Revocation failed: ${error}`);
        }

        console.log(`Token ${tokenId} revoked`);
      } catch (error) {
        console.error(
          `Error: ${error instanceof Error ? error.message : String(error)}`
        );
        process.exit(1);
      }
    } else {
      // Local revocation
      const broker = new Broker();
      const { RevocationList } = await import("./distributed/index.js");
      const revocationList = new RevocationList(broker.getConfigDir());
      revocationList.revoke({
        tokenId,
        agentId: tokenId,
        reason: options.reason,
      });
      console.log(`Token ${tokenId} revoked locally`);
    }
  });

program
  .command("sync")
  .description("Force sync from leader (follower mode)")
  .requiredOption("--leader-url <url>", "Leader URL")
  .requiredOption("--auth-token <token>", "Authentication token")
  .requiredOption("--follower-id <id>", "Follower identifier")
  .action(async (options) => {
    const broker = new Broker();

    const follower = new FollowerClient(broker, broker.getConfigDir(), {
      leaderUrl: options.leaderUrl,
      leaderAuthToken: options.authToken,
      followerId: options.followerId,
    });

    try {
      await follower.sync();
      const status = follower.getStatus();
      console.log("Sync completed successfully");
      console.log(JSON.stringify(status, null, 2));
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

program
  .command("follower")
  .description("Start as a follower (syncs from leader)")
  .requiredOption("--leader-url <url>", "Leader URL")
  .requiredOption("--auth-token <token>", "Authentication token")
  .requiredOption("--follower-id <id>", "Follower identifier")
  .option("--sync-interval <seconds>", "Sync interval in seconds", "60")
  .action(async (options) => {
    const broker = new Broker();

    const follower = new FollowerClient(broker, broker.getConfigDir(), {
      leaderUrl: options.leaderUrl,
      leaderAuthToken: options.authToken,
      followerId: options.followerId,
      syncIntervalSeconds: parseInt(options.syncInterval, 10),
    });

    try {
      await follower.start();
      console.log(`Follower started, syncing from ${options.leaderUrl}`);
      console.log("Press Ctrl+C to stop");

      // Handle shutdown
      process.on("SIGINT", () => {
        console.log("\nShutting down...");
        follower.stop();
        process.exit(0);
      });

      // Keep running and periodically show status
      setInterval(() => {
        const status = follower.getDetailedStatus();
        console.log(`[${new Date().toISOString()}] State: ${status.state}, Key: v${status.signingKeyVersion}, Revocations: ${status.revocationCount}`);
      }, 30000);
    } catch (error) {
      console.error(
        `Error: ${error instanceof Error ? error.message : String(error)}`
      );
      process.exit(1);
    }
  });

program.parse();

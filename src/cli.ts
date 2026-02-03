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
  .description("Initialize a provider")
  .option("--app-id <appId>", "GitHub App ID")
  .option("--installation-id <installationId>", "GitHub Installation ID")
  .option("--private-key <path>", "Path to private key file")
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
      } else {
        console.error(`Unknown provider: ${provider}`);
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

program.parse();

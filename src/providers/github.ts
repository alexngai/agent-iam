/**
 * GitHub provider adapter using GitHub App authentication
 */

import * as fs from "fs";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";
import type { GitHubProviderConfig, CredentialResult } from "../types.js";

/** GitHub permission mapping from our scopes */
const SCOPE_TO_PERMISSIONS: Record<string, Record<string, string>> = {
  "github:repo:read": { contents: "read", metadata: "read" },
  "github:repo:write": { contents: "write", metadata: "read" },
  "github:repo:admin": { administration: "write" },
  "github:issues:read": { issues: "read" },
  "github:issues:write": { issues: "write" },
  "github:actions:read": { actions: "read" },
  "github:actions:write": { actions: "write" },
  "github:pulls:read": { pull_requests: "read" },
  "github:pulls:write": { pull_requests: "write" },
};

/** Parse owner/repo from resource string */
function parseRepo(resource: string): { owner: string; repo: string } | null {
  const parts = resource.split("/");
  if (parts.length !== 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

export class GitHubProvider {
  private config: GitHubProviderConfig;
  private privateKey: string;

  constructor(config: GitHubProviderConfig) {
    this.config = config;
    this.privateKey = fs.readFileSync(config.privateKeyPath, "utf-8");
  }

  /**
   * Issue a GitHub installation access token
   *
   * @param scope - The scope requested (e.g., "github:repo:read")
   * @param resource - The repository (e.g., "owner/repo")
   */
  async issueCredential(scope: string, resource: string): Promise<CredentialResult> {
    const permissions = this.scopeToPermissions(scope);
    const repo = parseRepo(resource);

    // Create auth using GitHub App
    const auth = createAppAuth({
      appId: this.config.appId,
      privateKey: this.privateKey,
      installationId: parseInt(this.config.installationId, 10),
    });

    // Get installation token with scoped permissions
    const installationAuth = await auth({
      type: "installation",
      permissions,
      ...(repo ? { repositoryNames: [repo.repo] } : {}),
    });

    // The token expires in 1 hour by default
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    return {
      credentialType: "bearer_token",
      credential: {
        token: installationAuth.token,
        tokenType: "bearer",
      },
      expiresAt,
    };
  }

  /**
   * Convert our scope format to GitHub API permissions
   */
  private scopeToPermissions(scope: string): Record<string, string> {
    // Direct match
    if (SCOPE_TO_PERMISSIONS[scope]) {
      return SCOPE_TO_PERMISSIONS[scope];
    }

    // Handle wildcard scopes
    if (scope === "github:repo:*" || scope === "github:*") {
      return {
        contents: "write",
        metadata: "read",
        issues: "write",
        pull_requests: "write",
      };
    }

    // Default to read-only contents
    return { contents: "read", metadata: "read" };
  }

  /**
   * Verify the GitHub App is properly configured
   */
  async verify(): Promise<{ valid: boolean; error?: string }> {
    try {
      const auth = createAppAuth({
        appId: this.config.appId,
        privateKey: this.privateKey,
        installationId: parseInt(this.config.installationId, 10),
      });

      // Try to get an installation token
      await auth({ type: "installation" });
      return { valid: true };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * List repositories accessible to this installation
   */
  async listRepositories(): Promise<string[]> {
    const auth = createAppAuth({
      appId: this.config.appId,
      privateKey: this.privateKey,
      installationId: parseInt(this.config.installationId, 10),
    });

    const installationAuth = await auth({ type: "installation" });

    const octokit = new Octokit({ auth: installationAuth.token });
    const { data } = await octokit.apps.listReposAccessibleToInstallation();

    return data.repositories.map((repo) => `${repo.owner.login}/${repo.name}`);
  }
}

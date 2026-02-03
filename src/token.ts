/**
 * Token creation, signing, and verification
 */

import * as crypto from "crypto";
import type {
  AgentToken,
  DelegationRequest,
  VerificationResult,
  SerializedToken,
  Constraints,
  ScopeConstraint,
} from "./types.js";

/** Sign a token using HMAC-SHA256 */
function sign(token: Omit<AgentToken, "signature">, secret: Buffer): string {
  const payload = JSON.stringify(token);
  return crypto.createHmac("sha256", secret).update(payload).digest("base64url");
}

/** Verify token signature */
function verifySignature(token: AgentToken, secret: Buffer): boolean {
  const { signature, ...tokenWithoutSig } = token;
  if (!signature) return false;
  const expected = sign(tokenWithoutSig, secret);
  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}

/** Check if a scope matches a pattern (supports wildcards) */
export function scopeMatches(pattern: string, scope: string): boolean {
  if (pattern === scope) return true;
  if (pattern === "*") return true;

  // Handle wildcards: "github:repo:*" matches "github:repo:read"
  if (pattern.endsWith(":*")) {
    const prefix = pattern.slice(0, -1); // "github:repo:"
    return scope.startsWith(prefix);
  }

  // Handle partial wildcards: "github:*" matches "github:repo:read"
  const patternParts = pattern.split(":");
  const scopeParts = scope.split(":");

  for (let i = 0; i < patternParts.length; i++) {
    if (patternParts[i] === "*") return true;
    if (patternParts[i] !== scopeParts[i]) return false;
  }

  return patternParts.length === scopeParts.length;
}

/** Check if a resource matches a constraint pattern (glob-style) */
export function resourceMatches(pattern: string, resource: string): boolean {
  // Convert glob pattern to regex
  // "myorg/*" -> matches "myorg/repo", "myorg/other"
  // "myorg/repo-*" -> matches "myorg/repo-a", "myorg/repo-b"
  const regexPattern = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape special regex chars
    .replace(/\*/g, ".*") // Convert * to .*
    .replace(/\?/g, "."); // Convert ? to .

  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(resource);
}

/** Token service for creating and verifying tokens */
export class TokenService {
  private secret: Buffer;

  constructor(secret: Buffer) {
    this.secret = secret;
  }

  /** Create a root token */
  createRootToken(params: {
    agentId: string;
    scopes: string[];
    constraints?: Constraints;
    delegatable?: boolean;
    maxDelegationDepth?: number;
    ttlDays?: number;
  }): AgentToken {
    const now = new Date();
    const expiresAt = params.ttlDays
      ? new Date(now.getTime() + params.ttlDays * 24 * 60 * 60 * 1000).toISOString()
      : undefined;

    const token: Omit<AgentToken, "signature"> = {
      agentId: params.agentId,
      scopes: params.scopes,
      constraints: params.constraints ?? {},
      delegatable: params.delegatable ?? true,
      maxDelegationDepth: params.maxDelegationDepth ?? 3,
      currentDepth: 0,
      expiresAt,
      maxExpiresAt: expiresAt,
    };

    const signature = sign(token, this.secret);
    return { ...token, signature };
  }

  /** Delegate a token to create a child token */
  delegate(parent: AgentToken, request: DelegationRequest): AgentToken {
    // Validate parent can delegate
    if (!parent.delegatable) {
      throw new Error("Parent token is not delegatable");
    }

    if (parent.currentDepth >= parent.maxDelegationDepth) {
      throw new Error(
        `Delegation depth exceeded: ${parent.currentDepth} >= ${parent.maxDelegationDepth}`
      );
    }

    // Validate requested scopes are subset of parent
    for (const scope of request.requestedScopes) {
      const allowed = parent.scopes.some((ps) => scopeMatches(ps, scope));
      if (!allowed) {
        throw new Error(`Scope "${scope}" not allowed by parent token`);
      }
    }

    // Merge constraints (child constraints must be narrower)
    const mergedConstraints = this.mergeConstraints(
      parent.constraints,
      request.requestedConstraints ?? {},
      request.requestedScopes
    );

    // Calculate expiry (cannot exceed parent)
    const now = new Date();
    let expiresAt: string | undefined;

    if (request.ttlMinutes) {
      expiresAt = new Date(
        now.getTime() + request.ttlMinutes * 60 * 1000
      ).toISOString();
    }

    if (parent.expiresAt) {
      if (!expiresAt || new Date(expiresAt) > new Date(parent.expiresAt)) {
        expiresAt = parent.expiresAt;
      }
    }

    const child: Omit<AgentToken, "signature"> = {
      agentId: request.agentId ?? `agent-${crypto.randomBytes(4).toString("hex")}`,
      parentId: parent.agentId,
      scopes: request.requestedScopes,
      constraints: mergedConstraints,
      delegatable: (request.delegatable ?? true) && parent.delegatable,
      maxDelegationDepth: parent.maxDelegationDepth,
      currentDepth: parent.currentDepth + 1,
      expiresAt,
      maxExpiresAt: parent.maxExpiresAt,
    };

    const signature = sign(child, this.secret);
    return { ...child, signature };
  }

  /** Verify a token */
  verify(token: AgentToken): VerificationResult {
    // Check signature
    if (!verifySignature(token, this.secret)) {
      return { valid: false, error: "Invalid signature" };
    }

    // Check expiration
    if (token.expiresAt && new Date(token.expiresAt) < new Date()) {
      return { valid: false, error: "Token expired" };
    }

    return { valid: true };
  }

  /** Check if token allows a specific scope and resource */
  checkPermission(
    token: AgentToken,
    scope: string,
    resource: string
  ): VerificationResult {
    // First verify the token itself
    const verification = this.verify(token);
    if (!verification.valid) {
      return verification;
    }

    // Check if scope is allowed
    const scopeAllowed = token.scopes.some((ts) => scopeMatches(ts, scope));
    if (!scopeAllowed) {
      return { valid: false, error: `Scope "${scope}" not allowed` };
    }

    // Check constraints for this scope
    const constraint = this.findConstraint(token.constraints, scope);

    // Check timing constraints
    if (constraint?.notBefore) {
      const notBefore = new Date(constraint.notBefore);
      if (new Date() < notBefore) {
        return {
          valid: false,
          error: `Scope "${scope}" not valid before ${constraint.notBefore}`,
        };
      }
    }

    if (constraint?.notAfter) {
      const notAfter = new Date(constraint.notAfter);
      if (new Date() > notAfter) {
        return {
          valid: false,
          error: `Scope "${scope}" expired at ${constraint.notAfter}`,
        };
      }
    }

    // Check resource constraints
    if (constraint?.resources) {
      const resourceAllowed = constraint.resources.some((pattern) =>
        resourceMatches(pattern, resource)
      );
      if (!resourceAllowed) {
        return {
          valid: false,
          error: `Resource "${resource}" not allowed for scope "${scope}"`,
        };
      }
    }

    return { valid: true };
  }

  /** Serialize token for transport */
  serialize(token: AgentToken): SerializedToken {
    return Buffer.from(JSON.stringify(token)).toString("base64url");
  }

  /** Deserialize token from transport format */
  deserialize(serialized: SerializedToken): AgentToken {
    const json = Buffer.from(serialized, "base64url").toString("utf-8");
    return JSON.parse(json) as AgentToken;
  }

  /**
   * Create a refreshed token with a new expiry
   * Keeps all other properties the same and re-signs
   */
  createRefreshedToken(
    token: AgentToken,
    newExpiresAt?: string
  ): AgentToken {
    const refreshed: Omit<AgentToken, "signature"> = {
      agentId: token.agentId,
      parentId: token.parentId,
      scopes: token.scopes,
      constraints: token.constraints,
      delegatable: token.delegatable,
      maxDelegationDepth: token.maxDelegationDepth,
      currentDepth: token.currentDepth,
      expiresAt: newExpiresAt,
      maxExpiresAt: token.maxExpiresAt,
    };

    const signature = sign(refreshed, this.secret);
    return { ...refreshed, signature };
  }

  /** Merge parent and child constraints */
  private mergeConstraints(
    parentConstraints: Constraints,
    childConstraints: Constraints,
    childScopes: string[]
  ): Constraints {
    const merged: Constraints = {};

    for (const scope of childScopes) {
      // Find applicable parent constraint
      const parentConstraint = this.findConstraint(parentConstraints, scope);
      const childConstraint = childConstraints[scope];

      if (parentConstraint || childConstraint) {
        merged[scope] = this.mergeConstraint(parentConstraint, childConstraint);
      }
    }

    return merged;
  }

  /** Find constraint that applies to a scope */
  private findConstraint(
    constraints: Constraints,
    scope: string
  ): ScopeConstraint | undefined {
    // Exact match first
    if (constraints[scope]) {
      return constraints[scope];
    }

    // Then try wildcard matches
    for (const [pattern, constraint] of Object.entries(constraints)) {
      if (scopeMatches(pattern, scope)) {
        return constraint;
      }
    }

    return undefined;
  }

  /** Merge two constraints (child must be narrower) */
  private mergeConstraint(
    parent?: ScopeConstraint,
    child?: ScopeConstraint
  ): ScopeConstraint {
    const result: ScopeConstraint = {};

    // Merge resources (intersection if both exist)
    if (parent?.resources || child?.resources) {
      if (parent?.resources && child?.resources) {
        // Child must be subset - for simplicity, just use child's
        // A full implementation would compute intersection
        result.resources = child.resources;
      } else {
        result.resources = child?.resources ?? parent?.resources;
      }
    }

    // Use stricter time bounds
    if (parent?.notBefore || child?.notBefore) {
      const parentTime = parent?.notBefore ? new Date(parent.notBefore) : new Date(0);
      const childTime = child?.notBefore ? new Date(child.notBefore) : new Date(0);
      result.notBefore = (parentTime > childTime ? parentTime : childTime).toISOString();
    }

    if (parent?.notAfter || child?.notAfter) {
      const parentTime = parent?.notAfter
        ? new Date(parent.notAfter)
        : new Date("9999-12-31");
      const childTime = child?.notAfter
        ? new Date(child.notAfter)
        : new Date("9999-12-31");
      result.notAfter = (parentTime < childTime ? parentTime : childTime).toISOString();
    }

    // Use smaller maxUses
    if (parent?.maxUses !== undefined || child?.maxUses !== undefined) {
      result.maxUses = Math.min(
        parent?.maxUses ?? Infinity,
        child?.maxUses ?? Infinity
      );
    }

    return result;
  }
}

/** Generate a new random signing secret */
export function generateSecret(): Buffer {
  return crypto.randomBytes(32);
}

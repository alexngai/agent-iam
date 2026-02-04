# MAP Protocol Integration Design Specification

This document specifies how to integrate agent-iam as an IAM provider for the Multi-Agent Protocol (MAP).

## Overview

agent-iam provides capability-based tokens with optional identity binding, federation metadata, and agent capabilities. MAP consumes these tokens through a custom authenticator that maps agent-iam concepts to MAP's native types.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              MAP System                                  │
│                                                                          │
│  ┌──────────────────┐    ┌─────────────────────┐    ┌────────────────┐  │
│  │  MAP Connection  │───▶│ AgentIAMAuthenticator│───▶│   MAP Router   │  │
│  │  (with token)    │    │                     │    │                │  │
│  └──────────────────┘    │  - Verify token     │    │  - Route msgs  │  │
│                          │  - Extract identity │    │  - Enforce     │  │
│                          │  - Map capabilities │    │    permissions │  │
│                          └─────────────────────┘    └────────────────┘  │
│                                    │                                     │
│                                    ▼                                     │
│                          ┌─────────────────────┐                         │
│                          │     agent-iam       │                         │
│                          │   TokenService      │                         │
│                          └─────────────────────┘                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 1. Authentication Method

### 1.1 Custom Auth Method: `x-agent-iam`

Register a custom authentication method for agent-iam tokens:

```typescript
// map-protocol/ts-sdk/src/server/auth/authenticators/agent-iam.ts

import { TokenService, type AgentToken } from 'agent-iam';
import type { Authenticator, AuthContext, AuthResult } from '../types';

export interface AgentIAMAuthenticatorOptions {
  /** The agent-iam TokenService instance */
  tokenService: TokenService;

  /** System ID for this MAP system (used in identity binding) */
  systemId: string;

  /** Whether to require identity binding */
  requireIdentity?: boolean;

  /** Allowed tenant IDs (undefined = all) */
  allowedTenants?: string[];
}

export class AgentIAMAuthenticator implements Authenticator {
  readonly methods = ['x-agent-iam'] as const;

  private tokenService: TokenService;
  private systemId: string;
  private requireIdentity: boolean;
  private allowedTenants?: string[];

  constructor(options: AgentIAMAuthenticatorOptions) {
    this.tokenService = options.tokenService;
    this.systemId = options.systemId;
    this.requireIdentity = options.requireIdentity ?? false;
    this.allowedTenants = options.allowedTenants;
  }

  async authenticate(
    credentials: AuthCredentials,
    context: AuthContext
  ): Promise<AuthResult> {
    // Extract token from credentials
    const tokenStr = credentials.credentials?.token;
    if (!tokenStr || typeof tokenStr !== 'string') {
      return {
        success: false,
        error: {
          code: 'invalid_credentials',
          message: 'Missing or invalid agent-iam token',
        },
      };
    }

    try {
      // Deserialize and verify token
      const token = this.tokenService.deserialize(tokenStr);
      const verification = this.tokenService.verify(token);

      if (!verification.valid) {
        return {
          success: false,
          error: {
            code: 'invalid_token',
            message: verification.error ?? 'Token verification failed',
          },
        };
      }

      // Check identity requirement
      if (this.requireIdentity && !token.identity) {
        return {
          success: false,
          error: {
            code: 'identity_required',
            message: 'Token must include identity binding',
          },
        };
      }

      // Check tenant restriction
      if (this.allowedTenants && token.identity?.tenantId) {
        if (!this.allowedTenants.includes(token.identity.tenantId)) {
          return {
            success: false,
            error: {
              code: 'tenant_not_allowed',
              message: `Tenant ${token.identity.tenantId} not allowed`,
            },
          };
        }
      }

      // Check federation (if token came from another system)
      if (token.federation && token.identity?.systemId !== this.systemId) {
        if (!token.federation.crossSystemAllowed) {
          return {
            success: false,
            error: {
              code: 'federation_not_allowed',
              message: 'Token does not allow cross-system use',
            },
          };
        }

        if (token.federation.allowedSystems &&
            !token.federation.allowedSystems.includes(this.systemId)) {
          return {
            success: false,
            error: {
              code: 'system_not_allowed',
              message: `Token not allowed for system ${this.systemId}`,
            },
          };
        }
      }

      // Build principal from token
      const principal = this.buildPrincipal(token);

      return {
        success: true,
        principal,
        // Pass the full token for later use
        metadata: { agentIamToken: token },
      };
    } catch (error) {
      return {
        success: false,
        error: {
          code: 'token_parse_error',
          message: error instanceof Error ? error.message : 'Failed to parse token',
        },
      };
    }
  }

  private buildPrincipal(token: AgentToken): AuthPrincipal {
    return {
      id: token.agentId,
      issuer: token.identity?.systemId ?? this.systemId,
      claims: {
        // Core token info
        agentId: token.agentId,
        parentId: token.parentId,
        scopes: token.scopes,
        delegationDepth: token.currentDepth,

        // Identity binding (if present)
        ...(token.identity && {
          principalId: token.identity.principalId,
          principalType: token.identity.principalType,
          tenantId: token.identity.tenantId,
          organizationId: token.identity.organizationId,
        }),

        // Federation info (if present)
        ...(token.federation && {
          federationOrigin: token.federation.originSystem,
          federationHops: token.federation.hopCount,
        }),
      },
      expiresAt: token.expiresAt ? new Date(token.expiresAt).getTime() : undefined,
    };
  }
}
```

### 1.2 Authentication Flow

```
Client                          MAP Server                      agent-iam
   │                                │                               │
   │── map/connect ────────────────▶│                               │
   │   { auth: {                    │                               │
   │       method: "x-agent-iam",   │                               │
   │       credentials: {           │                               │
   │         token: "<serialized>"  │                               │
   │       }                        │                               │
   │   }}                           │                               │
   │                                │                               │
   │                                │── deserialize & verify ──────▶│
   │                                │                               │
   │                                │◀── verification result ───────│
   │                                │                               │
   │                                │── build principal             │
   │                                │── extract capabilities        │
   │                                │                               │
   │◀── connected ──────────────────│                               │
   │    { principal, capabilities } │                               │
```

## 2. Capability Mapping

### 2.1 Scopes to ParticipantCapabilities

Map agent-iam scopes to MAP participant capabilities:

```typescript
// map-protocol/ts-sdk/src/server/auth/agent-iam-mapper.ts

import type { AgentToken, AgentCapabilities } from 'agent-iam';
import type { ParticipantCapabilities, AgentPermissions } from '../../types';

/**
 * Configuration for mapping agent-iam tokens to MAP capabilities
 */
export interface CapabilityMapperConfig {
  /** Map agent-iam scopes to MAP capabilities */
  scopeMappings?: {
    /** Scopes that grant observation capability */
    observation?: string[];
    /** Scopes that grant messaging capability */
    messaging?: string[];
    /** Scopes that grant lifecycle (spawn/register) capability */
    lifecycle?: string[];
    /** Scopes that grant scope management capability */
    scopes?: string[];
    /** Scopes that grant federation capability */
    federation?: string[];
  };

  /** Default capabilities when no mappings match */
  defaults?: Partial<ParticipantCapabilities>;
}

const DEFAULT_SCOPE_MAPPINGS = {
  observation: ['map:observe:*', 'map:*'],
  messaging: ['map:message:*', 'map:*'],
  lifecycle: ['map:lifecycle:*', 'map:agent:*', 'map:*'],
  scopes: ['map:scope:*', 'map:*'],
  federation: ['map:federation:*', 'map:*'],
};

export class AgentIAMCapabilityMapper {
  private scopeMappings: Required<CapabilityMapperConfig['scopeMappings']>;
  private defaults: Partial<ParticipantCapabilities>;

  constructor(config?: CapabilityMapperConfig) {
    this.scopeMappings = {
      ...DEFAULT_SCOPE_MAPPINGS,
      ...config?.scopeMappings,
    };
    this.defaults = config?.defaults ?? {};
  }

  /**
   * Map an agent-iam token to MAP ParticipantCapabilities
   */
  mapToParticipantCapabilities(token: AgentToken): ParticipantCapabilities {
    const caps = token.agentCapabilities;
    const scopes = token.scopes;

    return {
      observation: this.mapObservation(scopes, caps),
      messaging: this.mapMessaging(scopes, caps),
      lifecycle: this.mapLifecycle(scopes, caps),
      scopes: this.mapScopes(scopes, caps),
      federation: this.mapFederation(scopes, caps, token.federation),
      ...this.defaults,
    };
  }

  /**
   * Map an agent-iam token to MAP AgentPermissions
   */
  mapToAgentPermissions(token: AgentToken): AgentPermissions {
    const caps = token.agentCapabilities;

    return {
      canSee: this.mapVisibility(caps),
      canMessage: this.mapMessagePermissions(caps),
      acceptsFrom: this.mapAcceptsFrom(caps),
    };
  }

  private hasScope(scopes: string[], patterns: string[]): boolean {
    return patterns.some(pattern =>
      scopes.some(scope => this.scopeMatches(pattern, scope))
    );
  }

  private scopeMatches(pattern: string, scope: string): boolean {
    if (pattern === scope) return true;
    if (pattern === '*') return true;
    if (pattern.endsWith(':*')) {
      return scope.startsWith(pattern.slice(0, -1));
    }
    return false;
  }

  private mapObservation(
    scopes: string[],
    caps?: AgentCapabilities
  ): ParticipantCapabilities['observation'] {
    const canObserve = caps?.canObserve ??
                       this.hasScope(scopes, this.scopeMappings.observation);
    return {
      canObserve,
      canQuery: canObserve,
    };
  }

  private mapMessaging(
    scopes: string[],
    caps?: AgentCapabilities
  ): ParticipantCapabilities['messaging'] {
    const hasMessagingScope = this.hasScope(scopes, this.scopeMappings.messaging);
    return {
      canSend: caps?.canMessage ?? hasMessagingScope,
      canReceive: caps?.canReceive ?? hasMessagingScope,
      canBroadcast: caps?.canMessage ?? hasMessagingScope,
    };
  }

  private mapLifecycle(
    scopes: string[],
    caps?: AgentCapabilities
  ): ParticipantCapabilities['lifecycle'] {
    const hasLifecycleScope = this.hasScope(scopes, this.scopeMappings.lifecycle);
    return {
      canSpawn: caps?.canSpawn ?? hasLifecycleScope,
      canRegister: hasLifecycleScope,
      canUnregister: hasLifecycleScope,
      canSteer: hasLifecycleScope,
      canStop: hasLifecycleScope,
    };
  }

  private mapScopes(
    scopes: string[],
    caps?: AgentCapabilities
  ): ParticipantCapabilities['scopes'] {
    const hasScopesScope = this.hasScope(scopes, this.scopeMappings.scopes);
    return {
      canCreateScopes: caps?.canCreateScopes ?? hasScopesScope,
      canManageScopes: hasScopesScope,
    };
  }

  private mapFederation(
    scopes: string[],
    caps?: AgentCapabilities,
    federation?: AgentToken['federation']
  ): ParticipantCapabilities['federation'] {
    const hasFederationScope = this.hasScope(scopes, this.scopeMappings.federation);
    const canFederate = (caps?.canFederate ?? hasFederationScope) &&
                        (federation?.crossSystemAllowed ?? true);
    return {
      canFederate,
    };
  }

  private mapVisibility(
    caps?: AgentCapabilities
  ): AgentPermissions['canSee'] {
    // Map agent-iam visibility to MAP canSee
    const visibility = caps?.visibility ?? 'public';

    switch (visibility) {
      case 'public':
        return { agents: 'all', scopes: 'all', structure: 'full' };
      case 'scope':
        return { agents: 'scoped', scopes: 'member', structure: 'local' };
      case 'parent-only':
        return { agents: 'hierarchy', scopes: 'member', structure: 'local' };
      case 'system':
        return { agents: 'direct', scopes: 'member', structure: 'none' };
      default:
        return { agents: 'all', scopes: 'all', structure: 'full' };
    }
  }

  private mapMessagePermissions(
    caps?: AgentCapabilities
  ): AgentPermissions['canMessage'] {
    if (caps?.canMessage === false) {
      return { agents: 'direct', scopes: 'member' };
    }
    return { agents: 'all', scopes: 'all' };
  }

  private mapAcceptsFrom(
    caps?: AgentCapabilities
  ): AgentPermissions['acceptsFrom'] {
    if (caps?.canReceive === false) {
      return { agents: 'hierarchy', clients: 'none', systems: 'none' };
    }
    return { agents: 'all', clients: 'all', systems: 'all' };
  }
}
```

### 2.2 Integration with Connection Handler

```typescript
// map-protocol/ts-sdk/src/server/handlers/connection.ts

import { AgentIAMAuthenticator } from '../auth/authenticators/agent-iam';
import { AgentIAMCapabilityMapper } from '../auth/agent-iam-mapper';
import type { AgentToken } from 'agent-iam';

export function createConnectionHandler(
  options: ConnectionHandlerOptions & {
    agentIamMapper?: AgentIAMCapabilityMapper;
  }
) {
  const mapper = options.agentIamMapper ?? new AgentIAMCapabilityMapper();

  return {
    'map/connect': async (params, context) => {
      // ... authentication happens via AuthManager ...

      // After successful auth, extract agent-iam token from metadata
      const agentIamToken = context.authResult?.metadata?.agentIamToken as AgentToken | undefined;

      if (agentIamToken) {
        // Map to MAP capabilities
        const participantCapabilities = mapper.mapToParticipantCapabilities(agentIamToken);
        const agentPermissions = mapper.mapToAgentPermissions(agentIamToken);

        // Use these capabilities for the connection
        context.capabilities = participantCapabilities;
        context.defaultAgentPermissions = agentPermissions;
      }

      // ... rest of connection handling ...
    },
  };
}
```

## 3. Agent Spawn Integration

### 3.1 Token Delegation on Spawn

When an agent spawns a child, delegate the agent-iam token:

```typescript
// map-protocol/ts-sdk/src/server/handlers/lifecycle.ts

import { TokenService, type DelegationRequest } from 'agent-iam';

export function createLifecycleHandler(
  options: LifecycleHandlerOptions & {
    tokenService?: TokenService;
  }
) {
  return {
    'map/agents/spawn': async (params, context) => {
      const parentToken = context.authResult?.metadata?.agentIamToken;

      if (parentToken && options.tokenService) {
        // Build delegation request from spawn params
        const delegationRequest: DelegationRequest = {
          agentId: params.agentId,
          requestedScopes: params.requestedScopes ?? parentToken.scopes,
          ttlMinutes: params.ttlMinutes,

          // Map spawn params to agent capabilities
          agentCapabilities: params.capabilities ? {
            canSpawn: params.capabilities.canSpawn,
            canMessage: params.capabilities.canSend,
            canReceive: params.capabilities.canReceive,
            visibility: params.visibility,
          } : undefined,

          // Inherit identity by default
          inheritIdentity: params.inheritIdentity ?? true,
        };

        // Delegate token for child
        const childToken = options.tokenService.delegate(parentToken, delegationRequest);

        // Pass to spawned agent
        context.childToken = childToken;
      }

      // ... spawn the agent ...
    },
  };
}
```

### 3.2 Token Passing to Subprocess Agents

```typescript
// map-protocol/ts-sdk/src/server/subprocess-spawner.ts

import { AGENT_TOKEN_ENV } from 'agent-iam';

export class SubprocessSpawner {
  spawn(command: string[], options: SpawnOptions & { childToken?: AgentToken }) {
    const env = {
      ...process.env,
      ...options.env,
    };

    // Pass delegated token via environment
    if (options.childToken) {
      env[AGENT_TOKEN_ENV] = this.tokenService.serialize(options.childToken);
    }

    return spawn(command[0], command.slice(1), { env });
  }
}
```

## 4. Federation Gateway

### 4.1 Cross-System Token Handling

```typescript
// map-protocol/ts-sdk/src/federation/agent-iam-gateway.ts

import { TokenService, type AgentToken } from 'agent-iam';

export interface FederationGatewayConfig {
  /** This system's ID */
  systemId: string;

  /** Token service for this system */
  tokenService: TokenService;

  /** Trusted peer systems and their public keys */
  trustedPeers: {
    [systemId: string]: {
      /** Token service for verifying their tokens */
      tokenService: TokenService;
      /** Scope mapping (their scopes → our scopes) */
      scopeMapping?: Record<string, string | null>;
    };
  };
}

export class AgentIAMFederationGateway {
  constructor(private config: FederationGatewayConfig) {}

  /**
   * Handle incoming federated token from another system
   */
  async handleIncomingToken(
    sourceSystemId: string,
    incomingToken: AgentToken
  ): Promise<{ localToken: AgentToken; allowed: boolean; reason?: string }> {
    const peer = this.config.trustedPeers[sourceSystemId];

    if (!peer) {
      return { localToken: incomingToken, allowed: false, reason: 'Unknown peer system' };
    }

    // Verify with peer's token service
    const verification = peer.tokenService.verify(incomingToken);
    if (!verification.valid) {
      return { localToken: incomingToken, allowed: false, reason: verification.error };
    }

    // Check federation metadata
    if (!incomingToken.federation?.crossSystemAllowed) {
      return { localToken: incomingToken, allowed: false, reason: 'Token does not allow federation' };
    }

    if (incomingToken.federation.allowedSystems &&
        !incomingToken.federation.allowedSystems.includes(this.config.systemId)) {
      return { localToken: incomingToken, allowed: false, reason: 'System not in allowed list' };
    }

    // Check hop count
    const hopCount = (incomingToken.federation.hopCount ?? 0) + 1;
    if (hopCount > (incomingToken.federation.maxHops ?? 3)) {
      return { localToken: incomingToken, allowed: false, reason: 'Max hops exceeded' };
    }

    // Translate scopes if mapping configured
    const translatedScopes = this.translateScopes(
      incomingToken.scopes,
      peer.scopeMapping
    );

    // Create local token with federated identity
    const localToken = this.config.tokenService.createRootToken({
      agentId: `federated:${sourceSystemId}:${incomingToken.agentId}`,
      scopes: translatedScopes,
      constraints: incomingToken.constraints,
      delegatable: incomingToken.delegatable &&
                   (incomingToken.federation.allowFurtherFederation ?? true),
      maxDelegationDepth: Math.min(incomingToken.maxDelegationDepth, 2),
      ttlDays: 1, // Short TTL for federated tokens

      // Preserve identity with federation info
      identity: {
        systemId: this.config.systemId,
        principalId: incomingToken.identity?.principalId
          ? `federated:${sourceSystemId}:${incomingToken.identity.principalId}`
          : undefined,
        principalType: incomingToken.identity?.principalType,
        tenantId: incomingToken.identity?.tenantId,
        federatedFrom: {
          sourceOrganization: sourceSystemId,
          originalPrincipalId: incomingToken.identity?.principalId ?? incomingToken.agentId,
          originalSystemId: incomingToken.federation.originSystem ?? sourceSystemId,
          federatedAt: new Date().toISOString(),
        },
      },

      // Update federation metadata
      federation: {
        crossSystemAllowed: incomingToken.federation.allowFurtherFederation ?? false,
        originSystem: incomingToken.federation.originSystem ?? sourceSystemId,
        hopCount,
        maxHops: incomingToken.federation.maxHops,
        allowFurtherFederation: false, // Don't allow further federation by default
      },

      // Preserve capabilities with attenuation
      agentCapabilities: incomingToken.agentCapabilities ? {
        ...incomingToken.agentCapabilities,
        canFederate: false, // Federated tokens can't federate further
      } : undefined,
    });

    return { localToken, allowed: true };
  }

  /**
   * Prepare a token for sending to another system
   */
  prepareOutgoingToken(
    token: AgentToken,
    targetSystemId: string
  ): { serialized: string; allowed: boolean; reason?: string } {
    if (!token.federation?.crossSystemAllowed) {
      return { serialized: '', allowed: false, reason: 'Token does not allow federation' };
    }

    if (token.federation.allowedSystems &&
        !token.federation.allowedSystems.includes(targetSystemId)) {
      return { serialized: '', allowed: false, reason: 'Target system not allowed' };
    }

    return {
      serialized: this.config.tokenService.serialize(token),
      allowed: true,
    };
  }

  private translateScopes(
    scopes: string[],
    mapping?: Record<string, string | null>
  ): string[] {
    if (!mapping) return scopes;

    return scopes
      .map(scope => {
        const mapped = mapping[scope];
        if (mapped === null) return null; // Blocked scope
        return mapped ?? scope; // Use mapping or original
      })
      .filter((s): s is string => s !== null);
  }
}
```

## 5. Server Setup

### 5.1 Complete Server Configuration

```typescript
// Example: Setting up a MAP server with agent-iam authentication

import { TokenService, generateSecret, Broker } from 'agent-iam';
import { createMAPServer } from 'map-protocol/server';
import { AgentIAMAuthenticator } from 'map-protocol/server/auth/authenticators/agent-iam';
import { AgentIAMCapabilityMapper } from 'map-protocol/server/auth/agent-iam-mapper';

// Initialize agent-iam
const secret = generateSecret(); // Or load from config
const tokenService = new TokenService(secret);
const broker = new Broker();

// Create the authenticator
const agentIamAuth = new AgentIAMAuthenticator({
  tokenService,
  systemId: 'my-map-system',
  requireIdentity: true, // Require identity for audit
  allowedTenants: ['acme-corp', 'partner-inc'], // Multi-tenant
});

// Create the capability mapper
const capabilityMapper = new AgentIAMCapabilityMapper({
  scopeMappings: {
    observation: ['map:observe:*', 'system:*'],
    messaging: ['map:message:*', 'agent:*'],
    lifecycle: ['map:lifecycle:*', 'agent:spawn:*'],
  },
  defaults: {
    streaming: {
      supportsAck: true,
      supportsFlowControl: false,
      supportsPause: false,
    },
  },
});

// Create the server
const server = createMAPServer({
  port: 8080,

  auth: {
    required: true,
    authenticators: [agentIamAuth],
    bypassForTransports: { stdio: true }, // Trust local subprocesses
  },

  agentIamMapper: capabilityMapper,
  tokenService,

  // Federation config
  federation: {
    enabled: true,
    systemId: 'my-map-system',
    trustedPeers: {
      'partner-system': {
        publicKey: '...', // For verifying their tokens
        scopeMapping: {
          'partner:resource:read': 'shared:resource:read',
          'partner:admin:*': null, // Block admin scopes
        },
      },
    },
  },
});

await server.start();
```

### 5.2 Client Connection with agent-iam Token

```typescript
// Example: Connecting to MAP server with agent-iam token

import { Broker } from 'agent-iam';
import { createMAPClient } from 'map-protocol/client';

// Get or create a token
const broker = new Broker();
const token = broker.createRootToken({
  agentId: 'my-agent',
  scopes: ['map:*', 'github:repo:read'],
  identity: {
    systemId: 'my-map-system',
    principalId: 'user@acme-corp.com',
    principalType: 'human',
    tenantId: 'acme-corp',
  },
  federation: {
    crossSystemAllowed: true,
    maxHops: 2,
  },
  agentCapabilities: {
    canSpawn: true,
    canMessage: true,
    canReceive: true,
    visibility: 'public',
  },
  ttlDays: 1,
});

// Connect to MAP server
const client = await createMAPClient({
  url: 'ws://localhost:8080',
  auth: {
    method: 'x-agent-iam',
    credentials: {
      token: broker.serializeToken(token),
    },
  },
});

// Now use the client...
await client.send({
  to: { agent: 'other-agent' },
  payload: { type: 'hello' },
});
```

## 6. Type Mappings Summary

| agent-iam | MAP | Notes |
|-----------|-----|-------|
| `AgentToken.agentId` | `AuthPrincipal.id` | Direct mapping |
| `AgentToken.scopes` | `ParticipantCapabilities.*` | Via mapper config |
| `AgentToken.identity.principalId` | `AuthPrincipal.claims.principalId` | In claims |
| `AgentToken.identity.systemId` | `AuthPrincipal.issuer` | Token issuer |
| `AgentToken.identity.tenantId` | `AuthPrincipal.claims.tenantId` | For multi-tenant |
| `AgentToken.agentCapabilities.canSpawn` | `ParticipantCapabilities.lifecycle.canSpawn` | Direct |
| `AgentToken.agentCapabilities.canMessage` | `ParticipantCapabilities.messaging.canSend` | Direct |
| `AgentToken.agentCapabilities.visibility` | `AgentPermissions.canSee` | Mapped |
| `AgentToken.federation.crossSystemAllowed` | Gateway routing decision | Federation control |
| `AgentToken.expiresAt` | `AuthPrincipal.expiresAt` | Token expiry |

## 7. Security Considerations

### 7.1 Token Validation

- Always verify token signature before trusting any claims
- Check token expiration before each operation
- Validate scopes against requested operations
- Verify federation metadata for cross-system requests

### 7.2 Federation Security

- Maintain separate signing keys per system (never share)
- Use scope mapping to restrict federated tokens
- Limit hop count to prevent routing loops
- Log all federation events for audit

### 7.3 Identity Binding

- Require identity for audit-sensitive operations
- Preserve identity through delegation chain
- Include external auth info when available
- Log principal ID with all security-relevant events

## 8. Implementation Checklist

### MAP Server Side

- [ ] Implement `AgentIAMAuthenticator`
- [ ] Implement `AgentIAMCapabilityMapper`
- [ ] Update connection handler to use mapper
- [ ] Update spawn handler for token delegation
- [ ] Implement federation gateway
- [ ] Add configuration options
- [ ] Write tests

### Integration Tests

- [ ] Token verification flow
- [ ] Capability mapping accuracy
- [ ] Delegation on spawn
- [ ] Federation gateway (same trust domain)
- [ ] Federation gateway (cross-org)
- [ ] Token expiration handling
- [ ] Identity inheritance

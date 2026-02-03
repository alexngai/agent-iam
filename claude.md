# Claude Code Guide for Agent IAM

This document provides context for AI agents working on this codebase.

## Project Overview

Agent IAM is a capability-based credential broker for AI agents. It manages what agents can do through cryptographically signed tokens that support hierarchical delegation with automatic scope attenuation.

**Key distinction**: This is NOT an identity management system. It's a capabilities management system. Tokens represent "what you can do" rather than "who you are."

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Broker                                   │
│  - Token creation, verification, delegation                      │
│  - Credential issuance from providers                           │
│  - Configuration management                                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
   │ GitHub      │ │  AWS STS    │ │ API Key     │
   │ Provider    │ │  Provider   │ │ Provider    │
   └─────────────┘ └─────────────┘ └─────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      AgentRuntime                                │
│  - Token lifecycle management                                   │
│  - Background refresh                                           │
│  - Subprocess environment creation                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Distributed Mode                              │
│  Leader ◄──────sync──────► Follower                             │
│  - Signing keys, Revocation lists, Provider configs             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Capability Tokens

Tokens are JSON objects signed with HMAC-SHA256. Key properties:
- `agentId`: Identifier for the agent holding this token
- `scopes`: Array of allowed operations (e.g., `["github:repo:read"]`)
- `constraints`: Per-scope restrictions (resources, time windows, usage limits)
- `maxDelegationDepth`: How many levels of sub-delegation are allowed
- `expiresAt`: Token expiration timestamp

### Scope Format

Scopes follow `provider:resource:action` pattern:
- `github:repo:read` - Read GitHub repositories
- `aws:s3:write` - Write to S3
- `openai:chat:*` - All chat operations (wildcard)
- `system:token:refresh` - Can refresh own token

### Delegation Rules

1. **Scope Attenuation**: Child tokens can only have equal or fewer scopes than parent
2. **Constraint Narrowing**: Child constraints must be equal or more restrictive
3. **TTL Capping**: Child expiry cannot exceed parent expiry
4. **Depth Limiting**: Each delegation decrements remaining depth

## Directory Structure

```
src/
├── index.ts           # Main exports
├── types.ts           # Core type definitions
├── broker.ts          # Main Broker class
├── token.ts           # Token operations (create, verify, delegate)
├── config.ts          # ConfigService for persistence
├── runtime.ts         # AgentRuntime for subprocess management
├── cli.ts             # Command-line interface
├── providers/
│   ├── index.ts       # Provider exports
│   ├── types.ts       # Provider interfaces
│   ├── github.ts      # GitHub App provider
│   ├── google.ts      # Google OAuth provider
│   ├── aws.ts         # AWS STS provider
│   └── api-key.ts     # Generic API key provider
└── distributed/
    ├── index.ts       # Distributed mode exports
    ├── types.ts       # Distributed types
    ├── signing-keys.ts # Versioned key management
    ├── revocation.ts  # Token revocation list
    ├── leader.ts      # Leader HTTP server
    └── follower.ts    # Follower sync client
```

## Key Files to Understand

1. **`src/types.ts`** - Start here for core interfaces (`AgentToken`, `ScopeConstraint`, `DelegationRequest`)
2. **`src/token.ts`** - Token creation, verification, and delegation logic
3. **`src/broker.ts`** - Main API surface that orchestrates everything
4. **`src/runtime.ts`** - How agents manage their own tokens and create subprocess environments

## Testing

```bash
npm test                    # Run all tests (209 tests)
npm test -- --test-name-pattern "Broker"  # Run specific tests
```

Test files:
- `src/broker.test.ts` - Broker unit tests
- `src/runtime.test.ts` - Runtime and refresh tests
- `src/providers/*.test.ts` - Provider tests
- `src/distributed/distributed.test.ts` - Distributed mode tests
- `src/e2e.test.ts` - End-to-end integration tests

Tests use real file systems and HTTP servers with minimal mocking. Only external API calls (GitHub, AWS, etc.) are mocked.

## Common Tasks

### Adding a New Provider

1. Create `src/providers/newprovider.ts` implementing `CredentialProvider`
2. Add configuration interface in `src/providers/types.ts`
3. Register in `src/broker.ts` `initProvider()` method
4. Add CLI commands in `src/cli.ts`
5. Add tests in `src/providers/newprovider.test.ts`

### Adding a New Constraint Type

1. Extend `ScopeConstraint` interface in `src/types.ts`
2. Add validation logic in `src/token.ts` `checkPermission()` function
3. Add constraint narrowing logic in `src/token.ts` `delegate()` function
4. Update tests

### Modifying Token Structure

1. Update `AgentToken` interface in `src/types.ts`
2. Update token creation in `src/token.ts`
3. Update serialization (base64 JSON encoding)
4. Update verification logic
5. Run all tests to find affected areas

## Security Considerations

1. **Never log tokens** - They contain sensitive credential access rights
2. **Signing keys are in `~/.agent-iam/secret`** - Protect this file
3. **Constraints are enforced at verification time** - Always call `checkPermission()` before using credentials
4. **Delegation cannot widen access** - This is enforced cryptographically

## CLI Usage

```bash
npm run cli -- status                           # Show broker status
npm run cli -- token create-root --agent-id x --scopes "github:repo:read"
npm run cli -- token verify <token>
npm run cli -- token delegate --parent <token> --scopes "github:repo:read"
```

## Debugging Tips

1. **Token verification fails**: Check if signing secret changed, token expired, or constraints violated
2. **Delegation fails**: Parent might not have requested scopes, or depth exceeded
3. **Credential fetch fails**: Provider might not be configured, or scope doesn't map to provider
4. **Distributed sync fails**: Check network, auth token, or leader availability

## Design Document Reference

The original design document is at `docs/design.md`. It covers:
- Phase 1: Core token operations
- Phase 2: Delegation and constraints
- Phase 3: Runtime and refresh
- Phase 4: Provider adapters
- Phase 5: Distributed mode
- Phase 6: Central authority (not implemented)

## Code Style

- TypeScript with strict mode
- Node.js native test runner (`node:test`)
- No external test frameworks
- Minimal dependencies (only `jsonwebtoken` for JWT, `minimist` for CLI)
- Functional approach for token operations, class-based for services

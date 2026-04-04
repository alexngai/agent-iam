# Agent IAM - Development Guide

## Project Overview

Agent IAM is a capability-based credential broker for AI agents with a persistent identity system. It manages what agents can do (capability tokens) and who they are (persistent identity), kept as separate but composable concerns.

## Architecture

The codebase is organized into these layers:

- **Core token system** (`src/token.ts`, `src/types.ts`): HMAC-SHA256 signed capability tokens with scopes, constraints, and hierarchical delegation
- **Broker** (`src/broker.ts`): Orchestrates tokens, credentials, and identity. Main entry point for most operations
- **Identity system** (`src/identity/`): Pluggable persistent identity with two providers:
  - `KeypairIdentityProvider`: Ed25519 keypairs, self-certifying, works without broker for verification
  - `PlatformIdentityProvider`: Broker-assigned UUIDs with HMAC, requires broker for verification
  - `IdentityService`: Dispatches to correct provider based on ID prefix (`key:` vs `platform:`)
  - `standalone-verifier.ts`: Pure crypto verification function - no broker, no disk I/O, no network
- **Runtime** (`src/runtime.ts`): Agent-side token lifecycle management, refresh, subprocess spawning
- **Providers** (`src/providers/`): GitHub, Google, AWS, Slack, API key credential adapters
- **Distributed** (`src/distributed/`): Leader/follower sync, key rotation, revocation lists
- **CLI** (`src/cli.ts`): Command-line interface for all operations

## Key Design Decisions

1. **Identity is separate from capability**: `persistentIdentity` on `AgentToken` is "who you are"; `scopes` are "what you can do". They compose but don't conflate.

2. **Self-certifying tokens**: Tokens carry the agent's public key so remote services can verify identity without broker access. The `verifyIdentityProof()` function needs only the token data.

3. **Proof-of-possession**: `createRootTokenWithIdentity()` calls `prove()` to generate an Ed25519 signature over a challenge, embedded in the token. This prevents claiming an identity without holding the private key.

4. **Authority endorsements**: Trusted parties can sign (persistentId + publicKey + claim) to vouch for an agent. Follows the X.509/VC pattern. Endorsements are optional - TOFU works without them.

5. **Pluggable providers**: The `IdentityProvider` interface supports additional identity types (attested/SPIFFE, decentralized/DID) without changing the token or broker.

6. **Attenuation only**: Delegation can only narrow permissions, never widen. This applies to scopes, constraints, federation, capabilities, and identity inheritance.

## Build & Test

```bash
npm install          # Install dependencies
npm run build        # TypeScript compilation (tsc)
npm test             # Run all tests (318 tests, node:test)
npm run cli -- ...   # Run CLI commands
```

Tests use `node:test` and `node:assert`. Test files are co-located with source (`*.test.ts`). Identity tests are in `src/identity/identity.test.ts`.

## Common Patterns

### Adding a new identity provider

1. Implement the `IdentityProvider` interface from `src/identity/types.ts`
2. Register it in `Broker` constructor (`src/broker.ts`)
3. Add prefix mapping in `IdentityService.inferType()` (`src/identity/identity-service.ts`)
4. Export from `src/identity/index.ts` and `src/index.ts`

### Adding a new credential provider

1. Create provider class in `src/providers/`
2. Add config type to `src/types.ts`
3. Wire into `Broker.issueFromProvider()` switch statement
4. Add CLI init command in `src/cli.ts`

## File Conventions

- Source in `src/`, compiled output in `dist/`
- Config stored in `~/.agent-credentials/` (override with `AGENT_IAM_HOME`)
- Identity keys stored in `~/.agent-credentials/identities/`
- Private keys use mode 0o600, directories use mode 0o700
- Tokens passed between processes via `AGENT_TOKEN` environment variable
